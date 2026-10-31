#!/usr/bin/env bash
# Called ONLY by the forced auth-deploy SSH key through restricted sudo.
# Root-owned script: validates the CI artifact, takes a consistent SQLite
# snapshot, atomically activates a release, checks health, and restores on fail.
set -Eeuo pipefail
umask 077

[[ "$(id -u)" -eq 0 ]] || { echo "Receiver must run as root" >&2; exit 1; }
exec 9>/run/lock/donnarieix-auth-deploy.lock
flock -n 9 || { echo "Another Auth deployment is running" >&2; exit 1; }


base=/opt/donnarieix-auth
state=/var/lib/donnarieix-auth
db="$state/data/auth.db"
live="$base/bin/auth"
tmp="$(mktemp -d /var/tmp/auth-upload.XXXXXXXX)"
backup=""
release=""
switched=0
stopped=0
had_previous=0

restore_db() {
    # Both an existing DB and a previously absent DB can be restored exactly.
    rm -f -- "$db" "$db-wal" "$db-shm"
    if [[ -f "$backup/auth.db" ]]; then
        install -m 0600 -o donnarieix-auth -g donnarieix-auth "$backup/auth.db" "$db"
    fi
}

rollback_on_exit() {
    code=$?
    trap - EXIT
    if (( code != 0 )); then
        echo "Deployment failed; service and recovery details:" >&2
        systemctl show donnarieix-auth.service \
          --property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus \
          --no-pager >&2 || true
        if [[ -n "$backup" && -d "$backup" ]]; then
            # Preserve logs locally, never export the journal to CI.
            journalctl -u donnarieix-auth.service -b -n 100 --no-pager \
              > "$backup/service-failure-journal.log" 2>&1 || true
            chmod 0600 "$backup/service-failure-journal.log" || true
            echo "Detailed journal kept locally: $backup/service-failure-journal.log" >&2
        fi
        if (( switched == 1 )); then
            echo "Rolling back executable and SQLite to pre-deploy snapshot." >&2
            systemctl stop donnarieix-auth.service || true
            if (( had_previous == 1 )); then
                install -m 0755 -o root -g root "$backup/previous-auth" "$base/bin/.auth-rollback"
                mv -Tf "$base/bin/.auth-rollback" "$live"
            else
                rm -f -- "$live" "$base/bin/.auth-rollback"
            fi
            restore_db
            if (( had_previous == 1 )); then
                systemctl start donnarieix-auth.service || true
            fi
        elif (( stopped == 1 )) && (( had_previous == 1 )); then
            systemctl start donnarieix-auth.service || true
        fi
    fi
    if (( code != 0 )) && [[ -n "$release" ]]; then
        rm -rf -- "$release"
    fi
    rm -rf -- "$tmp"
    exit "$code"
}
trap rollback_on_exit EXIT

# Bound the wire input and reject anything other than exactly two regular
# files; never use tar -x against untrusted SSH input.
head -c 157286401 > "$tmp/upload.tar.gz"
[[ "$(stat -c %s "$tmp/upload.tar.gz")" -le 157286400 ]] || { echo "Archive exceeds upload limit" >&2; exit 1; }
python3 - "$tmp" <<'PY'
import hashlib
import os
from pathlib import Path
import re
import sys
import tarfile

dest = Path(sys.argv[1])
archive = dest / "upload.tar.gz"

with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    names = [m.name.removeprefix("./") for m in members]
    if sorted(names) != ["SHA256SUMS", "auth"]:
        raise SystemExit("Archive must contain exactly auth and SHA256SUMS")
    for m, name in zip(members, names):
        if not m.isfile() or m.size > 100_000_000 or name not in {"auth", "SHA256SUMS"}:
            raise SystemExit("Unsafe tar entry")
        source = tf.extractfile(m)
        if source is None:
            raise SystemExit("Unreadable tar entry")
        with source, (dest / name).open("xb") as target:
            remaining = m.size
            while remaining:
                data = source.read(min(remaining, 1024 * 1024))
                if not data:
                    raise SystemExit("Truncated tar entry")
                target.write(data)
                remaining -= len(data)

manifest = (dest / "SHA256SUMS").read_text(encoding="ascii").strip()
match = re.fullmatch(r"([0-9a-f]{64})  auth", manifest)
if not match:
    raise SystemExit("Invalid checksum manifest")
with (dest / "auth").open("rb") as source:
    digest = hashlib.file_digest(source, "sha256").hexdigest()
if digest != match.group(1):
    raise SystemExit("Artifact checksum mismatch")
PY


# Only root-owned directories and regular executable files are used by systemd.
# Legacy /opt/donnarieix-auth/current may contain a circular symlink: ignore it.
mkdir -p "$base/releases" "$base/bin" /var/backups/donnarieix-auth
[[ ! -L "$base/bin" ]] || { echo "Refusing symlinked binary directory" >&2; exit 1; }
[[ ! -L "$live" ]] || { echo "Refusing symlinked active executable" >&2; exit 1; }
release="$(mktemp -d "$base/releases/release-XXXXXXXX")"
install -m 0755 -o root -g root "$tmp/auth" "$release/auth"

# Prefer the new live regular file. If this CT was already deployed with
# the old symlink, salvage a valid prior executable when possible.
previous_binary=""
if [[ -f "$live" && -x "$live" ]]; then
    previous_binary="$live"
elif [[ -f "$base/current/auth" && -x "$base/current/auth" ]]; then
    previous_binary="$base/current/auth"
fi

backup="$(mktemp -d /var/backups/donnarieix-auth/snapshot-XXXXXXXX)"
chmod 0700 "$backup"
if [[ -n "$previous_binary" ]]; then
    install -m 0755 -o root -g root "$previous_binary" "$backup/previous-auth"
    had_previous=1
fi

systemctl stop donnarieix-auth.service || true
stopped=1
if [[ -f "$db" ]]; then
    # Service is stopped; include committed WAL state in SQLite snapshot.
    python3 - "$db" "$backup/auth.db" <<'PY'
import sqlite3, sys
src = sqlite3.connect("file:" + sys.argv[1] + "?mode=ro", uri=True)
dst = sqlite3.connect(sys.argv[2])
try:
    src.backup(dst)
    verdict = dst.execute("PRAGMA quick_check").fetchone()
    if verdict is None or verdict[0] != "ok":
        raise RuntimeError("SQLite backup failed integrity check")
finally:
    dst.close()
    src.close()
PY
    chmod 0600 "$backup/auth.db"
fi
cp -a "$state/keys" "$backup/keys"

# Atomic replacement of a REAL executable. This avoids any symlink traversal
# in systemd ExecStart, including legacy circular current/current.next links.
install -m 0755 -o root -g root "$release/auth" "$base/bin/.auth-next"
mv -Tf "$base/bin/.auth-next" "$live"
switched=1

systemctl reset-failed donnarieix-auth.service || true
systemctl start donnarieix-auth.service
listen="$(sed -n 's/^AUTH_LISTEN_ADDR=//p' /etc/donnarieix-auth/auth.env | tail -n 1)"
issuer="$(sed -n 's/^AUTH_PUBLIC_ORIGIN=//p' /etc/donnarieix-auth/auth.env | tail -n 1)"
[[ -n "$listen" && -n "$issuer" ]] || { echo "Missing Auth listen/issuer settings" >&2; exit 1; }

healthy=0
for attempt in $(seq 1 30); do
    if curl -fsS --max-time 2 "http://$listen/health" >/dev/null 2>&1 && \
       curl -fsS --max-time 2 "http://$listen/.well-known/openid-configuration" 2>/dev/null | \
       python3 -c 'import json,sys; o=json.load(sys.stdin); assert o["issuer"] == sys.argv[1]' "$issuer" 2>/dev/null; then
        healthy=1
        break
    fi
    sleep 1
done

if [[ "$healthy" -ne 1 ]]; then
    health_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "http://$listen/health" 2>/dev/null || true)"
    discovery_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "http://$listen/.well-known/openid-configuration" 2>/dev/null || true)"
    echo "Auth readiness failed: health HTTP ${health_code:-unreachable}; discovery HTTP ${discovery_code:-unreachable}" >&2
    exit 1
fi

switched=0
release=""
echo "Auth deployed successfully; recovery snapshot: $backup"
