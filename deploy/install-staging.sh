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
tmp="$(mktemp -d /var/tmp/auth-upload.XXXXXXXX)"
backup=""
release=""
previous=""
switched=0
stopped=0

rollback_on_exit() {
    code=$?
    trap - EXIT
    if (( code != 0 )); then
        echo "Deployment diagnostics (no application secrets exported):" >&2
        systemctl show donnarieix-auth.service \
          --property=LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus \
          --no-pager >&2 || true
        if [[ -n "$backup" && -d "$backup" ]]; then
            # Journals can contain sensitive records. Keep logs only on the CT.
            journalctl -u donnarieix-auth.service -b -n 100 --no-pager \
              > "$backup/service-failure-journal.log" 2>&1 || true
            chmod 0600 "$backup/service-failure-journal.log" || true
            echo "Service journal saved privately at: $backup/service-failure-journal.log" >&2
        else
            echo "Inspect locally: journalctl -u donnarieix-auth.service -b -n 100 --no-pager" >&2
        fi
    fi
    if (( code != 0 && switched == 0 && stopped == 1 )); then
        systemctl start donnarieix-auth.service || true
    fi
    if (( code != 0 && switched == 1 )); then
        echo "Auth deployment failed; restoring previous executable and SQLite." >&2
        systemctl stop donnarieix-auth.service || true
        if [[ -n "$previous" && -x "$previous/auth" ]]; then
            ln -sfn "$previous" "$base/current.next"
            mv -Tf "$base/current.next" "$base/current"
        else
            rm -f "$base/current" "$base/current.next"
        fi
        rm -f "$db" "$db-wal" "$db-shm"
        if [[ -n "$backup" && -f "$backup/auth.db" ]]; then
            install -m 0600 -o donnarieix-auth -g donnarieix-auth "$backup/auth.db" "$db"
        fi
        if [[ -n "$previous" ]]; then
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

mkdir -p "$base/releases" /var/backups/donnarieix-auth
release="$(mktemp -d "$base/releases/release-XXXXXXXX")"
install -m 0755 -o root -g root "$tmp/auth" "$release/auth"

# Do not change the binary or database until all artifact validation passed.
previous="$(readlink -f "$base/current" || true)"
systemctl stop donnarieix-auth.service || true
stopped=1
backup="$(mktemp -d /var/backups/donnarieix-auth/snapshot-XXXXXXXX)"
chmod 0700 "$backup"
if [[ -f "$db" ]]; then
    # SQLite online backup includes committed WAL transactions. Auth is
    # stopped here so the copy is a stable pre-migration recovery point.
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
# Key backup stays root-only; never publish key files to Actions/artifacts.
cp -a "$state/keys" "$backup/keys"

ln -sfn "$release" "$base/current.next"
mv -Tf "$base/current.next" "$base/current"
switched=1

systemctl start donnarieix-auth.service
listen="$(sed -n 's/^AUTH_LISTEN_ADDR=//p' /etc/donnarieix-auth/auth.env | tail -n 1)"
issuer="$(sed -n 's/^AUTH_PUBLIC_ORIGIN=//p' /etc/donnarieix-auth/auth.env | tail -n 1)"
[[ -n "$listen" && -n "$issuer" ]] || { echo "Missing Auth listen/issuer settings" >&2; exit 1; }

healthy=0
for attempt in $(seq 1 40); do
    if curl -fsS --max-time 2 "http://$listen/health" >/dev/null 2>&1 && \
       curl -fsS --max-time 2 "http://$listen/.well-known/openid-configuration" | \
       python3 -c 'import json,sys; o=json.load(sys.stdin); assert o["issuer"] == sys.argv[1]' "$issuer" 2>/dev/null; then
        healthy=1
        break
    fi
    sleep 1
done
if [[ "$healthy" -ne 1 ]]; then
    health_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "http://$listen/health" 2>/dev/null || true)"
    discovery_code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 "http://$listen/.well-known/openid-configuration" 2>/dev/null || true)"
    echo "Auth readiness check failed: health HTTP ${health_code:-unreachable}, discovery HTTP ${discovery_code:-unreachable}" >&2
    exit 1
fi

switched=0
release=""
echo "Donnarieix Auth deployed successfully; previous SQLite snapshot: $backup"
