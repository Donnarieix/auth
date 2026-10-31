#!/usr/bin/env bash
# Root-owned forced-command target for an unprivileged SSH deploy user.
# Provision sudoers for exactly systemctl restart donnarieix-auth.service,
# and allow deploy user to write only /opt/donnarieix-auth/releases and current.
set -Eeuo pipefail
umask 077
base=/opt/donnarieix-auth
incoming="$(mktemp -d)"
release=""
cleanup() { rm -rf "$incoming"; if [ -n "$release" ] && [ -d "$release" ]; then rm -rf "$release"; fi; }
trap cleanup EXIT

# No shell command arguments are accepted from the SSH client.
if [ -n "${SSH_ORIGINAL_COMMAND:-}" ]; then
  echo "Interactive commands prohibited" >&2
  exit 1
fi
cat > "$incoming/release.tar.gz"
# Prevent tar path traversal and reject unexpected entries/links.
python3 - "$incoming/release.tar.gz" "$incoming" <<'PY'
import sys, tarfile, os, hashlib
archive, dest = sys.argv[1:]
with tarfile.open(archive, "r:gz") as tf:
    members = tf.getmembers()
    if sorted(x.name.lstrip("./") for x in members) != ["SHA256SUMS", "auth"]:
        raise SystemExit("Unexpected archive entries")
    if any(not x.isfile() or x.size > 100_000_000 for x in members):
        raise SystemExit("Invalid archive content")
    for member in members:
        name = member.name.lstrip("./")
        with tf.extractfile(member) as source, open(os.path.join(dest, name), "wb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
checksum = open(os.path.join(dest, "SHA256SUMS")).read().strip().split()
if len(checksum) != 2 or checksum[1] != "auth":
    raise SystemExit("Invalid checksum manifest")
with open(os.path.join(dest, "auth"), "rb") as f:
    digest = hashlib.file_digest(f, "sha256").hexdigest()
if digest != checksum[0]:
    raise SystemExit("Binary checksum mismatch")
PY

mkdir -p "$base/releases"
release="$base/releases/$(date -u +%Y%m%dT%H%M%SZ)-$$"
mkdir "$release"
install -m 0755 "$incoming/auth" "$release/auth"
previous="$(readlink -f "$base/current" || true)"
ln -s "$release" "$base/current.next"
mv -Tf "$base/current.next" "$base/current"

if ! sudo -n systemctl restart donnarieix-auth.service; then
    echo "Service restart failed" >&2
else
    for _ in $(seq 1 30); do
        if curl -fsS --max-time 2 http://127.0.0.1:3000/health >/dev/null; then
            echo "Staging deployed: $release"
            release=""
            exit 0
        fi
        sleep 1
    done
fi
echo "Staging health check failed; restoring previous binary" >&2
if [ -n "$previous" ] && [ -x "$previous/auth" ]; then
    ln -s "$previous" "$base/current.next"
    mv -Tf "$base/current.next" "$base/current"
    sudo -n systemctl restart donnarieix-auth.service || true
else
    rm -f "$base/current"
fi
echo "Restore the matching pre-migration SQLite backup if the schema changed" >&2
exit 1
