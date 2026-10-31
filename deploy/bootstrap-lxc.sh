#!/usr/bin/env bash
# One-time, idempotent private Debian 13 LXC preparation.
# Run as root inside the CT, from the cloned repository.
set -Eeuo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "Run this setup as root inside the CT." >&2
  exit 1
fi
if [ "$(dpkg --print-architecture)" != "amd64" ]; then
  echo "The CI release artifact requires Debian amd64." >&2
  exit 1
fi
if ! grep -q '^VERSION_ID="13"' /etc/os-release; then
  echo "Expected Debian 13; review the setup before continuing." >&2
  exit 1
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
apt-get update
apt-get install -y --no-install-recommends ca-certificates openssl curl

if ! getent passwd donnarieix-auth >/dev/null; then
  useradd --system --user-group --home-dir /var/lib/donnarieix-auth \
    --shell /usr/sbin/nologin donnarieix-auth
fi
install -d -m 0700 -o donnarieix-auth -g donnarieix-auth \
  /var/lib/donnarieix-auth /var/lib/donnarieix-auth/data \
  /var/lib/donnarieix-auth/keys
install -d -m 0700 -o root -g root /etc/donnarieix-auth
install -d -m 0755 -o root -g root \
  /opt/donnarieix-auth /opt/donnarieix-auth/releases

if [ ! -e /etc/donnarieix-auth/auth.env ]; then
  install -m 0600 -o root -g root \
    "$script_dir/staging.env.example" /etc/donnarieix-auth/auth.env
fi
if [ ! -e /var/lib/donnarieix-auth/keys/oidc.private.pem ]; then
  runuser -u donnarieix-auth -- openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:3072 \
    -out /var/lib/donnarieix-auth/keys/oidc.private.pem
fi
chmod 0600 /var/lib/donnarieix-auth/keys/oidc.private.pem
chown donnarieix-auth:donnarieix-auth \
  /var/lib/donnarieix-auth/keys/oidc.private.pem
install -m 0644 -o root -g root \
  "$script_dir/donnarieix-auth.service" \
  /etc/systemd/system/donnarieix-auth.service
systemctl daemon-reload

echo "CT prepared; no public port opened and service not started."
echo "Config: /etc/donnarieix-auth/auth.env"
echo "Next: install a verified release artifact in /opt/donnarieix-auth/releases."
