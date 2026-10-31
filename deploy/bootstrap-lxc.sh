#!/usr/bin/env bash
# Idempotent Debian 13 LXC setup: service + restricted CI SSH receiver.
# First run may omit the deploy key; rerun with a public key to activate CI.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root in the CT" >&2; exit 1; }
[[ "$(dpkg --print-architecture)" == "amd64" ]] || { echo "Requires amd64" >&2; exit 1; }
. /etc/os-release
[[ "$ID" == "debian" && "$VERSION_ID" == "13" ]] || { echo "Requires Debian 13" >&2; exit 1; }
dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  ca-certificates curl openssl python3 openssh-server sudo util-linux

if ! id donnarieix-auth &>/dev/null; then
  useradd --system --user-group --home-dir /var/lib/donnarieix-auth \
    --shell /usr/sbin/nologin donnarieix-auth
fi
install -d -m 0700 -o donnarieix-auth -g donnarieix-auth \
  /var/lib/donnarieix-auth /var/lib/donnarieix-auth/data \
  /var/lib/donnarieix-auth/keys
install -d -m 0700 -o root -g root /etc/donnarieix-auth /var/backups/donnarieix-auth
install -d -m 0755 -o root -g root \
  /opt/donnarieix-auth /opt/donnarieix-auth/releases
if [[ ! -f /etc/donnarieix-auth/auth.env ]]; then
  install -m 0600 -o root -g root "$dir/staging.env.example" /etc/donnarieix-auth/auth.env
fi
if [[ ! -f /var/lib/donnarieix-auth/keys/oidc.private.pem ]]; then
  runuser -u donnarieix-auth -- openssl genpkey -algorithm RSA \
    -pkeyopt rsa_keygen_bits:3072 -out /var/lib/donnarieix-auth/keys/oidc.private.pem
fi
chown donnarieix-auth:donnarieix-auth /var/lib/donnarieix-auth/keys/oidc.private.pem
chmod 0600 /var/lib/donnarieix-auth/keys/oidc.private.pem
install -m 0644 -o root -g root "$dir/donnarieix-auth.service" \
  /etc/systemd/system/donnarieix-auth.service
install -m 0755 -o root -g root "$dir/install-staging.sh" /usr/local/sbin/auth-receive
systemctl daemon-reload
systemctl enable donnarieix-auth.service

if [[ "$#" -gt 0 ]]; then
  key="$1"
  [[ "$key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]][A-Za-z0-9._@+-]+)?$ ]] || {
    echo "Expected a single ssh-ed25519 public key argument" >&2
    exit 1
  }
  if ! id auth-deploy &>/dev/null; then
    useradd --system --user-group --create-home \
      --home-dir /var/lib/auth-deploy --shell /bin/sh auth-deploy
  fi
  passwd -l auth-deploy >/dev/null
  install -d -m 0700 -o auth-deploy -g auth-deploy /var/lib/auth-deploy/.ssh
  printf 'restrict,command="sudo -n /usr/local/sbin/auth-receive" %s\n' "$key" \
    > /var/lib/auth-deploy/.ssh/authorized_keys
  chown auth-deploy:auth-deploy /var/lib/auth-deploy/.ssh/authorized_keys
  chmod 0600 /var/lib/auth-deploy/.ssh/authorized_keys

  printf 'auth-deploy ALL=(root) NOPASSWD: /usr/local/sbin/auth-receive\n' \
    > /etc/sudoers.d/70-donnarieix-auth-deploy
  chmod 0440 /etc/sudoers.d/70-donnarieix-auth-deploy
  visudo -cf /etc/sudoers.d/70-donnarieix-auth-deploy
  sshd -t
  systemctl enable --now ssh
  echo "Restricted CI SSH receiver enabled on this CT."
else
  echo "Receiver installed but CI SSH access not configured (no public key passed)."
fi
echo "App data and RSA key remain persistent. No application binary deployed yet."
