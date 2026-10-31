#!/usr/bin/env bash
# One-time setup on infra-static: SSH forwarding only to Auth CT SSH port.
# The same CI key has separate, restricted roles on bastion and CT.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" -eq 0 ]] || { echo "Run as root on infra-static" >&2; exit 1; }
[[ "$#" -eq 1 ]] || { echo "Usage: $0 'ssh-ed25519 BASE64'" >&2; exit 1; }
key="$1"
[[ "$key" =~ ^ssh-ed25519[[:space:]][A-Za-z0-9+/=]+([[:space:]][A-Za-z0-9._@+-]+)?$ ]] || {
  echo "Expected an ssh-ed25519 public key" >&2
  exit 1
}
if ! id auth-tunnel &>/dev/null; then
  useradd --system --user-group --create-home \
    --home-dir /var/lib/auth-tunnel --shell /bin/sh auth-tunnel
fi
passwd -l auth-tunnel >/dev/null
install -d -m 0700 -o auth-tunnel -g auth-tunnel /var/lib/auth-tunnel/.ssh
# 'restrict' disables all forwarding; 'port-forwarding' explicitly restores
# it, while permitopen limits destinations to the single private CT address.
# Direct-tcpip (-W / ProxyJump) does not open a shell session. A forced
# nologin command blocks interactive or arbitrary shell commands.
printf 'restrict,port-forwarding,permitopen="192.168.1.142:22",command="/usr/sbin/nologin" %s\n' "$key" \
  > /var/lib/auth-tunnel/.ssh/authorized_keys
chown auth-tunnel:auth-tunnel /var/lib/auth-tunnel/.ssh/authorized_keys
chmod 0600 /var/lib/auth-tunnel/.ssh/authorized_keys
/usr/sbin/sshd -t
echo "SSH bastion access installed. Auth CI can forward only to 192.168.1.142:22."
echo "Existing SEPPYL and Nginx configurations were not modified."
