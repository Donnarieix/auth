#!/usr/bin/env bash
# One-time SMTP setup on the Auth CT; password is not echoed or logged.
set -Eeuo pipefail
umask 077
[[ "$(id -u)" == "0" && -t 0 ]] || { echo "Run interactively as root" >&2; exit 1; }
conf=/etc/donnarieix-auth/auth.env
[[ -f "$conf" && ! -L "$conf" ]] || { echo "Missing config" >&2; exit 1; }
read -rp "SMTP server (TLS hostname): " host
read -rp "SMTP account (full email): " username
read -rp "Sender email [same as account]: " from
from="${from:-$username}"
read -rp "Security implicit/starttls [implicit]: " mode
mode="${mode:-implicit}"
case "$mode" in implicit) port=465 ;; starttls) port=587 ;; *) exit 2 ;; esac
read -rsp "SMTP password: " password
printf '\n'
[[ "$host" =~ ^[A-Za-z0-9][A-Za-z0-9.-]*$ ]] || { echo "Invalid hostname" >&2; exit 2; }
[[ "$username" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || { echo "Invalid account" >&2; exit 2; }
[[ "$from" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || { echo "Invalid sender" >&2; exit 2; }
[[ -n "$password" && "$password" != *$'\r'* ]] || { echo "Invalid password" >&2; exit 2; }
quote_env() {
  local v="$1"
  v="${v//\\/\\\\}"
  v="${v//\"/\\\"}"
  printf '"%s"' "$v"
}
temp="$(mktemp /etc/donnarieix-auth/auth.env.new.XXXXXXXX)"
backup="$(mktemp /etc/donnarieix-auth/auth.env.backup.XXXXXXXX)"
trap 'rm -f -- "$temp"; unset password' EXIT
chmod 0600 "$temp" "$backup"
cp -- "$conf" "$backup"
grep -Ev '^(SMTP_HOST|SMTP_PORT|SMTP_TLS_MODE|SMTP_USERNAME|SMTP_PASSWORD|MAIL_FROM)=' "$conf" > "$temp" || true
{
  printf 'SMTP_HOST=%s\n' "$(quote_env "$host")"
  printf 'SMTP_PORT=%s\n' "$port"
  printf 'SMTP_TLS_MODE=%s\n' "$mode"
  printf 'SMTP_USERNAME=%s\n' "$(quote_env "$username")"
  printf 'SMTP_PASSWORD=%s\n' "$(quote_env "$password")"
  printf 'MAIL_FROM=%s\n' "$(quote_env "$from")"
} >> "$temp"
unset password
chown root:root "$temp"
chmod 0600 "$temp"
mv -f -- "$temp" "$conf"
if ! systemctl restart donnarieix-auth.service || ! systemctl is-active --quiet donnarieix-auth.service; then
  cp -- "$backup" "$conf"
  chmod 0600 "$conf"
  systemctl restart donnarieix-auth.service || true
  echo "Auth restart failed; previous configuration restored" >&2
  exit 1
fi
rm -f -- "$backup"
echo "SMTP configuration saved. Send a real test verification email to validate delivery."
