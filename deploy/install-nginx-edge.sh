#!/usr/bin/env bash
# One-time HTTPS edge setup for Donnarieix Auth on infra-static.
# Does not replace any existing SEPPYL/Drive vhost. Does not open the Auth CT.
# Supports a valid existing SAN/wildcard cert, or unattended HTTP-01 webroot.
set -Eeuo pipefail
umask 077

domain="auth-test.donnarieix.fr"
issuer="https://$domain"
backend="http://192.168.1.142:3000"
site="/etc/nginx/sites-available/$domain"
enabled="/etc/nginx/sites-enabled/$domain"
webroot="/var/www/auth-acme"
email=""
mode="auto"
vpn_cidr=""

usage() {
  echo "Usage: $0 [--email address] [--mode auto|existing|webroot] [--vpn-cidr CIDR]"
  echo "Auto: reuse a valid certificate, or use Certbot HTTP-01 if --email is set."
}
while (($#)); do
  case "$1" in
    --email) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; email="$2"; shift 2 ;;
    --mode) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; mode="$2"; shift 2 ;;
    --vpn-cidr) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; vpn_cidr="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ "$(id -u)" == 0 ]] || { echo "Run with sudo on infra-static" >&2; exit 1; }
[[ "$mode" == "auto" || "$mode" == "existing" || "$mode" == "webroot" ]] || { usage >&2; exit 2; }
[[ "$email" == "" || "$email" =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || {
  echo "Invalid ACME contact email" >&2; exit 2;
}
# Prevent an accidentally world-accessible test SSO.
if [[ -n "$vpn_cidr" ]]; then
    python3 - "$vpn_cidr" <<'PY'
import ipaddress,sys
network=ipaddress.ip_network(sys.argv[1],strict=False)
if network.prefixlen == 0 or not (network.is_private or network.is_loopback):
    raise SystemExit("VPN allowance must be a private network, not an Internet-wide CIDR")
PY
fi
command -v nginx >/dev/null || { echo "Nginx missing on infra-static" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl missing" >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 missing" >&2; exit 1; }
nginx -t

# Fail early if the SSO isn't reachable privately; no existing vhosts touched.
curl --fail --silent --show-error --max-time 5 "$backend/health" >/dev/null || {
  echo "Auth CT is not responding at $backend/health" >&2
  exit 1
}
curl --fail --silent --show-error --max-time 5 \
  "$backend/.well-known/openid-configuration" |
  python3 -c 'import json,sys; issuer=json.load(sys.stdin)["issuer"]; assert issuer==sys.argv[1], f"Unexpected issuer: {issuer}"' "$issuer"

# Reuse an existing certificate only when it really covers this hostname.
choose_cert() {
  local name="$1"
  [[ -r "$name/fullchain.pem" && -r "$name/privkey.pem" ]] || return 1
  openssl x509 -in "$name/fullchain.pem" -noout -checkhost "$domain" |
    grep -q "does match certificate" || return 1
  openssl x509 -in "$name/fullchain.pem" -noout -checkend 604800 |
    grep -q "Certificate will not expire" || return 1
  return 0
}

certdir=""
shopt -s nullglob
for candidate in "/etc/letsencrypt/live/$domain" /etc/letsencrypt/live/*; do
  if [[ -d "$candidate" ]] && choose_cert "$candidate"; then
    certdir="$candidate"
    break
  fi
done
shopt -u nullglob

if [[ "$mode" == "webroot" ]]; then
  # Force HTTP-01 only if a dedicated certificate isn't already present.
  if [[ "$certdir" != "/etc/letsencrypt/live/$domain" ]]; then
    certdir=""
  fi
fi
if [[ -z "$certdir" && "$mode" == "existing" ]]; then
  echo "No valid certificate covers $domain; stop without modifying Nginx." >&2
  exit 1
fi
if [[ -z "$certdir" && -z "$email" ]]; then
  echo "No existing certificate covers $domain." >&2
  echo "Rerun with --email YOUR_ADDRESS to request an auto-renewable HTTP-01 certificate." >&2
  echo "HTTP-01 requires public DNS to infra-static and public TCP/80 for ACME." >&2
  exit 1
fi
# Never replace a different operator-managed configuration by surprise.
if [[ -e "$enabled" && "$(readlink -f "$enabled")" != "$site" ]]; then
  echo "Refusing to overwrite unrelated enabled Nginx site: $enabled" >&2
  exit 1
fi

install -d -m 0755 "$webroot/.well-known/acme-challenge"
install -d -m 0755 /etc/nginx/sites-available /etc/nginx/sites-enabled
backup_dir="$(mktemp -d /var/tmp/auth-nginx-backup.XXXXXXXX)"
chmod 0700 "$backup_dir"
if [[ -f "$site" ]]; then
    cp -a "$site" "$backup_dir/previous.conf"
fi

write_http_vhost() {
  cat > "$site.tmp" <<EOF
# Managed by Donnarieix Auth; ACME HTTP-01 is the only HTTP endpoint.
server {
    listen 80;
    server_name $domain;
    location ^~ /.well-known/acme-challenge/ {
        root $webroot;
        default_type text/plain;
        try_files \$uri =404;
    }
    location / { return 404; }
}
EOF
  install -m 0644 "$site.tmp" "$site"
  rm -f "$site.tmp"
}

enable_site() {
  if [[ ! -e "$enabled" ]]; then ln -s "$site" "$enabled"; fi
  if ! nginx -t; then
    echo "Nginx config validation failed; restoring previous Auth site." >&2
    if [[ -f "$backup_dir/previous.conf" ]]; then
      cp -a "$backup_dir/previous.conf" "$site"
    else
      rm -f "$enabled" "$site"
    fi
    nginx -t || true
    exit 1
  fi
  systemctl reload nginx
}

# For HTTP-01, first serve a public challenge and no other content.
if [[ -z "$certdir" ]]; then
  command -v certbot >/dev/null || {
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends certbot
  }
  write_http_vhost
  enable_site
  echo "Requesting Let's Encrypt via public TCP/80 only (webroot); no app exposed."
  certbot certonly --webroot --webroot-path "$webroot" \
    --cert-name "$domain" --domain "$domain" \
    --email "$email" --agree-tos --non-interactive --keep-until-expiring
  certdir="/etc/letsencrypt/live/$domain"
  choose_cert "$certdir" || { echo "Certificate issued but does not match $domain" >&2; exit 1; }
fi

extra_allow=""
if [[ -n "$vpn_cidr" ]]; then
  extra_allow="        allow $vpn_cidr;"
fi
cat > "$site.tmp" <<EOF
# Managed by Donnarieix Auth. HTTPS remains local/VPN-only for testing.
server {
    listen 80;
    server_name $domain;
    location ^~ /.well-known/acme-challenge/ {
        root $webroot;
        default_type text/plain;
        try_files \$uri =404;
    }
    location / { return 404; }
}
server {
    listen 443 ssl;
    server_name $domain;
    ssl_certificate $certdir/fullchain.pem;
    ssl_certificate_key $certdir/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 16k;

    location / {
        allow 127.0.0.1;
        allow ::1;
        allow 192.168.1.0/24;
$extra_allow
        deny all;

        proxy_pass $backend;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_connect_timeout 5s;
        proxy_read_timeout 30s;
        proxy_buffering off;
    }
}
EOF
install -m 0644 "$site.tmp" "$site"
rm -f "$site.tmp"
enable_site

# Verify using real TLS certificate and hostname, without public DNS or
# NAT loopback. The private listener is untouched.
curl --fail --silent --show-error --max-time 8 \
  --resolve "$domain:443:127.0.0.1" "https://$domain/health" >/dev/null
curl --fail --silent --show-error --max-time 8 \
  --resolve "$domain:443:127.0.0.1" "https://$domain/.well-known/openid-configuration" |
  python3 -c 'import json,sys; assert json.load(sys.stdin)["issuer"]==sys.argv[1]' "$issuer"

# Reload Nginx when the specific certificate is renewed. The authenticator
# used on an existing certificate may still be manual; do not promise auto
# renewal unless "certbot renew --dry-run" has succeeded.
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/51-auth-nginx-reload <<'HOOK'
#!/bin/sh
set -eu
nginx -t && systemctl reload nginx
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/51-auth-nginx-reload

echo "Auth TLS edge installed: https://$domain -> $backend"
echo "Certificate: $certdir"
echo "Private testing only: LAN (and explicit VPN CIDR, if given) allowed."
echo "Check certificate renewal using: certbot renew --dry-run"
echo "Review DNS, routing and firewall before inviting any testers."
