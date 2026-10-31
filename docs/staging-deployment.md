# Donnarieix Auth — private staging deployment

This is for **synthetic test accounts only**; it is not a production authorization.
The staging branch intentionally does not merge draft PR #54 or PR #35.
The service uses SQLite in `/var/lib/donnarieix-auth/data/auth.db`.
It must never share this database with the legacy authentication service.

## Topology and prerequisites

Debian 13 x86_64, Nginx, systemd and OpenSSL. Do not install on the machine
hosting SEPPYL unless you can dedicate port 3000 (loopback) and a separate
hostname. Prefer a separate Proxmox VM. The hostname, HTTPS certificate,
firewall/VPN access and SSH ingress must be configured beforehand.

Staging issuer: `https://auth-test.donnarieix.fr` (example only).
It must resolve to the actual host, and the TLS certificate must explicitly
cover it. A certificate for `donnarieix.fr` alone is insufficient.
No public registration until you have a controlled anti-abuse and SMTP plan.

## One-time preparation on the test VM (root)

```bash
sudo apt-get update
sudo apt-get install -y openssl ca-certificates curl nginx
sudo useradd --system --home-dir /var/lib/donnarieix-auth \
  --shell /usr/sbin/nologin donnarieix-auth || true
sudo install -d -o donnarieix-auth -g donnarieix-auth -m 0700 \
  /var/lib/donnarieix-auth /var/lib/donnarieix-auth/data \
  /var/lib/donnarieix-auth/keys
sudo install -d -o root -g root -m 0700 /etc/donnarieix-auth
sudo install -m 0600 -o root -g root deploy/staging.env.example \
  /etc/donnarieix-auth/auth.env
sudo -u donnarieix-auth openssl genpkey -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out /var/lib/donnarieix-auth/keys/oidc.private.pem
sudo chmod 0600 /var/lib/donnarieix-auth/keys/oidc.private.pem
sudo install -m 0644 deploy/donnarieix-auth.service \
  /etc/systemd/system/donnarieix-auth.service
sudo systemctl daemon-reload
```

Review and customize `/etc/donnarieix-auth/auth.env` and
`deploy/nginx-staging.conf`. **Do not enable Nginx staging virtual host**
until its certificate is valid and VPN/firewall isolation is applied.
Place `auth` (from verified CI artifact) as
`/usr/local/bin/donnarieix-auth` mode 0755, root-owned.
Then run `systemctl enable --now donnarieix-auth`.

The systemd service uses `WorkingDirectory=/var/lib/donnarieix-auth`;
that makes the SQLite path `/var/lib/donnarieix-auth/data/auth.db`.
The OIDC key must exist before startup in HTTPS mode.

## Administrator bootstrap (with service stopped)

```bash
sudo systemctl stop donnarieix-auth
sudo -u donnarieix-auth bash -c 'cd /var/lib/donnarieix-auth && \
  set -a && source /etc/donnarieix-auth/auth.env && set +a && \
  /usr/local/bin/donnarieix-auth admin bootstrap operator'
```

The environment file is root-only. The command above therefore cannot read
it as the service user without a secure privileged wrapper. Instead use:

```bash
sudo systemd-run --wait --pty --collect \
  --property=User=donnarieix-auth \
  --property=WorkingDirectory=/var/lib/donnarieix-auth \
  --property=EnvironmentFile=/etc/donnarieix-auth/auth.env \
  /usr/local/bin/donnarieix-auth admin bootstrap operator
```

Save the one-time credential in a password manager. Enroll TOTP using the
same systemd-run pattern with `admin totp enroll operator`.
Restart the service and test `curl -fsS http://127.0.0.1:3000/health`.
Do not transmit the admin credential, signing key, or SQLite database via chat.

## Release and updates

CI (`.github/workflows/ci.yml`) runs formatting, Clippy, tests, builds a
Debian-compatible Linux artifact and publishes `auth-linux-amd64`.
Use a pinned SHA256 checksum and install the binary with an atomic rename,
then restart the service and check `/health`. Before any update, take an
SQLite-consistent backup (e.g. SQLite `.backup`) together with a protected
backup of key material. A binary rollback may not roll back a schema migration;
always preserve the matching database backup.

CI's optional SSH deployment requires a restricted forced-command receiver
and GitHub Environment `staging`. Until the receiver is provisioned, leave
`AUTH_STAGING_AUTO_DEPLOY` unset and do not run the deploy job.
The receiver must reject unexpected tar entries, verify checksum, snapshot
SQLite, switch the binary atomically, restart and health-check before success.
Never configure unrestricted root SSH deployment.

## Acceptance checks

1. `/health` succeeds locally; port 3000 is not accessible externally.
2. The TLS chain and `AUTH_PUBLIC_ORIGIN` exactly match the hostname.
3. `/.well-known/openid-configuration` issuer and JWKS match.
4. Administrator browser login and TOTP work over HTTPS.
5. A synthetic verified user completes PKCE authorization/consent,
   code exchange, UserInfo, logout, and denied consent with a real test client.
6. Incorrect redirect_uri, reused code, wrong verifier and wrong audience fail.
7. Verify SMTP and email verification separately before real invitations.
8. Test a backup restore on a disposable VM.

Keep this service private until outstanding CSP and security-gate reviews
are complete. Do not silently merge the unfinished permissions PR #54.
