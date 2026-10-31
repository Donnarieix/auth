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
Install verified CI binary in `/opt/donnarieix-auth/releases/initial/auth` and create a `current` symlink pointing to that release. Keep releases separate from SQLite and keys.
Then run `systemctl enable --now donnarieix-auth`.

The systemd service uses `WorkingDirectory=/var/lib/donnarieix-auth`;
that makes the SQLite path `/var/lib/donnarieix-auth/data/auth.db`.
The OIDC key must exist before startup in HTTPS mode.

## Administrator bootstrap (with service stopped)

```bash
sudo systemctl stop donnarieix-auth

Use systemd-run so the root-only environment file is read by systemd:

```bash
sudo systemd-run --wait --pty --collect \
  --property=User=donnarieix-auth \
  --property=WorkingDirectory=/var/lib/donnarieix-auth \
  --property=EnvironmentFile=/etc/donnarieix-auth/auth.env \
  /opt/donnarieix-auth/current/auth admin bootstrap operator
```

Save the one-time credential in a password manager. Enroll TOTP using the
same systemd-run pattern with `admin totp enroll operator`.
Restart the service and test `curl -fsS http://127.0.0.1:3000/health`.
Do not transmit the admin credential, signing key, or SQLite database via chat.

## Restricted automatic delivery

The receiver `deploy/install-staging.sh` should be copied to
`/usr/local/sbin/auth-staging-receive` as root-owned, executable.
Provision a dedicated SSH deployment user with a forced command and
`no-pty,no-agent-forwarding,no-X11-forwarding,no-port-forwarding`.
Give this user write access only to `/opt/donnarieix-auth/releases`
and the `current` symlink, and passwordless sudo permission **only**
for `systemctl restart donnarieix-auth.service`. Do not grant root shell.
The receiving host needs Python 3 and curl.

Configure GitHub Environment `staging` secrets:
`AUTH_STAGING_SSH_KEY`, `AUTH_STAGING_KNOWN_HOSTS`,
`AUTH_STAGING_HOST`, `AUTH_STAGING_PORT` and
`AUTH_STAGING_USER`. Verify the SSH host fingerprint out of band.
GitHub runners need a private network route to the VM; do not expose
SSH to the internet just to make this deployment function.

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
