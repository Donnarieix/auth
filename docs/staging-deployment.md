# Donnarieix Auth — test CT (Debian 13, Proxmox)

**Staging only, synthetic accounts. Not production approved.**

## Architecture

- App: unprivileged Debian 13 LXC at `192.168.1.142`.
- HTTPS edge: existing Nginx on `infra-static`; do not install Nginx in the CT.
- Proposed test hostname/issuer: `https://auth-test.donnarieix.fr`.
- Nginx reverse-proxies to `http://192.168.1.142:3000`.
- Auth binds explicitly to `AUTH_LISTEN_ADDR=192.168.1.142:3000` and refuses wildcard binds.
- Proxmox firewall MUST restrict TCP 3000 to **infra-static's LAN IP only**.
  The CT's address is not a public listener, but the whole LAN must not
  be assumed trusted. Deny other inbound traffic except administration.
- SQLite: `/var/lib/donnarieix-auth/data/auth.db`.
- OIDC RSA signing key: `/var/lib/donnarieix-auth/keys/oidc.private.pem`.
- Application releases: `/opt/donnarieix-auth/releases/` with a `current` symlink.

The CT should have a DHCP reservation, so `192.168.1.142` stays constant.

## 1. Bootstrap inside the CT

Run these in the CT's Proxmox Console as root:

```bash
apt-get update
apt-get install -y git
git clone --single-branch --branch infra/staging-deployment \
  https://github.com/Donnarieix/auth.git /root/auth-staging
cd /root/auth-staging
bash deploy/bootstrap-lxc.sh
```

This creates a dedicated system user, private SQLite/key directories,
a fresh RSA key and a systemd unit. It does **not** install Nginx or
start Auth, and it never overwrites an existing private key or env file.
Review `/etc/donnarieix-auth/auth.env`, particularly the private IP and
issuer. Keep that file root-owned and mode 0600; never send it to CI or chat.

## 2. Get the verified binary

Once GitHub CI is green, open the latest successful run for PR #55, download
the **auth-linux-amd64** artifact and extract the outer ZIP on your PC.
The result is `auth-linux-amd64.tar.gz`. Transfer this archive to the
CT using SSH/SCP (with a non-root SSH user) or an operator-controlled
Proxmox host `pct push`. Avoid cloning signing keys or databases.

For a **first installation** after transferring the archive to
`/root/auth-linux-amd64.tar.gz`, run inside the CT:

```bash
install -d -m 0755 /opt/donnarieix-auth/releases/initial
tar -tzf /root/auth-linux-amd64.tar.gz
tar -xzf /root/auth-linux-amd64.tar.gz \
  -C /opt/donnarieix-auth/releases/initial
(cd /opt/donnarieix-auth/releases/initial && sha256sum -c SHA256SUMS)
chown -R root:root /opt/donnarieix-auth/releases/initial
chmod 0755 /opt/donnarieix-auth/releases/initial/auth
ln -sfn /opt/donnarieix-auth/releases/initial /opt/donnarieix-auth/current
systemctl enable --now donnarieix-auth.service
curl -fsS http://192.168.1.142:3000/health
```

Only use artifacts created by your own reviewed CI run. The
checksum verifies transfer integrity, not independent publisher
authenticity. Never run an archive with unexpected entries; the full
automated SSH installer performs stricter archive validation.

## 3. Initial administrator

With the service stopped, run the management command under the service
identity with the root-only env loaded by systemd:

```bash
systemctl stop donnarieix-auth
systemd-run --wait --pty --collect \
  --property=User=donnarieix-auth \
  --property=WorkingDirectory=/var/lib/donnarieix-auth \
  --property=EnvironmentFile=/etc/donnarieix-auth/auth.env \
  /opt/donnarieix-auth/current/auth admin bootstrap operator
```

Save the generated one-time admin credential to a password manager, never
Git/chat. Enable administrator TOTP using the same command with
`admin totp enroll operator` instead of `admin bootstrap operator`.
Then restart:

```bash
systemctl start donnarieix-auth
systemctl status donnarieix-auth --no-pager
```

## 4. HTTPS on infra-static

The DNS name `auth-test.donnarieix.fr` must resolve correctly for your
clients. A trusted TLS certificate must explicitly include that hostname
(SAN); an existing certificate for `donnarieix.fr` alone does not cover it.
A DNS-01 certificate can be obtained while keeping the CT private.

Copy `deploy/nginx-staging.conf` to the Nginx host, adjust the certificate
paths and source-IP allowlist for your LAN/WireGuard addresses. This file
targets `192.168.1.142:3000` by default. Do not use the old Caddy template.
On `infra-static`, run `nginx -t` before enabling/reloading the site.
Do not enable a virtual host whose certificate files do not yet exist.

From `infra-static`, first verify the backend with:

```bash
curl -fsS http://192.168.1.142:3000/health
```

Then, from an allowed client, verify HTTPS and discovery:

```bash
curl -fsS https://auth-test.donnarieix.fr/health
curl -fsS https://auth-test.donnarieix.fr/.well-known/openid-configuration
curl -fsS https://auth-test.donnarieix.fr/.well-known/jwks.json
```

Do not test user login over raw HTTP: production-origin cookies are Secure.

## 5. Future CI / SSH deployment

The CI builds a release artifact and contains an **opt-in** staging job.
For automatic delivery, provision a restricted SSH deploy user, a
root-owned receiver `deploy/install-staging.sh` as a forced SSH command,
minimal sudoers access to restart Auth, pinned host keys and GitHub staging
secrets. GitHub-hosted runners must be able to reach the CT; for a private
CT prefer a self-hosted runner or a dedicated private tunnel rather than
opening an unrestricted public SSH port.

Before each update, make and verify a SQLite-consistent backup and protect
OIDC private keys. **Binary rollback does not roll back SQLite schema**.
Do not auto-deploy any branch containing incomplete migrations.

## 6. Acceptance gates

- CI: Rust release builds, tests and Clippy pass (format differences are
  currently reported separately and still need cleanup).
- Port 3000 inaccessible from unauthorized LAN hosts; allowed Nginx path works.
- TLS issuer URL, discovery, JWKS and Secure cookies agree.
- Administrator login and TOTP verified.
- Synthetic verified user completes OIDC PKCE, consent and denial, UserInfo,
  logout and token revocation via independent client.
- Wrong redirect, wrong verifier, replayed code and forbidden audience fail.
- SMTP verified before inviting real accounts.
- Backups and restoration tested.

Draft security PR #35 and multi-resource permission PR #54 remain unmerged.
Keep staging private and synthetic until the outstanding security review.
