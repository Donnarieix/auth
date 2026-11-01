# Donnarieix Auth — Proxmox LXC, GitHub Actions auto-deploy

This **one CT is the intended long-term hosting target**, initially restricted
to staging/test accounts. The application is not yet approved for real users.
Unlike an ephemeral test VM, no recreation or manual binary transfer is
expected as the project matures.

## Architecture and persistent paths

- CT: unprivileged Debian 13, `192.168.1.142`, runs only Auth and systemd.
- TLS: existing `infra-static` Nginx reverse-proxies to `192.168.1.142:3000`.
- Initial issuer: `https://auth-test.donnarieix.fr`, private/VPN only.
- SQLite: `/var/lib/donnarieix-auth/data/auth.db`.
- RSA key: `/var/lib/donnarieix-auth/keys/oidc.private.pem`.
- Releases: `/opt/donnarieix-auth/releases`; active executable is a **regular file** at `/opt/donnarieix-auth/bin/auth` (atomically replaced, no symlink).
- SQLite/key snapshots: `/var/backups/donnarieix-auth/` (root-only).
- CI: GitHub-hosted runner -> SSH port already used for infra-static ->
  restricted forwarding to the CT -> forced-command release receiver.

No developer passwords, OIDC keys, SQLite DBs or user data are copied to CI.
Only reviewed compiled binaries are delivered. The receiver takes a SQLite
backup **before running any new migration**, atomically replaces the executable without following a symlink, restarts Auth,
checks HTTP health and OIDC discovery, and on failure restores both the
previous executable and pre-upgrade SQLite database. Saved private RSA key
material is kept off the CI runner.

The initial issuer is part of OIDC's security identity. Before registering
real client apps, decide whether the final hostname will instead be
`auth.donnarieix.fr`; changing it later requires reconfiguration of clients.

## One-time setup — deployment SSH key

Use **PowerShell on your own PC** (not inside the CT):

```powershell
ssh-keygen -t ed25519 -f "$env:USERPROFILE\.ssh\donnarieix-auth-ci" -C "auth-github-actions"
Get-Content "$env:USERPROFILE\.ssh\donnarieix-auth-ci.pub"
```

If PowerShell treats `-N '""'` unexpectedly, run `ssh-keygen` without
`-N` and press Enter twice at the passphrase prompts. This is a
deploy-only key. Protect its **private** half; put it only in the GitHub
Actions environment secret, never commit or paste it into chat.

Copy the entire `ssh-ed25519 AAAA... auth-github-actions` **public** line.
Both machines below will receive that same public key with distinct
forced-command/forward-only restrictions.

## One-time setup — Auth CT

You have already run the initial bootstrap. Run it **once again** with the
CI public key so it installs the SSH receiver; this does not regenerate
an existing RSA signing key or overwrite `auth.env`.

Inside Proxmox -> CT `192.168.1.142` -> Console, as root:

```bash
cd /root/auth-staging
git fetch origin main
git checkout -B main FETCH_HEAD
bash deploy/bootstrap-lxc.sh 'ssh-ed25519 AAAA... auth-github-actions'
```

Replace the quoted example with your real **public** line. This provisions:

- `auth-deploy`, an account with no usable password.
- `/usr/local/sbin/auth-receive` as root-owned installer.
- `authorized_keys` forced command, no TTY, no agent or forwarding.
- `sudoers` allowing that account **only the root-owned receiver**.
- systemd unit and persistent data/key directories.
- SSH daemon if missing.

The Auth service is **enabled but not started** until CI delivers its
first binary. The CT requires an incoming SSH connection from
`infra-static` to TCP/22, and TCP/3000 should only be reachable from
`infra-static`. Configure both at the Proxmox/LXC firewall.
Reserve `192.168.1.142` in DHCP.

## One-time setup — SSH jump through infra-static

From `infra-static`, with normal administrator privileges:

```bash
git clone --depth 1 --single-branch --branch main \
  https://github.com/Donnarieix/auth.git /tmp/auth-ci-setup
sudo bash /tmp/auth-ci-setup/deploy/bootstrap-bastion.sh \
  'ssh-ed25519 AAAA... auth-github-actions'
```

This creates a dedicated `auth-tunnel` account. It may **only** forward
connections to `192.168.1.142:22`; it cannot run a remote shell.
Existing SSH deployment accounts for SEPPYL, Nginx, and Drive are unchanged.

GitHub-hosted runners must already be able to reach the same public SSH
address/port used for SEPPYL deployment. This reuses the **network path**,
not SEPPYL's private deployment key or its forced-command SSH account.
If no externally reachable SSH ingress exists, an isolated self-hosted
deploy runner or VPN peer will be required instead.

## One-time setup — pin host keys and GitHub secrets

Read the **server-generated public host keys locally**, not from
`ssh-keyscan` over an untrusted external path. On `infra-static`:

```bash
awk '{print "auth-bastion " $1 " " $2}' /etc/ssh/ssh_host_ed25519_key.pub
```

On the CT:

```bash
awk '{print "auth-ct " $1 " " $2}' /etc/ssh/ssh_host_ed25519_key.pub
```

In GitHub -> `Donnarieix/auth` -> Settings -> Environments, create
`staging`, allow deployments from `main`, and add these **environment
secrets** (do not enable manual approval if the goal is unattended deploy):

| Secret | Value |
| --- | --- |
| `AUTH_DEPLOY_SSH_KEY` | Entire contents of the *private* deploy key, copied directly from your PC |
| `AUTH_DEPLOY_KNOWN_HOSTS` | The two public host-key lines, `auth-bastion ...` and `auth-ct ...` |
| `AUTH_BASTION_HOST` | Public hostname/IP used by the existing SEPPYL GitHub Actions SSH deployment |
| `AUTH_BASTION_PORT` | Existing external SSH port (or `22`) |

Also go to Settings -> Secrets and variables -> Actions -> **Variables**,
and add the repository variable `AUTH_AUTO_DEPLOY=true` **only after**
the hosts and environment secrets above have been configured.

No need for a direct public address for `192.168.1.142`, separate
artifact transfer, or a second application deployment key.

## One-time repair after the first failed rollout

If systemd reported `203/EXEC` and `Too many levels of symbolic links` at
`/opt/donnarieix-auth/current/auth`, this was the legacy symlink-based
launcher. **Do not delete SQLite, RSA signing keys or protected snapshots.**
The new launcher and installer use a regular executable at
`/opt/donnarieix-auth/bin/auth`, independent of the broken `current` link.

On the CT console, as root, once the fix is merged into `main`:

```bash
systemctl stop donnarieix-auth.service
systemctl reset-failed donnarieix-auth.service
cd /root/auth-staging
git fetch origin main
git checkout -B main FETCH_HEAD
bash deploy/bootstrap-lxc.sh
systemctl daemon-reload
systemctl cat donnarieix-auth.service | grep ExecStart
```

No public SSH key is required on this second bootstrap: the restricted
`auth-deploy` SSH setup persists. The expected ExecStart is
`/opt/donnarieix-auth/bin/auth`. Leave the service stopped until CI
delivers a valid artifact; the new unit will no longer spin indefinitely
when a binary is missing. The root-owned receiver is updated during this
one-time command. Once repaired, use GitHub Actions to redeploy; all
further ordinary updates are automatic.

## Automatic releases

1. Merge the reviewed staging-deployment PR into `main`.
2. Each later push to `main` runs `cargo fmt` diagnostic,
   Clippy, tests and locked release compilation with Rust cache.
3. The binary is packaged in the downloadable `auth-linux-amd64` artifact.
4. If quality checks and build pass, and `AUTH_AUTO_DEPLOY=true`,
   Actions uses the pinned SSH gateway to call the CT's forced receiver.
5. The CT receiver validates archive content and SHA-256, stops Auth,
   backs up SQLite and keys, replaces the real executable under `bin/auth`, starts Auth, and tests
   `/health` plus issuer discovery. Failed startup triggers rollback.
6. The workflow fails if deployment fails; previous releases and
   protected snapshots remain available for investigation.

No manual build, SCP, download or systemctl restart for ordinary pushes.
Changes to the **root-owned receiver itself** require a reviewed one-time
re-install via the bootstrap script (intentional privilege boundary).

The deployment deliberately does **not** run on PRs or unreviewed branches.
`workflow_dispatch` on `main` can retry a rollout explicitly. The
service must remain behind trusted HTTPS for browser use.

## HTTPS on infra-static (one-time, automated)

The CT at `192.168.1.142` is already deployed through GitHub Actions.
**Do not install Nginx inside the CT**: it stays on existing `infra-static`.
The issuer remains `https://auth-test.donnarieix.fr` until the team deliberately
chooses a final hostname; changing the issuer later requires client updates.

### DNS

In the DNS zone that actually serves `donnarieix.fr` (o2switch if your
authoritative NS are there), configure `auth-test.donnarieix.fr` to resolve
to **infra-static's HTTPS entry point**, never to the CT private IP.
A CNAME `auth-test` -> `seppyl.donnarieix.fr` is one option if SEPPYL
already resolves to that same Nginx server and no other A/AAAA record
exists for `auth-test`. For an A record, use your existing public reverse
proxy address, not `192.168.1.142`. Local clients may also need split DNS
or NAT loopback to reach that name correctly.

### Automated Nginx setup

The reviewed `deploy/install-nginx-edge.sh` generates a dedicated Nginx
site, preserving SEPPYL and Drive configurations. It first checks the CT's
`/health` and OIDC issuer discovery, then searches for an existing valid
certificate whose SAN covers `auth-test.donnarieix.fr` (including
`*.donnarieix.fr`). It uses such a cert when available. Otherwise,
it can request a new dedicated certificate with Certbot **HTTP-01 webroot**,
which remains automatically renewable.

On `infra-static`, once DNS is ready:

```bash
git clone --depth 1 --branch main \
  https://github.com/Donnarieix/auth.git /tmp/auth-https-setup
cd /tmp/auth-https-setup
sudo bash deploy/install-nginx-edge.sh --email YOUR_WORKING_EMAIL
```

If the checkout already exists, update it with `git pull --ff-only`.
Replace the email with one that you control. This address is passed to
Let's Encrypt for certificate-related notices, not written to GitHub.
The script does not require the email if an existing valid cert is found.

If a new cert is needed, the public DNS hostname must point to
`infra-static` and **TCP/80 must be reachable publicly** for ACME
HTTP-01. The generated HTTP site only serves files under
`/.well-known/acme-challenge/` and returns 404 for every other path.
The application itself remains restricted to LAN/VPN on HTTPS. If public
TCP/80 is unavailable, use a properly automated DNS-01 challenge instead;
manual DNS-01 certificates **do not renew automatically** without hooks.
Never open TCP/3000 publicly.

If your WireGuard clients arrive at Nginx from a separate private subnet,
you can permit that CIDR explicitly:

```bash
sudo bash deploy/install-nginx-edge.sh --mode existing --vpn-cidr YOUR_WG_CIDR
```

Do not use a public CIDR or 0.0.0.0/0. The default HTTPS allowlist is
localhost and `192.168.1.0/24`, with all other sources denied.

The script calls `nginx -t` before reloading, uses a dedicated site name,
checks real HTTPS using `curl --resolve ...:127.0.0.1`, installs a Certbot
post-renewal Nginx reload hook, and does **not** restart the Auth CT or
touch the SQLite DB. A cert reused from earlier manual DNS-01 may still
require manual renewal: verify `certbot renew --dry-run` and migrate it to
an automated authenticator before real production use.

### Validation

On `infra-static`:

```bash
curl -fsS http://192.168.1.142:3000/health
curl -fsS --resolve auth-test.donnarieix.fr:443:127.0.0.1 \
  https://auth-test.donnarieix.fr/health
curl -fsS --resolve auth-test.donnarieix.fr:443:127.0.0.1 \
  https://auth-test.donnarieix.fr/.well-known/openid-configuration
sudo nginx -t
```

From an **allowed LAN/VPN client**, browse
`https://auth-test.donnarieix.fr`. Test that an unauthorized source gets
403 and that Nginx/Proxmox firewall deny direct access to CT TCP/3000.

If `certbot certonly --webroot` cannot validate because port 80 is not
reachable externally, leave the site private and choose automated DNS-01.
Do not expose the login page over HTTP to work around certificate problems.

## Administrator setup and go-live acceptance

The first administrative credential and TOTP **must be bootstrapped
locally** after the initial CI deployment, not printed into CI logs:

```bash
systemctl stop donnarieix-auth
systemd-run --wait --pty --collect \
  --property=User=donnarieix-auth \
  --property=WorkingDirectory=/var/lib/donnarieix-auth \
  --property=EnvironmentFile=/etc/donnarieix-auth/auth.env \
  /opt/donnarieix-auth/bin/auth admin bootstrap operator
```

Keep the credential in a password manager. Run the same
`systemd-run` command with `admin totp enroll operator`, then
`systemctl start donnarieix-auth`.

Before inviting real users: verify browser CSP, HTTPS TLS, SMTP,
account verification/recovery, multiple client OIDC PKCE flows,
negative tests, secure cookies, backup restoration and monitoring.
Not all production security gates are complete; do not merge the
unfinished draft resource permission PR #54 blindly.
