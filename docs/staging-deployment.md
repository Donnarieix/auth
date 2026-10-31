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
- Releases: `/opt/donnarieix-auth/releases`; `current` symlink.
- SQLite/key snapshots: `/var/backups/donnarieix-auth/` (root-only).
- CI: GitHub-hosted runner -> SSH port already used for infra-static ->
  restricted forwarding to the CT -> forced-command release receiver.

No developer passwords, OIDC keys, SQLite DBs or user data are copied to CI.
Only reviewed compiled binaries are delivered. The receiver takes a SQLite
backup **before running any new migration**, swaps the binary, restarts Auth,
checks HTTP health and OIDC discovery, and on failure restores both the
previous executable and pre-upgrade SQLite database. Saved private RSA key
material is kept off the CI runner.

The initial issuer is part of OIDC's security identity. Before registering
real client apps, decide whether the final hostname will instead be
`auth.donnarieix.fr`; changing it later requires reconfiguration of clients.

## One-time setup — deployment SSH key

Use **PowerShell on your own PC** (not inside the CT):

```powershell
ssh-keygen -t ed25519 -N '""' -f "$env:USERPROFILE\.ssh\donnarieix-auth-ci" -C "auth-github-actions"
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
git pull --ff-only
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
git clone --depth 1 --single-branch --branch infra/staging-deployment \
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

## Automatic releases

1. Merge the reviewed staging-deployment PR into `main`.
2. Each later push to `main` runs `cargo fmt` diagnostic,
   Clippy, tests and locked release compilation with Rust cache.
3. The binary is packaged in the downloadable `auth-linux-amd64` artifact.
4. If quality checks and build pass, and `AUTH_AUTO_DEPLOY=true`,
   Actions uses the pinned SSH gateway to call the CT's forced receiver.
5. The CT receiver validates archive content and SHA-256, stops Auth,
   backs up SQLite and keys, switches `current`, starts Auth, and tests
   `/health` plus issuer discovery. Failed startup triggers rollback.
6. The workflow fails if deployment fails; previous releases and
   protected snapshots remain available for investigation.

No manual build, SCP, download or systemctl restart for ordinary pushes.
Changes to the **root-owned receiver itself** require a reviewed one-time
re-install via the bootstrap script (intentional privilege boundary).

The deployment deliberately does **not** run on PRs or unreviewed branches.
`workflow_dispatch` on `main` can retry a rollout explicitly. The
service must remain behind trusted HTTPS for browser use.

## HTTPS on infra-static (one-time)

`deploy/nginx-staging.conf` already proxies to
`192.168.1.142:3000`. Configure a DNS record and an HTTPS certificate
whose SAN covers `auth-test.donnarieix.fr`. An apex-only
`donnarieix.fr` certificate does not cover the subdomain.
Copy the reviewed Nginx site **only once**; test with `nginx -t`
before reloading. Continue restricting the hostname to LAN/VPN clients
for testing.

The SSH receiver checks Auth internally even before Nginx is configured;
the Nginx certificate/DNS process is separate from application releases.
Certbot DNS-01 renewal must be automated separately before real use.

## Administrator setup and go-live acceptance

The first administrative credential and TOTP **must be bootstrapped
locally** after the initial CI deployment, not printed into CI logs:

```bash
systemctl stop donnarieix-auth
systemd-run --wait --pty --collect \
  --property=User=donnarieix-auth \
  --property=WorkingDirectory=/var/lib/donnarieix-auth \
  --property=EnvironmentFile=/etc/donnarieix-auth/auth.env \
  /opt/donnarieix-auth/current/auth admin bootstrap operator
```

Keep the credential in a password manager. Run the same
`systemd-run` command with `admin totp enroll operator`, then
`systemctl start donnarieix-auth`.

Before inviting real users: verify browser CSP, HTTPS TLS, SMTP,
account verification/recovery, multiple client OIDC PKCE flows,
negative tests, secure cookies, backup restoration and monitoring.
Not all production security gates are complete; do not merge the
unfinished draft resource permission PR #54 blindly.
