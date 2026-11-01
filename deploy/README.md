# Donnarieix Auth — deployment and HTTPS

**Current target:** Debian 13 unprivileged Proxmox CT at
`192.168.1.142`, served through existing Nginx on `infra-static`.

- Application CI/CD: `.github/workflows/ci.yml` (push to `main` once
  `AUTH_AUTO_DEPLOY=true` and secrets are configured).
- LXC bootstrap: `deploy/bootstrap-lxc.sh`.
- Root-owned restricted SSH installer: `deploy/install-staging.sh`.
- HTTPS edge: `deploy/install-nginx-edge.sh` on **infra-static**, never
  inside the CT. It reuses a suitable existing certificate or obtains an
  automated HTTP-01 certificate when public port 80 is available.
- Exact DNS, Nginx, firewall and administrator instructions:
  [Staging deployment guide](../docs/staging-deployment.md).

The older `deploy/Caddyfile` is a historical example, **not** the active
network architecture. SQLite and OIDC keys must stay on the CT, never in Git
or GitHub Actions artifacts. Keep this test issuer accessible only to the
authorized LAN/VPN clients until security acceptance is complete.
