# Deploying Donnarieix Auth — HTTPS foundation

**Not a production approval.** The server still lacks a hardened browser CSP,
durable SMTP email queue, distributed anti-abuse controls, external security
review, and a real separate-client interoperability run. Only deploy into a
controlled staging environment with synthetic accounts until those gates pass.

## Architecture

- Caddy terminates publicly trusted HTTPS on the intended domain.
- Auth itself listens exclusively on `127.0.0.1:3000` and must **not**
  be published on a public or LAN interface.
- The service uses SQLite and private signing keys under
  `/var/lib/donnarieix-auth`; neither belongs in Git.
- Create the dedicated unprivileged `donnarieix-auth` system account;
  install a reviewed release binary in `/usr/local/bin/donnarieix-auth`.
- Place `deploy/donnarieix-auth.service` in
  `/etc/systemd/system/donnarieix-auth.service`; use
  `systemctl daemon-reload && systemctl enable --now donnarieix-auth`
  only after permission and configuration checks.
- Set `AUTH_DOMAIN` for the Caddy service, then adapt
  `deploy/Caddyfile` to the site's real configuration.

## Trusted operator setup

Create `/etc/donnarieix-auth/auth.env` readable only by the service
manager (e.g. `root:root 0600`) with values such as:

```ini
AUTH_PUBLIC_ORIGIN=https://auth.example.com
OIDC_SIGNING_KID=oidc-staging-2026
OIDC_SIGNING_KEY_FILE=/var/lib/donnarieix-auth/keys/oidc-current.private.pem
SMTP_HOST=mail.example.com
SMTP_USERNAME=replace-me
SMTP_PASSWORD=replace-me
MAIL_FROM=auth@example.com
```

Do not use the placeholder domain or credentials. Generate an RSA private key
**on the target host**, using the README's `openssl genpkey` command.
Store it with `0600` permissions owned by the Auth service account inside a
`0700` private directory. Restrict access to the SQLite directory as well.

## Safety gates before public deployment

1. Verify DNS, TLS certificate validation and canonical HTTPS origin.
2. Ensure `GET /.well-known/openid-configuration` and JWKS expose the exact
   issuer and active public signing key; never a private key.
3. Prove Auth cannot be reached directly over the LAN/Internet on port 3000.
4. Test real email verification and password recovery delivery from configured
   SMTP, including abuse controls and sender authenticity (SPF/DKIM/DMARC).
5. Run public native and confidential web OIDC flows with an independent client;
   reject code replay, wrong audience, nonce and redirect.
6. Verify secure, host-only session cookies and administrator isolation through
   a real browser, including logout and token rotation.
7. Review SSH access, log redaction, encrypted backups and a restoration drill.
8. Commission an independent security review and threat-model the final
   release before sending real identities through it.

Do not place live keys, SMTP secrets, administrator credentials, or production
SQLite files in the repository, CI artifacts or chat messages.
