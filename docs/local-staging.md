# Local SSO development (staging only)

This setup is for a single developer workstation, not a public identity service.

## Start

1. Install a current stable Rust toolchain.
2. Make sure port 3000 is not exposed beyond the loopback interface.
3. Leave `AUTH_PUBLIC_ORIGIN` unset, or explicitly set it to `http://127.0.0.1:3000`.
4. Run `cargo run` from the repository root.
5. Open `http://127.0.0.1:3000/developer` in a local browser.

The server creates `data/auth.db`. On the first local startup it generates
a persistent RSA signing key under `data/keys/`; both are ignored by Git.
Never commit, share, or reuse either for production. On Unix, local signing
keys must be readable only by their owner.

On loopback, outbound account email is captured into `data/outbox/*.txt` by
default if SMTP is not set. Verification and recovery codes appear in those
local files; do not share them. Clear the outbox after testing, and use separate
synthetic accounts rather than real personal data.

Run the local administrator bootstrap **once** (with the server stopped):

```sh
cargo run -- admin bootstrap operator
```

Store the one-time printed administrator credential in a local password manager.
If it is lost, run `cargo run -- admin token rotate operator` on the same host.

## Local navigation

- Developer dashboard: `http://127.0.0.1:3000/developer`
- Register an application: `http://127.0.0.1:3000/developer/new-client`
- OIDC metadata: `http://127.0.0.1:3000/.well-known/openid-configuration`
- Public signing keys: `http://127.0.0.1:3000/.well-known/jwks.json`

Desktop clients use Authorization Code + S256 PKCE with exact loopback
redirect URIs. Confidential web clients require a secret generated on the
trusted operator host via `cargo run -- client secret rotate <client-id>`.

## Limitations

This mode is deliberately bound to the exact loopback origin. HTTP use is
for local testing only; it is not a supported production configuration.
Production requires trusted HTTPS, SMTP, firewall configuration, key
management, penetration review, and monitoring.

Do not test with production credentials or connect an unreviewed external
application until the security acceptance gates are complete.
