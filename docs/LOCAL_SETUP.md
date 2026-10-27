# Local development runbook (Windows / Linux)

This runbook is for **local synthetic accounts only**, with one Auth checkout when the feature work has been integrated. It is not a production deployment guide.

## Requirements

- Rust stable toolchain and a working SQLite-compatible build environment.
- Keep the repository on a private local filesystem. Do not commit `data/`, `.env`, keys, test outbox messages or database files.
- No DNS, TLS certificate or SMTP provider is necessary for the Auth service's **loopback-only** development mode.

## First startup

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
cargo run
```

On Linux:

```sh
cp .env.example .env
cargo run
```

Leave `AUTH_PUBLIC_ORIGIN` unset. The service binds **127.0.0.1:3000** and automatically creates a local-only RSA signing key in `data/keys` when external signing keys are not configured. It also writes verification / recovery emails as private local files under `data/outbox` by default. These outbox messages contain sensitive one-time codes and must never be committed or shared.

Local browser entry points:

- `http://127.0.0.1:3000/account` — register, verify email, recover passwords
- `http://127.0.0.1:3000/developer` — developer console
- `http://127.0.0.1:3000/account/permissions` — review and revoke OIDC consents
- `http://127.0.0.1:3000/.well-known/openid-configuration` — local issuer metadata
- `http://127.0.0.1:3000/.well-known/jwks.json` — public signing keys

For the developer account, **stop the server first** (both CLI and server access the same SQLite file), then run:

```sh
cargo run -- admin bootstrap operator
```

Store the one-time generated administrator token in your local password manager. Restart the server and use the separate developer console credentials. For credential recovery, the trusted local CLI offers `cargo run -- admin token rotate operator`, which revokes prior developer browser sessions.

Registered desktop client callbacks may use the exact loopback HTTP URI with a fixed port; web client callbacks require HTTPS. Web clients additionally require a secret, which can be created in the developer console with administrator reauthentication or using `cargo run -- client secret rotate <client-id>` with the server stopped. Never put the web client secret in browser JavaScript.

## Automated checks before manual QA

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Passing these checks is **not** an external interoperability validation. In particular, the independent `Donnarieix/auth-test-client` repository currently validates only HTTPS issuer URLs in its configuration; this differs from Auth's exact loopback development issuer. Do not work around this by disabling certificate checks or exposing Auth to the LAN. Resolve this client compatibility restriction before planning a first interactive OIDC smoke test.

## Staging and production still require separate approval

Local development deliberately does not supply TLS termination, real email delivery, independently reviewed MFA, durable outgoing email queue, shared rate limiting, disaster recovery, or an external security audit. Keep real identities and production credentials out of the local prototype until those controls are reviewed.
