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

Store the one-time generated administrator token in your local password manager. For local administrator MFA, enroll a separate TOTP secret while the service
is stopped:

```sh
cargo run -- admin totp enroll operator
```

Configure your authenticator with the printed provisioning URI
(SHA256 / six digits / 30-second period). Keep the seed private and do not
commit it. Then restart the server and sign into the separate developer
console with the administrator credential **and**, after enrollment, a
six-digit authenticator code. The same time-step code cannot be reused.
Enrollment is optional for existing development administrators, but should
be completed before testing privileged flows. For credential recovery, the trusted local CLI offers `cargo run -- admin token rotate operator`, which revokes prior developer browser sessions. If the authenticator seed is lost, a trusted operator with **local database access** can run `cargo run -- admin totp reset operator` while the service is stopped; this clears the seed, revokes every developer session, records an audit event and **blocks login until MFA is configured again**. Re-enroll with `admin totp enroll` immediately afterwards. Browser endpoints never offer this recovery mechanism.

Registered desktop client callbacks may use the exact loopback HTTP URI with a fixed port; web client callbacks require HTTPS. Web clients additionally require a secret, which can be created in the developer console with administrator reauthentication or using `cargo run -- client secret rotate <client-id>` with the server stopped. Never put the web client secret in browser JavaScript.

## Automated checks before manual QA

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Passing these checks is **not** an external interoperability validation. The independent `Donnarieix/auth-test-client` now permits the exact `http://127.0.0.1:3000` loopback development issuer (HTTPS remains mandatory elsewhere). Its CI has completed a synthetic end-to-end account registration, email verification, OIDC authorization and signed ID-token validation with this provider. See [independent interoperability evidence](INTEROP_VALIDATION.md). This does not replace a real-browser QA campaign or a production security audit.

## Staging and production still require separate approval

Local development deliberately does not supply TLS termination, real email delivery, independently reviewed MFA, durable outgoing email queue, shared rate limiting, disaster recovery, or an external security audit. Keep real identities and production credentials out of the local prototype until those controls are reviewed.
