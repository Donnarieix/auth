# Donnarieix Auth

Central identity service for Donnarieix applications.

> **Status: early prototype, NOT production-ready.** This repository starts with a fresh Git history to avoid carrying over a mistakenly committed SQLite database. The previous repository is not a trusted source for secrets or account data.

## Purpose

Provide a common identity to Donnarieix apps through OpenID Connect. Each app keeps its own authorization rules, business data and preferences, and associates records with a stable subject identifier.

## V1 goal

A registered client should authenticate its users via **OpenID Connect Authorization Code + PKCE**, validate signed ID tokens from the issuer's published keys, and never handle the users' central passwords.

The Rust/Axum/SeaORM/SQLite code is a **development-only prototype**. It is not yet an OpenID Connect issuer.

## Security principles

- No databases, credentials, private keys, sessions or application secrets in Git.
- Immutable user UUID; mutable email and username; credentials stored separately from profiles.
- Protected administrator area; no public dynamic client registration in V1.
- Explicitly registered client redirect URIs and scoped identity claims.
- Security-sensitive changes require tests, review and controlled deployments.
- Potentially exposed credentials or sessions from the old repository must be revoked or rotated; migrating Git history does not make them safe again.

## Development only

Install a stable Rust toolchain, then run:

```sh
cp .env.example .env
cargo run
```

The API listens on `127.0.0.1:3000` only. It writes a local SQLite file at `data/auth.db` (excluded from Git). Do not use real accounts or deploy this prototype to a public network.

Check the project before submitting changes:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

**Passing unit tests does not mean authentication flows are production-safe.** Account and browser-session foundations exist, but a deployable OIDC provider, full operational controls and a security review remain outstanding.

## Database schema

The schema is managed by an explicit, transactional SQLite migration tracked in `schema_migrations`. On a new database it creates `users`, `password_credentials`, `sessions`, `clients` and `client_redirect_uris`.

Accounts have immutable UUIDs, unique case-insensitive emails and usernames, optional public display names and avatars, verification state, active state, and creation/update timestamps. Password hashes are stored **only** in `password_credentials`. Changing an email address automatically resets `email_verified`.

**Do not reuse the SQLite file from the old `auth-legacy` repository.** The initial migration refuses unversioned prototype tables; it does not attempt to salvage or convert old data. Use a new empty development database and never commit it.

## Local registration and password login (prototype)

`POST /register` accepts `{ "email": "...", "username": "...", "password": "..." }`. Usernames are limited to 3–32 ASCII letters, digits, hyphens or underscores. Emails are accepted in a deliberately restricted ASCII format (internationalized addresses are not yet supported). Passwords permit Unicode and must be 12–128 characters, up to 512 UTF-8 bytes, without NUL.

For syntactically valid requests, registration responds **202 Accepted**, whether a new account was created or the email/username is already in use. The response **does not confirm that the account exists**. When SMTP is configured, registration schedules an email-verification code; see the verification and recovery section below. Invalid values return 400; excessive requests return 429.

`POST /login` accepts `email` and `password`. Invalid credentials and unknown users have the same 401 response; a dummy Argon2id verification reduces account-existence timing differences. Password hashes have random salts and are computed in bounded blocking tasks.

The server applies conservative in-process 60-second rate limits to registration and login, both globally and for each normalized email. These are intended to defend the **single-process localhost prototype only**: limits reset on restart, are not shared by multiple server processes, and are not a substitute for gateway-level limits, monitoring, IP/device-based controls and security testing.

**This is not production-ready.** Verification/recovery endpoints are present but SMTP still requires configuration. The prototype login currently permits accounts with unverified emails. Production deployment and OIDC remain outstanding.

## Session security (development prototype)

- Login creates a **fresh independent session** for each browser or device. Sessions have **absolute expiration of one hour** (not renewed on access); a successful login never silently revokes another device.
- Logout (`POST /logout`) revokes **only the calling session**. Password recovery and disabling an account revoke **all sessions**; re-enabling an account cannot restore them (SQLite schema migration v3).
- `GET /me` requires an active session that has not expired and belongs to an active user. Expired/revoked cookies are rejected; session tokens are never stored as plaintext in SQLite.
- Cookies are `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain`, `Max-Age=3600`. Lax is selected to preserve future cross-site, top-level OpenID Connect navigations.
- Local HTTP mode (the default, bound **only** to `127.0.0.1:3000`) sets `auth_session` without `Secure`, and is **not a public deployment option**.
- To declare the externally visible **HTTPS** origin behind a future trusted reverse proxy, configure `AUTH_PUBLIC_ORIGIN=https://auth.example.com`. In that mode cookies are `Secure` and named `__Host-auth_session`; insecure origins other than the exact loopback development origin are rejected at startup. Configuring this value **does not enable TLS**, change the listening address, or make the prototype production-ready.
- **CSRF prevention:** all state-changing routes (including login, registration, email recovery and logout) require an exact `Origin` header equal to the configured origin; missing or mismatching origins are rejected with **403**. Requests advertising an incompatible `Sec-Fetch-Site` are also rejected. `SameSite=Lax` adds defense in depth; no CORS permissions are enabled for other origins. This requires same-origin browser calls; CLI tests must explicitly provide the corresponding `Origin` header.

Example loopback request:

```sh
curl -i http://127.0.0.1:3000/health
curl -i -H 'Origin: http://127.0.0.1:3000' -H 'Content-Type: application/json' \
  -d '{"email":"user@example.com","password":"example-password"}' \
  http://127.0.0.1:3000/login
```

This does **not** replace the security review, hardened edge controls, HTTPS termination, account-verification policy, browser frontend and interoperable OIDC that remain before production.

## Email verification and account recovery (prototype)

Email verification and password reset use random 32-byte codes sent to the user's **current email**. SQLite stores only SHA-256 hashes of codes, not their plaintext. Verification codes expire after **24 hours**; recovery codes expire after **30 minutes**. Codes are single use and invalid after a change of email. Recovery changes the password hash and revokes every existing user session within one transaction. Security events are recorded without secrets.

The initial account registration schedules a verification email if SMTP is configured. The following JSON POST endpoints are available:

| Endpoint | JSON fields | Result |
|---|---|---|
| `/email/verification/request` | `email` | 202 (whether account exists or not) |
| `/email/verification/confirm` | `token` | 204 on successful verification |
| `/password/reset/request` | `email` | 202 (whether account exists or not) |
| `/password/reset/confirm` | `token`, `new_password` | 204 on successful recovery |

Invalid/expired/reused codes receive a generic 400. Requests are rate limited within the application process. Codes are included in the **message body of the delivered email only** and must be submitted by POST; no public UI or email links exist yet.

To send real emails, configure the following variables in the **untracked local `.env`**, not in Git:

```text
SMTP_HOST=smtp.example.com
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-app-specific-password
MAIL_FROM=auth@example.com
```

SMTP uses an authenticated **TLS relay on port 465** (SMTPS). If `SMTP_HOST` is absent, delivery is disabled and no codes are exposed in logs, files or API responses. Requests still return their generic 202 response. Incorrect partial SMTP configuration prevents startup.

**Not production-ready:** email delivery is currently best effort; a crash can interrupt pending sends. Configure SPF, DKIM and DMARC for the sender, add a durable delivery queue, production security headers, distributed abuse controls, account notifications and proper frontend flows before exposing the service. Secure cookies/CSRF are tracked by #11, OpenID Connect by #12.

## OIDC client registry (first foundation, not an OIDC issuer yet)

Donnarieix Auth's V1 will implement **Authorization Code + PKCE S256** only. A registered application's redirect URI must exactly match one of the administrator-approved URIs. No OAuth implicit, password, or public client-registration endpoint is provided.

For now, only operators who can access the **local SQLite database** may create or disable OAuth clients using the server binary's **administrative command-line mode**:

```sh
cargo run -- client add web "Example Web App" https://app.example.com/callback
cargo run -- client add desktop "Example Desktop App" http://127.0.0.1:40404/callback
cargo run -- client list
cargo run -- client disable <client-id>
cargo run -- client secret rotate <web-client-id>
```

The `add` command prints a randomly generated public `client_id`. Clients are initially **public clients**, without a client secret, and will be required to use PKCE S256. `web` callbacks must use HTTPS. Native `desktop` callbacks may use HTTPS or an IPv4/IPv6 loopback HTTP URL with a fixed registered port. **Dynamic native loopback ports are not yet implemented.** Wildcards, prefix matching, URL fragments and embedded URL credentials are forbidden.

The internal Authorization Code service now issues random 32-byte codes bound to an active, **email-verified** account and browser session, a registered client, an exact callback and a PKCE S256 challenge. Codes expire after **5 minutes**; only their SHA-256 digest is stored. Redemption is transactional and single-use, requires the original client/callback/verifier, and rejects revoked sessions, disabled clients and unverified accounts. Migration **v5** upgrades existing v4 databases without deleting registered clients.

There is **still no** public `/authorize`, `/token`, `/userinfo`, `/.well-known/openid-configuration` or `/jwks` endpoint yet. The request validator and grant lifecycle are internal only; they never return JWTs. It requires `response_type=code`, `scope=openid`, explicit long `state` and `nonce`, and a canonical S256 PKCE challenge. Client secrets, administrator accounts, the separate developer interface, signed JWTs, key rotation, discovery and integration testing are subsequent work under #12. **Do not integrate an application or expose the service until those are completed.**

## OpenID Connect Authorization Code + PKCE (local prototype)

The server implements the initial Authorization Code + PKCE S256 path for **public desktop/native clients only**, with an authenticated browser consent page, opaque access tokens, scoped UserInfo and RS256 ID tokens. It is not yet certified or externally interoperable. The public `GET /.well-known/jwks.json` route is registered **only if a valid signing key is configured**. The returned JWKS includes RSA public components (`n`, `e`), `kid`, `alg=RS256`, and `use=sig`; private material never appears there.

Configure a real HTTPS issuer separately, then generate a **new key outside Git** on the trusted host:

```sh
umask 077
mkdir -p "$HOME/.local/share/donnarieix-auth/keys"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out "$HOME/.local/share/donnarieix-auth/keys/oidc-2026.private.pem"
chmod 600 "$HOME/.local/share/donnarieix-auth/keys/oidc-2026.private.pem"
```

Set these variables in the **local untracked** `.env`:

```text
AUTH_PUBLIC_ORIGIN=https://auth.example.com
OIDC_SIGNING_KID=oidc-2026
OIDC_SIGNING_KEY_FILE=/absolute/path/to/oidc-2026.private.pem
# OIDC_OLD_PUBLIC_KEYS_DIR=/absolute/path/to/public-keys
```

The signing key must be a valid PKCS#8 RSA private PEM of **at least 2048 bits** with exponent 65537. On Unix the application refuses private keys readable by the group or other users. The environment must declare an HTTPS origin, although **this configuration does not itself enable TLS or public deployment**. Never commit real private keys, test fixtures containing private keys or `.env`.

**Rotation:** create a new private key and unique `OIDC_SIGNING_KID`. Convert the old key to its **public** PEM before retiring it using `openssl pkey -in old.private.pem -pubout -out public-keys/old-kid.pem`. Keep old *public only* keys in `OIDC_OLD_PUBLIC_KEYS_DIR` until every token signed by the old key has expired (plus client cache and clock-skew allowances). Never reuse a `kid` for a different key. Updating files requires a controlled process restart; live rotation is not implemented.

An ID token includes only the user's stable UUID `sub` and mandatory OIDC claims by default. `profile` and `email` claims are conditional on authorized scopes. The authorization-code issuer and redeemer both require explicit, non-revoked per-client user consent. Clients must validate the signature, issuer, audience, expiration, nonce and their original authorization `state`. Auth enforces that the issuing user remains verified/active and that the client/scopes stay authorized.

**OIDC routes (available only with a valid HTTPS issuer and configured signing key):**

| Route | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | Public provider metadata |
| `GET /.well-known/jwks.json` | Public RSA verification keys |
| `GET /authorize` | Browser login and display of requested scopes |
| `POST /authorize/approve` | Explicit consent + short-lived, single-use authorization code |
| `POST /authorize/deny` | Explicit refusal redirected as `access_denied` |
| `POST /token` | Back-channel, form-encoded public-client code exchange with PKCE S256 |
| `GET /userinfo` | Scoped profile claims with hashed, 5-minute Bearer token |

The browser consent flow requires a verified user account and a valid session cookie. The login form communicates with the existing same-origin `POST /login` route. All browser state-changing requests are subject to Origin/CSRF checks; only back-channel `POST /token` is exempt from the Origin requirement because it does not authenticate with cookies.

The token endpoint supports registered public `desktop` clients (no client secret) and confidential `web` clients that authenticate using HTTP Basic (`client_secret_basic`). Both use Authorization Code + PKCE S256 and exact registered redirects. A newly registered web client is unusable until an operator initializes its secret with `cargo run -- client secret rotate <client-id>`. The secret is printed **once** locally; store it securely in the backend's secret store, never in a browser, Git or logs. Rotating the secret immediately invalidates the previous secret for further code redemption. A web client must exchange codes from its backend, not JavaScript shipped to browsers. The service does not issue refresh tokens. Both code issuance and redemption recheck registered clients, exact redirects, PKCE, verified accounts and consent. Access tokens are opaque and stored only as hashes, expire after five minutes, and become unusable after user deactivation, email un-verification, client deactivation, consent revocation or password reset. JSON responses never expose raw credentials, signing keys or session material in logs.

**Not production-ready:** no public HTTPS service has been deployed, SMTP email sending has not been validated with a real relay, and the independent `auth-test-client` has not yet completed a live end-to-end connection. Security hardening and interoperability review are still necessary, particularly for future confidential web clients and any additional OAuth/OIDC features.

## Implementation tracking

See the repository issues for the scope, decisions and planned work. All imported code is subject to review and CI checks before being merged.

## Developer administration identity (prototype)

Developer administrators are **not** normal SSO users. A separate `developer_administrators`
table (schema version 9) holds high-entropy token digests, with an independent
security-event table for future privileged actions.

A trusted server operator may initialize the very first administrator locally:

```sh
cargo run -- admin bootstrap operator
```

This command works only when no developer administrator exists. It generates a
random 32-byte credential, prints it once to the operator's terminal, and
stores only its SHA-256 digest. **Store it in a password manager, never a shell
history, repository, browser local storage or log.** Do not run on an untrusted
terminal. Currently there is no self-service recovery or additional-admin
enrollment; losing this bootstrap token requires a controlled operator
procedure.

A deliberately read-only proof of isolation is exposed as
`GET /developer/clients`, requiring `Authorization: Bearer <token>`.
It lists client names, identifiers, types, active states and a boolean
indicating whether a confidential credential exists; **it never returns client
secrets or end-user data**. An ordinary SSO session cookie cannot access it.

The read-only browser console is at `GET /developer`. Administrators sign in
with the separately bootstrapped username and high-entropy credential; this
creates a **separate**, 30-minute HttpOnly, SameSite=Strict browser session.
Logout revokes only this developer session; operator-side credential rotation
revokes all developer sessions for the account. Ordinary end-user SSO cookies
cannot authenticate to the developer console. To recover or rotate a lost
operator credential on a trusted host, run:

```sh
cargo run -- admin token rotate operator
```

**Important:** The developer console now also permits the current administrator
to register new applications through `/developer/new-client`; registrations
and their audit events are committed atomically. Other privileged lifecycle
operations (editing callback allowlists, deactivation and confidential secret
rotation) still require the trusted local CLI. MFA, multiple-admin onboarding,
independent review and a complete operational security model remain outstanding. Do not publicly deploy
until the missing security and operational features are implemented and
independently reviewed.
