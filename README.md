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

**Passing unit tests does not mean authentication flows are production-safe.** Email-based login, credential separation, database migrations, request validation, rate limiting, secure cookies, CSRF protection and OIDC remain outstanding.

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

## Implementation tracking

See the repository issues for the scope, decisions and planned work. All imported code is subject to review and CI checks before being merged.
