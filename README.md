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

## Implementation tracking

See the repository issues for the scope, decisions and planned work. All imported code is subject to review and CI checks before being merged.
