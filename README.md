# Donnarieix Auth

Central identity service for Donnarieix applications.

> **Status: early prototype, NOT production-ready.** This repository starts with a fresh Git history to avoid carrying over a mistakenly committed SQLite database. The previous repository is not a trusted source for secrets or account data.

## Purpose

Provide a common identity to Donnarieix apps through OpenID Connect. Each app keeps its own authorization rules, business data and preferences, and associates records with a stable subject identifier.

## V1 goal

A registered client should authenticate its users via **OpenID Connect Authorization Code + PKCE**, validate signed ID tokens from the issuer's published keys, and never handle the users' central passwords.

The existing Rust/Axum/SeaORM/SQLite code will be imported as a **development-only prototype** in a dedicated pull request. It is not yet an OpenID Connect issuer.

## Security principles

- No databases, credentials, private keys, sessions or application secrets in Git.
- Immutable user UUID; mutable email and username; credentials stored separately from profiles.
- Protected administrator area; no public dynamic client registration in V1.
- Explicitly registered client redirect URIs and scoped identity claims.
- Security-sensitive changes require tests, review and controlled deployments.
- Potentially exposed credentials or sessions from the old repository must be revoked or rotated; migrating Git history does not make them safe again.

## Implementation tracking

See the repository issues for the scope, decisions and planned work. All imported code is subject to review and CI checks before being merged.
