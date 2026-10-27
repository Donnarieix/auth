# Donnarieix Auth — production and OIDC acceptance gates

**Current status: NOT production-ready.** No real credentials or personal data should be loaded into a public deployment.

## 1. Confidential web clients (not implemented)

- [ ] Add an independent confidential-client credential model (hashed client secrets, creation/rotation/revocation, never returned except at creation).
- [ ] Require client authentication at `POST /token` for every confidential web client. Never allow `token_endpoint_auth_method=none` for those clients.
- [ ] Keep public native/desktop clients on Authorization Code + PKCE S256.
- [ ] Use exact registered callback comparison and forbid implicit/hybrid grants; test client mixups and replay.
- [ ] Only advertise methods in OIDC Discovery that are genuinely supported.

## 2. Separate developer administration (not implemented)

- [ ] Administrator credentials, roles and sessions must be distinct from end-user identities.
- [ ] Bootstrap first administrator through a local, access-controlled process with no default password.
- [ ] Implement administrator-only client lifecycle: add/list/update/disable, redirect allowlist, secret rotation and audit trail.
- [ ] Require CSRF protection, reauthentication for sensitive changes, rate limits and conservative failure handling.
- [ ] Test that ordinary users cannot reach developer endpoints or obtain administrative sessions.

## 3. Operations and security (not validated)

- [ ] TLS termination/reverse proxy with trusted forwarded-header handling, forced HTTPS and cookie checks in browsers.
- [ ] SMTP sender/domain configuration (SPF, DKIM, DMARC), delivery verification, retry queue, and verified-email onboarding.
- [ ] Production session/token revocation strategy, abuse mitigation shared across instances, monitoring and backups.
- [ ] CSP without inline JavaScript, reviewed logging and secret redaction, key rotation drill, secure key permissions.
- [ ] Software supply-chain review and independent adversarial security review.

## 4. Protocol verification and integration (not validated)

- [ ] Run `cargo fmt --all -- --check`, strict Clippy and all tests on every PR.
- [ ] Run a **separate** OIDC client end to end (prefer the independent auth-test-client repository): browser login, approval, callback and token exchange.
- [ ] Verify JWKS signature, issuer, audience, nonce, expiration, scope, `sub`, and state at the **client**.
- [ ] Assert code replay, wrong client, incorrect redirect, invalid verifier, CSRF and token substitution all fail.
- [ ] Test disabled accounts/clients, password reset, consent revocation, logout and key rollover.
- [ ] Verify both native public and authenticated confidential web clients against issuer metadata.
- [ ] Publish a concrete report with CI run IDs, integration environment and failures before closing #12.

## Current implementation note

The existing native-client flow was merged through PR #25. PR #26 adds initial browser response headers only; it does **not** complete any of the unchecked acceptance gates. No live HTTPS or SMTP validation has been performed.
