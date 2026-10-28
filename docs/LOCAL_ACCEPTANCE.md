# Local release acceptance checklist

This is the **one-checkout** manual acceptance plan for the local-only SSO
prototype. Do not test with real personal accounts or live SMTP credentials.
Automated CI is a prerequisite, not a replacement for browser QA.

## Automated prerequisites (already verified)

- [x] Auth Rust format, strict Clippy and unit/integration tests on merged PRs
- [x] Separate `auth-test-client` compiled from its own repository and completed
  a synthetic OIDC Authorization Code + PKCE S256 flow with signature,
  issuer/audience/nonce validation in independent Rust code
- [x] Independent tests reject unregistered callbacks, unsupported response
  type/PKCE method and invalid token exchanges
- [x] Developer session rotation, MFA enrollment and MFA recovery regression
  tests exercise revoked sessions and blocked login during recovery

Cross-repository CI proof: `Donnarieix/auth-test-client` [PR #4](https://github.com/Donnarieix/auth-test-client/pull/4) and [PR #5](https://github.com/Donnarieix/auth-test-client/pull/5).

## Single local setup

1. Clone Auth **once** from `main` and follow [LOCAL_SETUP.md](LOCAL_SETUP.md).
2. Bootstrap a distinct developer administrator with the trusted CLI.
3. Enroll a TOTP authenticator locally; **retain its backup seed privately**.
4. Start Auth on `127.0.0.1:3000` and access its account and developer pages.
5. Use the existing independent client checkout on `127.0.0.1:4000` with an
   explicitly registered public desktop client and exact callback. Do not use
   a confidential web-client secret in a browser.

## Manual browser acceptance scenarios

- [ ] Create a synthetic user; verify email from the local file outbox
- [ ] Sign in and sign out; confirm a logged-out browser cannot access `/me`
- [ ] Request password reset and confirm the old password/session is rejected
- [ ] Try an unverified account and incorrect credentials
- [ ] Sign in to the developer console **using separate admin identity** and
      test an incorrect administrator credential and missing/wrong TOTP
- [ ] Register a desktop and a confidential web client; check redirect URI
      validation, and create/rotate web secrets on a trusted backend only
- [ ] Update client redirects, disable a client and inspect the audit trail
- [ ] Complete OIDC consent on the independent client; verify the displayed
      identity is correct and client logout revokes the client's session
- [ ] Use `/account/permissions` to revoke consent; verify the client can no
      longer use old access tokens
- [ ] Reset TOTP locally; confirm old administrator cookies are rejected and
      login stays blocked until fresh enrollment
- [ ] Verify browser back button, cookies, inaccessible pages, error messages
      and accessibility without relying on the automated HTTP-only tests

## Interface and usability

- [ ] Visit `/account`: the login, registration, verification and recovery
      panels are easy to locate, with clear success/error feedback
- [ ] Sign in with a synthetic account, open `/account/profile`, edit the
      display name and an HTTPS avatar URL, then reload and verify persistence
- [ ] Check the avatar falls back to an initial if the remote image fails
- [ ] Change the header theme between System, Light, Dark and Contrast;
      reload each page and verify it persists locally
- [ ] Navigate `/account/permissions`, `/developer`,
      `/developer/new-client` and `/developer/manage-client`
- [ ] Test narrow desktop/mobile viewport width and 200% zoom, keyboard-only
      controls, visible focus and reduced-motion preference
- [ ] Confirm that administrative secrets are shown only at creation or
      rotation and are never inserted into URLs
- [ ] Inspect the browser developer console for blocked CSS/JS requests and
      any Content-Security-Policy errors

## Not claimed by the local acceptance

Passing this checklist would validate the local development user experience.
It **would not** certify a public SSO: production requires HTTPS/DNS,
secure SMTP delivery, backup restoration, stronger operational controls,
independent vulnerability assessment, key rotation drill and continued
security review. See [production readiness](production-readiness.md).
