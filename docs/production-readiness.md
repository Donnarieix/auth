# Donnarieix Auth — release acceptance gates

**Local-development candidate only. NOT production-ready.** No real user
credentials or personal identity data should be loaded into a public instance.

## Implemented in the repository

- [x] Authorization Code + S256 PKCE for public native clients.
- [x] Confidential web clients with hashed, rotatable secrets and HTTP Basic
  client authentication at the token endpoint.
- [x] Strict registered redirect matching; one-use short-lived codes and
  client/user/session/consent checks before redemption.
- [x] RS256 identity tokens, public JWKS, discovery, UserInfo and JWT tests.
- [x] Separate developer administrator identity, one-time bootstrap, browser
  session and logout, isolated from end-user SSO.
- [x] Developer client creation, listing, deactivation, callback allowlist
  management and one-time secret rotation; audited privileged mutations.
- [x] CSRF origin checks, strict developer cookies, rate-limit hooks,
  explicit browser response security headers and a loopback-only listener.
- [x] Self-service browser UI for registration, email verification and password
  recovery; account tokens are hashed and single-use.
- [x] Explicit localhost development OIDC origin, persistent local signing key
  and local mail outbox for offline trials.
- [x] CI configured to run Rust formatting, strict Clippy, tests and lockfile
  reproducibility checks.

## Unfinished security and production gates

- [ ] Verify a clean local build and complete live browser journey on a real
  installation, including both desktop and confidential web clients.
- [ ] Perform independent client interoperability and adversarial testing,
  beyond in-process integration tests.
- [ ] Replace inline JavaScript with external or nonce-protected scripts and
  deploy a strict CSP before public exposure.
- [ ] Add administrator MFA and multi-admin lifecycle; define administrative
  recovery and security-event monitoring policy.
- [ ] Harden operational throttling for distributed/public deployments,
  incident response, observability, backup/restore and signing-key rollover.
- [ ] Configure a real trusted HTTPS domain, TLS termination, firewall and
  secure browser cookie policy; verify from an external machine.
- [ ] Provision a real mail provider and sender-domain authentication,
  durable email retries and delivery monitoring.
- [ ] Perform security review of secrets, supply chain, authorization,
  session fixation, CSRF, input handling, logging and audit integrity.
- [ ] Publish a signed-off release report before exposing production accounts.

## Status and workflow

Keep the project on loopback for the planned local test phase. The full
development candidate is consolidated in PR #34. Do not close issue #12,
claim OIDC certification, or activate a public endpoint merely because CI is
green. The independent test client belongs to the next stage once the local
provider is validated.
