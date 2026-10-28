# Independent local OpenID Connect interoperability evidence

## Verified 28 October 2026

The **independent** relying party in the private `Donnarieix/auth-test-client`
repository uses the published Rust `openidconnect` library and communicates
with this provider over HTTP on the exact **loopback-only** development origin.
It does not import or invoke Auth's internal modules.

- Provider: `Donnarieix/auth`, loopback `http://127.0.0.1:3000`.
- Relying party: `Donnarieix/auth-test-client`, loopback `http://127.0.0.1:4000`.
- Integration CI: [run 40654155301](https://github.com/Donnarieix/auth-test-client/actions/runs/40654155301).
- Independent client Rust CI: [run 40654155213](https://github.com/Donnarieix/auth-test-client/actions/runs/40654155213).
- Source: [auth-test-client PR #4](https://github.com/Donnarieix/auth-test-client/pull/4) (merged).

Both workflows completed successfully, including building two separate binaries
from clean checkouts. The black-box job used a newly registered public
desktop client and a synthetic account; it validated:

1. Discovery endpoint metadata, advertised S256 and publicly exposed JWKS
   without RSA private components.
2. Independent relying-party authorization redirect with exact callback,
   `response_type=code`, PKCE S256, randomly generated state and nonce.
3. Registration of the synthetic account, local outbox delivery of its
   verification code and email verification.
4. Browser-like sign-in to Auth, explicit application consent and callback
   receipt of an authorization code.
5. Independent code exchange, RSA ID-token verification with the library,
   validated subject and email claims, and creation of a separate client
   session.
6. Removal of that local client session on logout.

All synthetic credentials and one-time codes stayed in the ephemeral runner;
no production data or public service endpoint was used.

## Scope and remaining work

This verifies **one complete public native/desktop OIDC flow on localhost**,
not every protocol branch and not a deployment security certification.
Provider-side integration/unit tests additionally cover confidential web-client
credential checks, wrong credentials, authorization code replay and consent
revocation. The browser-like CI driver is not a full real-browser or
cross-platform UX test.

Outstanding before **production**: browser UX testing, full negative
interoperability matrix, administrator MFA, production SMTP durability,
distributed abuse controls, public HTTPS/TLS and DNS staging, backup/restore,
key-rotation drill, independent threat review and vulnerability assessment.
These requirements must not be presented as passed because a localhost
interop test succeeded.
