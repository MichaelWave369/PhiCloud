# PhiCloud R3: local OAuth resource-server authorization gate

**A real development-only authorization boundary, not hosted PhiCloud, real user storage, production identity, or a mailbox integration.**

R0 remains a public, read-only, declarative registry. R3 introduces one **separate protected route** on the same loopback HTTP process:

`GET http://127.0.0.1:8769/v1/private/profile`

Without a verified token intended **specifically for PhiCloud**, this endpoint does not return a profile. Even on success, it returns **only a deliberately minimal synthetic self-profile descriptor** for the authenticated test subject. No files, accounts, Gmail messages, wallet funds, encryption keys, devices or operating-system capabilities can be accessed here.

## Why introspection rather than custom JWT code?

Keycloak 26.8's standard OAuth 2.0 token introspection endpoint can answer whether an access token remains active. It requires an authenticated **confidential client**, and Keycloak enforces token audience checks for client introspection. PhiCloud uses the verified response and independently checks **all** of:

- `active` must be the exact JSON boolean `true`.
- `iss` must be `http://127.0.0.1:8080/realms/phiid-dev`, never an arbitrary browser-provided URL.
- `aud` must include the explicit resource server client `phicloud-resource-dev`.
- `scope` must contain the exact whitespace-delimited `phicloud.profile.read`, not a prefix or wildcard.
- `token_type` must be `Bearer`; ID tokens or refresh tokens are not accepted as access tokens.
- `sub` is mandatory, nonempty and bounded; `exp` must be a future numeric integer; `nbf` cannot be in the future.
- Each protected request triggers **fresh** Keycloak introspection. No positive authorization cache is retained, so upstream session invalidation is observed at the next request.

The protected API never decodes or trusts a bearer token's JWT claims itself. It does not create JWT signatures, authenticate user passwords or issue access tokens. Keycloak remains the source of token validity. This is *provider-backed validation of a dev access token*, **not** a replacement for real file ownership or tenant isolation.

Official technical sources: [Keycloak token introspection endpoint](https://www.keycloak.org/securing-apps/oidc-layers) and [Keycloak 26.8 administration audience guidance](https://www.keycloak.org/docs/26.8.1/server_admin/).

## Default-off development start

Python 3.11+ with **no third-party dependencies** is sufficient for PhiCloud's local service. Without opt-in, `/v1/private/profile` returns 404; `/v1/services` stays public and declarative.

The caller must separately supply a real access token with the explicit audience and optional scope from **its own** PKCE OIDC flow, not from a PhiID preview JSON export or consent receipt.

To enable the local gate, register a **confidential** Keycloak development client named `phicloud-resource-dev`. Its secret is private to the resource server. Its Keycloak client roles and audience mapper must be configured as described in the CI test below. No client secret is committed or returned to the browser.

For POSIX shells, set process-only variables (illustrative, no actual credentials shown):

```sh
export PHICLOUD_ENABLE_OAUTH_DEV=1
export PHICLOUD_OAUTH_CLIENT_SECRET='<private-secret-from-local-Keycloak>'
python -m phicloud.server --port 8769
```

The client-secret variable is intentionally mandatory whenever R3 is enabled; do not paste the secret into chat, screenshots or files under source control. Never expose port 8769 to LAN/WAN, a reverse proxy, public DNS, browser extension, or shared machine. Keycloak is pinned to HTTP **IPv4 loopback** for this development fixture only.

In the **actual test workflow**, the confidential client and optional scope are registered **only in the disposable CI Keycloak instance**. The secret is retrieved from Keycloak's authenticated Admin API in CI memory and passed only to the Python test server's process environment. There is no checked-in secret or permanent grant.

## Protected resource

The successful response is schema `phicloud.private-profile.v0.1` and includes only a SHA-256-derived pseudonymous test-subject fingerprint, fixed resource/scope/audience labels, and explicit false flags for `cloud_storage_access`, `mailbox_access` and `phios_effect_authority`.

**The fingerprint is not a password, capability or hidden proof of permission.** It must not be used by PhiCloud or PhiOS as a credential. The actual issuer+subject pair is used only internally for the one profile calculation; it is not directly returned.

This demo has **no per-user stored resources**. The real next phase must enforce owner, tenant, resource-specific permissions, data encryption, audit and user deletion independently. A matching user subject alone cannot determine ownership of Gmail mailboxes, files or PhiOS device effects.

## Negative tests and CI evidence

`python -m unittest discover -s tests -v` covers fail-closed behavior for missing/malformed/duplicated bearer headers, wrong issuer, scope, audience, token type, expiry and claims, provider outage, and the absence of positive-decision caching.

`.github/workflows/keycloak-authz.yml` additionally boots **Keycloak 26.8.2**, pinned via an exact PhiID commit, registers a temporary `phicloud-resource-dev` confidential introspection client and optional resource scope/audience mapper, creates a disposable test user, and completes **real authorization-code + PKCE** browser sign-ins. It verifies:

1. No credentials means HTTP 401.
2. A real active token with the exact audience and `phicloud.profile.read` is accepted by the Python protected route.
3. A token without that scope/audience is denied.
4. A valid **PhiMail** access token with another audience is denied.
5. After Keycloak revokes the disposable user's sessions, the previously accepted token is denied by a fresh introspection call.
6. The test user and Keycloak container are removed even when testing fails.

No Gmail OAuth, PhiCloud object storage, remote user database, hosted identity service or public authorization system is deployed or tested. The existing registry endpoint stays unauthenticated because it contains **only public planning declarations**.

## Real security boundaries before future deployments

- Strong HTTPS from resource server to a reviewed identity provider, plus encrypted and rotated confidential credentials.
- Separate persistent authorization policy (owner, tenant, resource, operation), least privilege, rate limiting and audit.
- Shared deployment topology controls, proxy/header hardening, CORS/CSRF review and separate internet exposure gate.
- Account lifecycle, recovery, token revocation tests, clock skew policy, privacy/export/deletion and incident response.
- Separate PhiOS local approval of device and filesystem effects even if cloud identity passes.

**A recorded PhiID consent choice, Pocket approval, display profile, Gmail OAuth session, or matching `sub` is never permission to access this route.** Only a currently active, properly scoped and audience-restricted access token succeeds. No cloud account is required to operate PhiOS offline.
