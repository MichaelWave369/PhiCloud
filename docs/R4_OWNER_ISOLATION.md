# PhiCloud R4: owner-isolated disposable demo resources

**Status: development-only, localhost-only, in-memory test of per-user resource isolation. Not actual cloud storage or production account hosting.**

R3 proved that PhiCloud can reject invalid or revoked Keycloak OAuth2 access tokens and enforce the correct audience and scope. R4 addresses a separate question:

> **Can two different, properly authenticated users with the same authorized scopes nevertheless be prevented from reading or deleting one another's resources?**

R4 verifies this against actual disposable Keycloak users and the real Python PhiCloud resource server.

## Deployment and independence

The R0 declarative service inventory `GET /v1/services` stays publicly readable. The existing R3 protected profile `GET /v1/private/profile` still requires `phicloud.profile.read`.

The new owner demo is **OFF by default**, independently of R3. It is enabled only when both `PHICLOUD_ENABLE_OAUTH_DEV=1` and `PHICLOUD_ENABLE_OWNER_DEMO=1` are set in the **local process** with a valid, private Keycloak confidential-client secret. It continues to bind to `127.0.0.1` only and rejects conflicting Host headers and non-loopback clients. Setting only the owner-demo flag without enabling OAuth fails startup.

It does not require, modify, or grant PhiOS local authority; PhiOS must continue running without a network connection or PhiCloud identity.

## API (disposable)

All routes use fixed audience `phicloud-resource-dev` and real, fresh Keycloak token introspection for **every operation**. No direct client-controlled ownership metadata is accepted. Every record is owned by the exact verified `(issuer, subject)` pair:

| Method | Path | Required scope | Effect |
| --- | --- | --- | --- |
| `GET` | `/v1/private/demo-records` | `phicloud.demo.read` | Lists only the caller's in-memory test records |
| `GET` | `/v1/private/demo-records/{id}` | `phicloud.demo.read` | Returns a record **only if owned by the caller** |
| `POST` | `/v1/private/demo-records` | `phicloud.demo.write` | Creates one server-generated, owner-bound, payload-free record |
| `DELETE` | `/v1/private/demo-records/{id}` | `phicloud.demo.write` | Deletes only the caller's own record |

The write routes also require `X-PhiCloud-Action: create-demo-record` or `X-PhiCloud-Action: delete-demo-record`. No request body, content type, transfer encoding, or caller-supplied `owner` is accepted. Browser-originated calls may only use the exact same loopback origin. Cross-site Fetch requests are rejected. A foreign or nonexistent ID always returns HTTP 404, without revealing whether another account owns it.

Authentication failure or inadequate scope returns 401. If Keycloak is unreachable, the request fails closed with 503. Service capacity is bounded and creates return 429 rather than evicting another user's records.

## Data lifetime and limits

- A record contains only an unpredictable server-generated opaque ID, internal OIDC issuer/sub owner key, and timestamps. No names, email addresses, message bodies, files, user-entered text, passwords, tokens or keys are stored in records.
- The server returns only a minimal test descriptor with `kind:disposable_owner_test_only`, `persistent:false`, `files_present:false`, `cloud_storage_access:false`, `mailbox_access:false` and `phios_effect_authority:false`. Raw OIDC subject or issuer is **not exposed in resource responses**.
- Records expire after 10 minutes and disappear whenever the Python process restarts. Expiry is pruned when the store is accessed. There is **no persistent account database**, filesystem storage, cloud replication, backup, or recovery.
- Maximum **4 concurrent records per subject** and **64 across the development process**. A per-process lock protects create, list, read, delete and expiry checks against concurrent request races.
- A valid token with only `phicloud.demo.read` cannot create/delete. One with only `phicloud.demo.write` cannot list/read. The old `phicloud.profile.read` token cannot access these endpoints.

## Real-provider testing

The existing [Keycloak resource workflow](../.github/workflows/keycloak-authz.yml) is extended, rather than replaced. It pins a reviewed PhiID fixture and starts a disposable loopback-only Keycloak 26.x realm. The test registers a temporary confidential PhiCloud resource server and creates **three optional scopes** on the local test client's Keycloak realm:

- `phicloud.profile.read` for R3's profile.
- `phicloud.demo.read` for R4's read-only test resources.
- `phicloud.demo.write` for R4's create/delete operations.

Two disposable Keycloak test accounts each complete their own real authorization-code plus PKCE exchange and receive distinct access tokens containing the same demo scopes. The Python server then verifies:

1. Both can create/list/read their own bounded test records.
2. Neither can read or delete the other's opaque record ID, even when provided that exact ID.
3. Read-only and write-only token scopes enforce different operations. Identity-only and profile-only tokens are denied.
4. Explicit mutation action headers are required and no arbitrary user data is accepted.
5. Keycloak logout of user A immediately makes A's token unusable through fresh introspection, but **does not** terminate user B's token or disclose B's record.
6. Both disposable user accounts and the Keycloak container are cleaned up.

Additional Python tests use injected provider/clock doubles to cover expiry, capacity, issuer+subject isolation, cross-user delete denial, temporary provider failure and default-off mode. These mocked tests are **additional** to the real provider test, not a substitute for it. Existing R0 inventory tests and ANC/PhiShield advisory integration remain intact.

## What this does *not* prove

This is a **correctness demonstration of owner equality and OAuth scope enforcement under a disposable development realm**, not real tenant/account separation on a database, cloud file storage, encrypted persistence, secure recovery, hosted user management, continuous availability or a production security audit.

Before any actual user data is attached, implement tenant-aware persistent resource ownership, secure database migrations, per-resource permissions, privacy/export/delete guarantees, durable auditing, storage encryption/key management, request/rate limits, backup isolation, incident response and a separate HTTPS deployment review. Revisit the token issuer, audience, scope definition, client security and verification against the actual production IdP.

**Authentication is not authorization, and even a correctly authorized cloud request must never bypass local PhiOS effect approval.**
