# PhiCloud R6 — private durable synthetic tenant and owner proof

**Status: experimental, explicitly enabled, IPv4 loopback only. No actual PhiVault files, user content, production tenants or internet-facing service.**

R3 proved Keycloak token introspection, audience, scope and immediate revocation. R4 proved independent owners could not read or delete each other's temporary memory-only resources. R6 adds **one private SQLite database** so that exact ownership and explicit operator-provisioned tenant membership survive a resource-server restart.

R6 is deliberately independent of the concurrent PhiCloud R5 PhiShield/consent work. It does not grant an executable approval or turn a consent receipt into resource access.

## Trust model

The server must verify an active access token with exact issuer `http://127.0.0.1:8080/realms/phiid-dev`, audience `phicloud-resource-dev`, future expiry and **route-specific** `phicloud.tenant.read` or `phicloud.tenant.write` scope, by *fresh* confidential-client Keycloak introspection on every request.

The server derives the effective actor solely from the verified `(issuer, subject)`. The caller **cannot supply or alter** owner identity. Tenant IDs are only selectors, not permissions. Membership in a named tenant is checked against a separate private, operator-provisioned local membership table **before** a record operation. Both a matching tenant membership **and** matching record owner are needed for record access. Even two verified members of the same tenant cannot read or delete each other's markers.

All records are synthetic server-created metadata, with no uploaded/requested content, file paths, user-supplied ownership, object identifiers, mailbox data, or PhiOS device effects.

## Exact dev endpoints

All of these require `PHICLOUD_ENABLE_TENANT_DEV=1` *and* the existing `PHICLOUD_ENABLE_OAUTH_DEV=1`, a valid local confidential-client secret and a private local database path.

| Verb | Endpoint | Scope | Policy |
| --- | --- | --- | --- |
| GET | `/v1/private/tenants/{tenant}/records` | `phicloud.tenant.read` | Only actor-owned markers |
| GET | `/v1/private/tenants/{tenant}/records/{id}` | `phicloud.tenant.read` | Same tenant **and** record owner |
| GET | `/v1/private/tenants/{tenant}/audit` | `phicloud.tenant.read` | Only actor's synthetic create/delete audit events |
| POST | `/v1/private/tenants/{tenant}/records` | `phicloud.tenant.write` | Creates a server-owned marker for the authenticated actor |
| DELETE | `/v1/private/tenants/{tenant}/records/{id}` | `phicloud.tenant.write` | Deletes only actor's own marker, retaining a bounded audit event |

Write requests additionally need `X-PhiCloud-Action: create-tenant-test-record` or `X-PhiCloud-Action: delete-tenant-test-record`. No body, JSON, files, form fields, arbitrary owner, transfer encoding or action without a matching header is permitted. Browser-originated writes are accepted only when the Origin is the exact loopback server origin. Cross-site requests are rejected. Unknown tenants, nonmembers, unknown IDs and foreign-owned IDs all return the same 404 once a valid scope is verified.

On Keycloak rejection, 401; on Keycloak outage, 503; on bounded capacity, 429. The server does **not** cache positive token decisions.

## Private database and operator bootstrap

The optional local SQLite database is **not created** unless the R6 flag is set. It requires a pre-existing POSIX owner-private (`0700`) directory and an absolute `*.sqlite` path. Newly created DB files are `0600`. Shared permissions and symlink paths fail closed. Native Windows is deliberately unsupported until audited ACL handling exists; **WSL2/Linux** is suitable for local development.

A one-time, trusted operator fixture can pre-provision dev tenants and verified subject IDs. This is process-local configuration, **never a public HTTP route**, account signup, cloud provisioning service or production membership mechanism. The fixture must match exactly:

```json
{
  "schema": "phicloud.local-tenant-demo.v0.1",
  "tenants": [
    {
      "id": "alpha-team",
      "members": [
        {"iss": "http://127.0.0.1:8080/realms/phiid-dev", "sub": "DISPOSABLE_KEYCLOAK_TEST_SUBJECT"}
      ]
    }
  ]
}
```

**Do not commit actual subject IDs or credentials.** The example placeholder is not a real account. CI creates this fixture with two disposable Keycloak users and passes it in a private process environment variable (`PHICLOUD_TENANT_PROVISION_JSON`) on the first launch. Once provisioned, the database **refuses any later re-seeding**, including accidental changes on a subsequent process start. Restart the server without the fixture variable to reuse its existing memberships. There is no exposed membership-management API, automatic enrollment, or global admin wildcard.

Development process variables:

```text
PHICLOUD_ENABLE_OAUTH_DEV=1
PHICLOUD_OAUTH_CLIENT_SECRET=<private-dev-confidential-client-secret>
PHICLOUD_ENABLE_TENANT_DEV=1
PHICLOUD_TENANT_DB_PATH=/private/owner-only-directory/demo.sqlite
PHICLOUD_TENANT_PROVISION_JSON=<one-time-operator-created-fixture>
```

The local HTTP process still binds to `127.0.0.1` only. Never make this development port public, forward it to a LAN, attach it to a real hosted identity provider or copy production data into this fixture.

## Persistence, privacy, audit, limits

- SQLite stores an installation-specific salt and **salted SHA-256 pseudonymous indices** of verified `(issuer, subject)`, as well as tenant IDs, opaque record IDs and timestamps. The salt is *not* a password, signing key or substitute for full-disk encryption. The database must be treated as sensitive metadata.
- Records persist across process restarts but expire after **30 days**. They are pruned on future reads/writes. Explicit owner deletion physically removes the marker row; a lightweight `create`/`delete` event with the same opaque record ID remains in the local audit for up to **90 days**.
- Audit output shows **only the authenticated actor's events** within a tenant they belong to. No other user's audit or raw `iss/sub` is returned. The audit is normal SQLite data, **not a cryptographically tamper-evident or externally replicated log**.
- Bounded to 8 tenants, 16 provisioned members per tenant, 8 live records per owner/tenant, 128 live records overall and 1024 audit events. The store refuses additions when capacity is reached rather than silently evicting another user's records.
- An in-process lock and `BEGIN IMMEDIATE` transaction enforce atomic owner-checked record creation/deletion and corresponding audit writes. This **does not** demonstrate multi-node storage or backup/recovery.
- No account emails, user input, bearer/access/refresh tokens, plaintext passwords, file contents or resource payloads are stored in the database or returned by the API.
- The local database **is not encrypted**. It is a test fixture, and no real user content belongs in it. External file backups, operating-system permissions and retention policies require separate operator review.

## Verified test stages

The [R6 Keycloak workflow](../.github/workflows/tenant-durable-e2e.yml) tests a separate exact pinned PhiID development realm, two truly signed-in Keycloak accounts, temporary read/write scopes and a temporary confidential resource client. It proves identical tenant scopes do not bypass ownership, an unassigned tenant remains inaccessible, read/write scopes stay separate, and mutation acknowledgments are mandatory.

The test then **restarts the Python process using the same private SQLite file** and confirms both identities' data and audit history remain isolated. It deletes one user's marker, checks the audit record, logs out that user upstream, confirms the old token fails fresh introspection while the other user's token remains valid, restarts again and verifies deleted rows stay deleted.

The existing Python unit tests also test unsafe file modes, symlinks, invalid/duplicate operator fixture, no automatic membership, expiry, audit retention and capacity. The prior R3 and R4 tests, ANC advisory and PhiShield policy regression must remain green.

**This is not a production multi-tenant cloud design.** Before any real files or PhiVault data, implement reviewed tenant lifecycle and membership administration, migrations, encrypted data, ownership and ACL model, purpose-bound consent, egress controls, deletion/export, backup/restore, rate limiting, audit integrity, network/TLS security and incident recovery. Preserve offline PhiOS access and independent local effect approval.
