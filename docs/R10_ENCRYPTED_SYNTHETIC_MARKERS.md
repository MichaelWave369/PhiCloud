# PhiCloud R10: AES-256-GCM synthetic sealed markers

**Status: optional localhost-only security experiment. No user-provided plaintext, files, PhiVault bridge, cloud uploads, mailbox content, production KMS or real recovery escrow.**

R6–R9 proved separate security boundaries: verified Keycloak identity, precise audience and scopes, owner and tenant checks, durable SQLite records, offline revocation, and protection against SQLite-only stale-backup restoration. R10 is the next narrow milestone: **the database contains encrypted, integrity-authenticated synthetic marker values, but the 256-bit decryption key lives in an independent owner-private file.**

## What is actually encrypted?

Every R10 marker encrypts **exactly one fixed non-personal test canary**, created by the server, using the audited `cryptography` package's `AESGCM` implementation (AES-256-GCM). It is never supplied by the browser and is never returned as plaintext. Each row stores:

- An unpredictable opaque ID, tenant, pseudonymous issuer/subject owner index, creation and expiry times.
- A fresh 96-bit random nonce and the AES-GCM ciphertext/authentication tag.
- AES-GCM **associated authenticated data (AAD)** constructed from the schema, exact tenant, verified owner key, marker ID and timestamps. Altering those values, swapping a ciphertext between records or changing the ciphertext/tag makes decryption fail.

SQLite still stores the **tenant IDs, owner pseudonyms, IDs and timestamps as plaintext metadata**; the entire database is **not encrypted**. The previous R6 tenant records and audit are not retroactively encrypted. This proof demonstrates application-level encryption for a single fixed synthetic value only. Neither the pseudonymous index nor the key fingerprint is an authorization credential.

## Required explicit local opt-in

The R10 endpoints are **404 by default**. To enable them, the operator must first enable the existing R3 verified Keycloak gate and R6 private tenant store, and explicitly set:

```text
PHICLOUD_ENABLE_OAUTH_DEV=1
PHICLOUD_ENABLE_TENANT_DEV=1
PHICLOUD_OAUTH_CLIENT_SECRET=<private local Keycloak confidential-client secret>
PHICLOUD_TENANT_DB_PATH=/private/local-tenant/demo.sqlite
PHICLOUD_ENABLE_SEALED_DEV=1
PHICLOUD_SEALED_KEY_PATH=/private/independent-key-location/synthetic-demo.key
```

If the database has been enrolled in the R9 revocation witness, continue passing `PHICLOUD_ENABLE_FENCE_DEV=1` and its independent `PHICLOUD_TENANT_FENCE_PATH`; R10 does not permit bypassing R9's existing startup checks.

Create two **different** existing directories with POSIX `0700` modes (Linux/WSL2 only). They must not share a directory; keep the key directory outside the SQLite backup tree. The database must already be an existing owner-private synthetic fixture. Stop the PhiCloud server, then create the **one-time raw 32-byte key file** explicitly:

```sh
export PHICLOUD_SEALED_KEY_OPERATOR_DEV=1
python -m phicloud.sealed_key_operator \
  --db /private/local-tenant/demo.sqlite \
  --key-path /private/independent-key-location/synthetic-demo.key \
  --confirm 'CREATE SYNTHETIC TEST KEY'
```

The CLI obtains the same exclusive private SQLite process lock as R8/R9 operator tasks, generates 32 bytes from the OS CSPRNG, and writes an owner-private regular file (`0600`, `O_EXCL`, `O_NOFOLLOW`, `fsync`). **The key bytes are never displayed, logged, included in SQLite or committed to source.** An existing key will not be overwritten.

R10 checks the file path, regular-file/non-symlink status, private directory/permissions, exact key length, and database key fingerprint at startup. Missing, altered, broadly readable or replaced keys cause **fail-closed startup**. A lost key means the synthetic ciphertext can no longer be decrypted; R10 provides **no rotation, escrow, wrapping, recovery, or export of actual user keys.** Back up this disposable test key separately and securely if you want to exercise manual recovery, not in the same snapshot set as the SQLite DB.

## Scoped test HTTP endpoints

Exactly scoped real Keycloak access tokens must include audience `phicloud-resource-dev` and the route's `phicloud.sealed.read` or `phicloud.sealed.write`. Tokens are freshly introspected on each request. A valid account's `phicloud.profile.read` or `phicloud.tenant.read` token is insufficient.

| Operation | Route | Exact scope |
| --- | --- | --- |
| GET list | `/v1/private/tenants/{tenant}/sealed-markers` | `phicloud.sealed.read` |
| GET one | `/v1/private/tenants/{tenant}/sealed-markers/{id}` | `phicloud.sealed.read` |
| POST synthetic create | `/v1/private/tenants/{tenant}/sealed-markers` | `phicloud.sealed.write` |
| DELETE synthetic one | `/v1/private/tenants/{tenant}/sealed-markers/{id}` | `phicloud.sealed.write` |

The server binds IPv4 loopback only and checks its Host and peer, matching earlier rungs. Writes require exact `X-PhiCloud-Action: create-sealed-test-marker` or `delete-sealed-test-marker`, reject cross-origin browser mutations and **accept no request bodies or caller-chosen values**. All operations enforce current verified tenant membership and record ownership. For another owner's or nonexistent ID, HTTP 404 is indistinguishable. A failed integrity check returns HTTP 503 and does not provide decrypted content.

Markers expire in 10 minutes, at most 4 active per verified owner and 64 total. They persist locally until deletion, expiry pruning, owner revocation or database disposal. R8 and R9 now additionally **purge sealed ciphertext belonging to a revoked member in the selected tenant**, in the same SQL transaction as membership removal. Other tenants remain untouched. There is no actual file or full-user data deletion implementation.

## Evidence required before merge

- Python 3.11/3.12/3.13: key-file privacy, missing/wrong key refusal, no plaintext in SQLite, AES-GCM integrity against byte flips and manipulated owner+tenant metadata, expiry/ownership, route scopes/body denial, upstream revocation and provider failure.
- Pinned ANC and existing PhiShield auth regression unchanged.
- Disposable real Keycloak: two distinct users obtain dedicated sealed read/write scopes via PKCE, create and inspect their own sealed markers, get 404 for each other's IDs, and prove synthetic markers survive SQLite resource-server restart with the key outside its backup directory.
- R9 stale-backup rollback and revoke-only reconciliation must continue passing.

## Remaining limitations and next hard gates

A local `0600` raw key file is **not a KMS** and does not solve key lifecycle, key escrow, rotation, hardware-based protection, user-controlled encryption, disaster recovery, secure deletion from all backups, object encryption, network TLS, tenant migration, or malicious-host compromise. A privileged local actor can copy the key and database together and decrypt the test value.

Before any real PhiVault file integration, build a reviewed **envelope-encryption protocol with separately wrapped data-encryption keys**, explicit user-controlled recovery/export, securely stored KMS/HSM or offline custody and rotation, verified backup/restore consistency, per-resource ownership and durable audit. Keep PhiOS functional offline without any cloud account.

**R10 never converts a PhiID consent receipt or Pocket/PhiShield signature into access authority.** Only the resource server's fresh Keycloak verification and independent tenant+owner policies authorize its synthetic routes.
