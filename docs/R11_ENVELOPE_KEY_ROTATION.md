# PhiCloud R11: envelope-encrypted synthetic markers and offline KEK rotation

**Status:** experimental, default OFF, loopback/WSL2/Linux only. This is an integration proof for a fixed non-personal test canary. It is **not** production key management, hosted storage, encrypted real files, account recovery, or a PhiVault bridge.

## Why R11 exists

R10 encrypts fixed synthetic markers using one private 256-bit AES-GCM key. R11 instead generates a **unique random 256-bit data-encryption key (DEK) for every newly created R11 marker**, encrypts that one fixed synthetic value with the DEK using AES-256-GCM, and then **wraps the DEK** with an independent private 256-bit key-encryption key (KEK) using AES-256-GCM.

This allows an offline operator to **rewrap the DEKs** under a new KEK without changing or decrypting/re-encrypting the payload ciphertext. R10's existing ciphertext table is untouched. Both stages use the pinned, reviewed `cryptography` package, not a custom cryptographic primitive.

## Authenticity, identity and boundaries

Each payload AEAD and DEK wrapping AEAD has independently randomized 96-bit nonces. Each stage's authenticated associated data contains its domain tag, the schema, exact tenant, verified `(issuer, sub)` pseudonymous owner index, server-generated opaque record ID and timestamps.

The R11 record database contains tenant/owner pseudonym metadata, payload nonce and ciphertext, KEK wrap nonce and wrapped DEK, and times. There is **no raw DEK, KEK, raw issuer/subject, plaintext canary, user body or actual file** in these records. The independent local private KEK file is never returned over the HTTP API, written to SQLite, embedded in a frontend bundle or committed to source.

SQLite metadata includes a non-secret SHA-256 fingerprint of the *random KEK* to recognize the exact active key at startup and refuse an incorrect key. This fingerprint is **not** a credential or a substitute for independent key custody.

A matching Keycloak bearer token is necessary but **not sufficient**. Every request must pass fresh confidential-client introspection, exact `phicloud-resource-dev` audience, the separate `phicloud.envelope.read` or `phicloud.envelope.write` scope, existing server-side tenant membership, and exact marker ownership. Two valid users with identical scopes cannot read or delete each other's markers.

No R11 token creates a cloud file, accesses a mailbox, grants PhiOS local effect authority, changes tenant membership, or overrides a PhiID/PhiShield operator review.

## Configuration and operator workflow

R11 is OFF by default. Both R3's Keycloak authorization and R6's owner-private SQLite test store must already be enabled. The local machine must be nonproduction and use IPv4 loopback. To enable the feature for only synthetic canaries:

```text
PHICLOUD_ENABLE_OAUTH_DEV=1
PHICLOUD_ENABLE_TENANT_DEV=1
PHICLOUD_OAUTH_CLIENT_SECRET=<private local development secret>
PHICLOUD_TENANT_DB_PATH=/private/local-fixture/tenant.sqlite
PHICLOUD_ENABLE_ENVELOPE_DEV=1
PHICLOUD_ENVELOPE_KEK_PATH=/private/separately-backed-up-key/envelope-v1.key
```

Any R9 revocation witness enrollment still requires its correct independent witness file and explicit R9 flags. R11 does not weaken that startup gate.

1. Stop the local PhiCloud server. Pre-create a **different** `0700` owner-private key directory outside the SQLite backup directory. Generate two distinct random test KEKs using R10's existing offline `phicloud.sealed_key_operator` command, with `PHICLOUD_SEALED_KEY_OPERATOR_DEV=1`, `--db` pointing at the existing test SQLite, and a different `--key-path` ending in `.key` for each one. The command holds the exclusive DB lease; it outputs no key bytes. The files are `0600`.
2. Start PhiCloud with `PHICLOUD_ENVELOPE_KEK_PATH` pointing at the **first** private test KEK. Create/read only the fixed server-generated synthetic markers using the routes below.
3. Stop PhiCloud and run the separately guarded offline **rewrap** operator (this does not create keys, change membership or invoke a web endpoint):

```sh
export PHICLOUD_ENVELOPE_OPERATOR_DEV=1
python -m phicloud.envelope_operator \
  --db /private/local-fixture/tenant.sqlite \
  --old-key /private/separately-backed-up-key/envelope-v1.key \
  --new-key /private/separately-backed-up-key/envelope-v2.key \
  --confirm 'REWRAP SYNTHETIC ENVELOPES'
```

If the SQLite database is enrolled with an R9 witness, pass `--fence` with the correct private witness path. The R11 CLI opens the store with the **same exclusive POSIX lock** used by the server and R8/R9 operators. It fails closed if the server is still running or an old key is not the currently active key.

4. R11 verifies and decrypts **all** wrapped DEKs and checks every corresponding synthetic payload before modifying any row. In one SQLite transaction it produces new random wrapping nonces and rewraps all DEKs under the new KEK, then updates the active-key fingerprint. The payload nonce and ciphertext are unchanged, as are record IDs, tenant and owner. Any failed row, tampered ciphertext or SQL error rolls back the entire rotation and retains the old active key.
5. Restart PhiCloud with `PHICLOUD_ENVELOPE_KEK_PATH` pointing at the **new** key. The old KEK is now rejected for the rotated database. The old KEK file is **not automatically deleted or modified**. Preserve key custody until the operator has separately reviewed backup/recovery implications.

No API route can rotate a key, upload a payload or select an owner. The R11 HTTP routes are strictly:

| HTTP | Route | Required scope |
| --- | --- | --- |
| GET list | `/v1/private/tenants/{tenant}/envelope-markers` | `phicloud.envelope.read` |
| GET one | `/v1/private/tenants/{tenant}/envelope-markers/{id}` | `phicloud.envelope.read` |
| POST create fixed marker | `/v1/private/tenants/{tenant}/envelope-markers` | `phicloud.envelope.write` |
| DELETE own marker | `/v1/private/tenants/{tenant}/envelope-markers/{id}` | `phicloud.envelope.write` |

POST and DELETE require `X-PhiCloud-Action: create-envelope-test-marker` or `delete-envelope-test-marker`, respectively. Request bodies, arbitrary owner IDs, content types and cross-origin writes are rejected. The fixed marker expires in ten minutes, with at most four markers per owner and 64 per local fixture. **Only metadata flags** are sent in responses, never keys, wrapped DEKs, raw nonce/ciphertext or plaintext.

When an offline operator revokes tenant membership using R8/R9, PhiCloud deletes that member's R11 wrapped DEKs and ciphertext from the selected tenant **inside the same transaction**, leaving other tenants and owners unaffected.

## Tests and known limitations

The Python tests cover unique wrapped DEKs, data/KEK ciphertext never appearing in SQLite plaintext, tampering of both AEAD stages and owner metadata, correct scopes and ownership, missing/unsafe keys, offline lock refusal, transaction rollback on injected SQL failure, old-key denial and new-key restart, and revocation purge. The existing real disposable Keycloak test uses **two separate test users** with independent R11 scopes; after creating markers, it invokes the offline KEK rotation and proves existing markers remain available only to the right owner under the **new** key, with the old key refused.

**Key rotation is not key recovery.** R11 has no KMS/HSM, escrow, key wrapping for actual user-controlled access, password recovery, cloud account lifecycle, purpose-bound customer consent, file storage, production key export, signed independent rotation witness or disaster recovery across machines. The SQLite database remains plaintext for tenant/owner metadata, audit, R6 markers and R10 encrypted-marker metadata.

**Important backup limitation:** restoring an earlier SQLite snapshot together with the old KEK can revert rotation state, even though restoring a stale SQLite-only revocation snapshot is separately caught by R9 when its independent witness survives. R11 does not make key rotation rollback-proof. Before actual PhiVault files, protect key-rotation epochs outside the SQLite backup domain and design independent operator recovery, backed-up key custody, explicit user-controlled export/deletion and safe key retirement.

This prototype tests **encryption mechanics only**. It must not accept real personal data.
