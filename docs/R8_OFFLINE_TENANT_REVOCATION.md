# PhiCloud R8: offline one-way tenant membership revocation

**Status:** disposable local development security exercise. **Not** a public tenant administrator, production identity lifecycle, cloud file erasure, or a replacement for Keycloak session logout.

R6 established persistent local SQLite membership and synthetic owner-bound records. R8 adds the missing inverse operation: a trusted **offline operator** can remove one named member from one named tenant without recreating the entire database or deleting records owned by anybody else. A matching, still-active access token cannot re-enroll the user.

The concurrent R7 signed review work is separate. An Ed25519 operator review or PhiID consent receipt does not authorize this tenant operation, and the R8 CLI cannot authorize a device or effect.

## Critical boundaries

- The operation is **never** exposed as an HTTP route. Only a local OS user who can open the private `0600` SQLite file may invoke it.
- CLI execution requires `PHICLOUD_TENANT_OPERATOR_DEV=1`, an existing absolute private database path, and a nonproduction process. The CLI refuses to silently create a fresh database.
- The resource server and CLI both hold the **same exclusive nonblocking POSIX flock** on a persistent owner-private `.sqlite.lock` file. While the server is running, CLI preview and apply **fail closed**. This enforces an offline maintenance window for this single-process prototype.
- `--apply` additionally requires explicit `acknowledge:"REVOKE <tenant-id>"` matching the exact tenant name. Preview remains the default. These are operator safeguards, **not cryptographic human authentication**.
- The operator provides the exact development Keycloak issuer and subject in private **stdin JSON**, not CLI arguments, URL query parameters, logs or source code. The CLI never echoes the raw subject or its hash.
- Revocation atomically removes that specific `(tenant, subject)` membership, deletes only that owner's synthetic markers **inside that tenant**, and writes a durable private membership tombstone recording a timestamp and count of removed markers. Existing bounded create/delete audit rows are retained.
- Already-revoked operations are idempotent. Any attempt to find both an active membership and revocation tombstone fails closed as an integrity anomaly.
- Other tenant memberships, unrelated users' synthetic records and audit entries remain intact.
- A valid existing OAuth token **can remain active in Keycloak**. That does not allow tenant access, because the resource server separately checks current SQLite membership **after fresh token introspection** on each request. R8 does *not* revoke the upstream OAuth token.
- Database backups/restores, manual file tampering, owner metadata deletion, per-user privacy export, or authorized re-enrollment through an administrator UI are **not implemented**. A restore from a stale database backup could undo the local revocation. A production rollout therefore requires backup-aware revocation epochs/tombstone replication.

## Private maintenance procedure

Run on Linux/WSL2, with the PhiCloud local server **stopped**. Do not copy production subject IDs into this experimental fixture. The database must already be provisioned using the R6 operator fixture. It uses a pre-existing `0700` directory, `0600` database and `0600` lock file. No Windows-native ACL support is claimed.

The input is versioned and has exactly four fields:

```json
{
  "schema": "phicloud.local-tenant-operator-request.v0.1",
  "tenant": "alpha-team",
  "member": {
    "iss": "http://127.0.0.1:8080/realms/phiid-dev",
    "sub": "DISPOSABLE_LOCAL_KEYCLOAK_SUB"
  },
  "acknowledge": null
}
```

Send this JSON through standard input, not a shell command argument. First preview, without `--apply`:

```sh
export PHICLOUD_TENANT_OPERATOR_DEV=1
python -m phicloud.tenant_operator --db /private/phi-test/demo.sqlite < /private/owner-only/revoke-request.json
```

For actual removal, consciously update the JSON's final `acknowledge` to `"REVOKE alpha-team"`, then invoke:

```sh
python -m phicloud.tenant_operator --db /private/phi-test/demo.sqlite --apply < /private/owner-only/revoke-request.json
```

The JSON file is for **disposable test accounts only** and must be owner-private, never committed to git or passed through shared shell history. Alternatively pipe it from a trusted local source into stdin, while avoiding shell output and debug tracing.

Preview returns membership status, owned marker count and any previous tombstone. Apply returns a typed summary with `changed`, `previously_revoked`, `removed_markers`, `external_token_revoked:false`, `production_effects:false`. Neither returns Keycloak IDs, subject hashes, bearer tokens, private signing keys or stored resource names.

## Why the lock matters

SQLite transactions are atomic, but a second process editing memberships while a server holds a live connection could otherwise cause confusing cross-request behavior. R8 takes a **nonblocking process-exclusive advisory lock** in the private DB directory before opening SQLite. Both the app server and offline operator need the lock. Attempting to start a second server or operator against the same file fails immediately.

Advisory locking assumes all cooperating writers use this code. A hostile local process with file write permissions could ignore it. Do not interpret this as a tamper-evident log or secure against a compromised host.

## Tests and acceptance

- Python tests cover file/lock mode safety, active-server rejection, exact request schema and duplicate JSON field denial, production/opt-in failure, preview without mutation, explicit tenant confirmation, unrelated-tenant isolation, atomic rollback on a failed tombstone insert, repeat revocation, and absence of implicit re-grant.
- The existing R6 **real disposable Keycloak** integration now adds offline revocation between server restarts: two real signed-in users hold scoped tokens, an operator revokes one membership from one tenant, and the server verifies that the **still-active** bearer is rejected for that tenant after restart while the other tenant remains accessible.
- R3 authorization, R7 signed-review when integrated, ANC/PhiShield and offline PhiOS are independent. No user-supplied content, real file data, mailbox or OS/device effect occurs.

**Next rung:** reviewed tenant lifecycle and role administration, backup-aware revocation recovery, encrypted storage and privacy export/deletion before any real PhiVault file is introduced.
