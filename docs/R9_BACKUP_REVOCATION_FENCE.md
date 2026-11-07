# PhiCloud R9: backup-aware revocation witness and revoke-only recovery

**Experimental, default-off, Linux/WSL2 localhost security test.** R9 operates only on PhiCloud's existing **synthetic** tenant markers and private SQLite test database. It does not store real PhiVault files, grant production tenant privileges, encrypt data, or constitute tamper-proof backup/recovery.

## The failure R9 prevents

R8 removes a person's local tenant membership and records a tombstone in SQLite. But if an operator restores **an older copy of that entire SQLite database**, the local tombstone disappears with it and the still-active Keycloak token might regain that tenant's records. Ordinary SQLite transactions cannot detect that the whole DB was rolled back.

R9 adds a **separate, append-only, owner-private revocation witness** in a **different private directory**. The resource server requires the witness and checks its accumulated tenant/subject revocations against the SQLite tombstones and memberships **before opening an enrolled test database for normal traffic**. The independent witness is never part of the SQLite backup. Restoring only old SQLite while retaining the current witness leads to a **startup denial**, not restored access.

### Trust boundary and non-guarantees

This is a *two-copy rollback guard against accidental or incomplete restoration* on one trusted local machine. The witness is an append-only JSONL file, not a secure monotonic counter, distributed consensus, immutable cloud log, hardware-backed state, signed audit, or protection from a malicious local operator. **Restoring both an older SQLite database AND its older witness, deleting the witness and disabling the guard on an unenrolled older DB, or compromising the local host can defeat it.** No such design is acceptable as a production authorization or recovery system without a separately protected external revocation authority and backup policy.

The R8 private lock stays in effect. An operator cannot enroll, revoke, or reconcile while the service holds the database lease.

## One-time local enrollment

R9 requires an existing owner-only `0600` SQLite test database (R6/R8) in a `0700` directory, and a separately created **different** owner-only `0700` witness directory. Do **not** put the witness file inside the SQLite backup directory or restore it from the same snapshot set.

The operator command uses only stdin for confirmation and never accepts credentials, Keycloak tokens, service data, or raw subjects in argv:

```sh
# Stop PhiCloud first. Both paths are examples, not production locations.
mkdir -m 700 -p /private/local-phi-tenant-db /private/local-phi-revocation-fence
export PHICLOUD_TENANT_RECOVERY_DEV=1
printf '%s' '{"schema":"phicloud.tenant-recovery-operator/0.1","confirmation":"ENROLL INDEPENDENT WITNESS"}' |
  python -m phicloud.tenant_recovery \
    --db /private/local-phi-tenant-db/demo.sqlite \
    --witness /private/local-phi-revocation-fence/revoked.jsonl --enroll
```

Enrollment is **one-way**: the existing SQLite DB is bound to a random private witness identity; the witness snapshots all **previous** R8 membership tombstones and any future revocation is appended there first. The witness file is created with `O_EXCL`, an owner-only `0600` mode and explicit `fsync` (also on its directory). Enrollment cannot overwrite a witness or rebind an enrolled database.

**Interrupted enrollment fails closed:** If SQLite is marked enrolled but witness creation is interrupted, the database refuses normal startup. The prototype does not offer a silent reset, re-enrollment, or force-to-ignore control. Back it up and investigate manually; do not erase tombstones to make tests pass.

To run the **test-only** tenant service after enrollment, keep the original R6 environment and set:

```text
PHICLOUD_ENABLE_FENCE_DEV=1
PHICLOUD_TENANT_FENCE_PATH=/private/local-phi-revocation-fence/revoked.jsonl
```

If the enrolled database is opened without its witness, with a symlink, with shared file/directory permissions, or with a witness whose database binding or revocation entries disagree with SQLite, the process fails closed. The R8 operator command also requires the same fence environment when revoking members of an enrolled DB.

## Ordering of a witnessed revocation

With the local server stopped and offline operator intent confirmed using R8's existing `tenant_operator` CLI:

1. Confirm the current database and witness agree and the member is active.
2. **Append and `fsync`** the independent irreversible local witness event.
3. In a SQLite `BEGIN IMMEDIATE` transaction, delete only that member's synthetic markers in the selected tenant, remove membership and insert the matching SQLite tombstone.
4. Commit SQLite and release the shared process lease.

If step 3 fails or crashes, the witness is **ahead** of the DB. On the next startup, a normal resource server refuses access. **No rollback of the independent revocation** occurs.

## Operator recovery after an older SQLite-only restore

The operator must stop PhiCloud, preserve both files for investigation, and use a separate, explicit **revoke-only** reconciliation. It never adds memberships or recreates deleted markers:

```sh
export PHICLOUD_TENANT_RECOVERY_DEV=1
printf '%s' '{"schema":"phicloud.tenant-recovery-operator/0.1","confirmation":"RECONCILE REVOKE ONLY"}' |
  python -m phicloud.tenant_recovery \
    --db /private/local-phi-tenant-db/demo.sqlite \
    --witness /private/local-phi-revocation-fence/revoked.jsonl --reconcile
```

Reconciliation matches the bound DB/witness identity, rejects SQLite-only/unwitnessed tombstones (which could indicate a lost witness update), **removes** all memberships and synthetic markers covered by the witness and restores any missing SQLite tombstones with their original timestamps in one SQLite transaction. It writes a local `recovery_events` count and remains idempotent. It never issues/revokes upstream OAuth tokens and never restores account access.

After successful reconciliation, the operator can restart the guarded service. Any still-active Keycloak bearer token remains insufficient: the local tenant membership has been removed and per-request owner/membership checks continue to deny it. A DB snapshot taken **before fence enrollment**, without the fence binding identity, fails closed when the witness is enabled and is not automatically repaired.

### Operational limits

- Witness contains only tenant IDs, salted local pseudonymous principal keys, timestamps, a random DB binding ID and exact R8 tombstones. No raw `iss/sub`, emails, cookies, passwords, tokens or file payloads.
- Witness is limited to 1024 unique events and 256 KiB. It rejects duplicates, malformed/truncated JSONL, symlinks, shared permissions and mismatched identities. Capacity exhaustion fails closed rather than dropping revocations.
- SQLite database and witness must remain **independently backed up and protected**. R9 does *not* supply a full backup system, recovery key service, file encryption, backup retention policy, restored-data attestation, or disaster recovery across separate machines.
- A witness updated ahead of SQLite is an intended, safe recovery condition. A SQLite tombstone that has no matching witness event is **not** silently discarded by reconciliation.
- The append file is not cryptographically authenticated. A privileged local attacker can tamper with it; treat it as an accidental-rollback test, not a production security guarantee.

## Testing

- `tests/test_tenant_fence.py`: stale SQLite snapshot refusal, revoke-only recovery, old R8 tombstone carry-forward, interrupted SQLite commit after fsynced witness, no re-grant, missing/corrupt/symlink/broad-permission witness refusal, duplicate entries, and required operator confirmations.
- Existing Python 3.11/3.12/3.13 and ANC/PhiShield regression suites remain unchanged in authorization scope.
- The existing R6 two-real-user disposable Keycloak workflow now enrolls an independent witness **after** R8 proves its initial revocation, takes a SQLite-only snapshot, records another local revocation, restores the stale SQLite snapshot, confirms normal startup denial, performs offline reconciliation, then verifies the **still-active** Keycloak token cannot re-enter the revoked tenant.

**No actual PhiVault, PhiID account recovery, production credentials, third-party objects, cloud files, or local PhiOS effects are modified by R9.**

The next hard prerequisite for real data remains: independently protected recovery authority, encrypted file/object storage, tenant lifecycle/ownership ACL reviews, privacy export/deletion and trustworthy multi-node audit.
