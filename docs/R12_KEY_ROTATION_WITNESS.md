# PhiCloud R12: independent key-rotation witness and exact pending-epoch repair

**Experimental, nonproduction, Linux/WSL2 localhost only. Synthetic canaries, no personal data, no real PhiVault files.**

## Failure mode

R11 introduced per-marker AES-256-GCM DEKs wrapped under a separate private KEK. But an operator restoring **both an older SQLite snapshot and its matching old KEK** could silently revert the rotation. R9's separate witness records **membership revocations**, not key-rotation epochs.

R12 introduces a **different owner-private JSONL witness** tracking KEK fingerprints and sequential rotations. It lives in a directory separate from both the SQLite backup and KEK directory. The witness survives a SQLite-only or SQLite-plus-KEK restore and must match the database's active wrapping-key fingerprint whenever R11 is enabled.

This is a proof against **accidental or partial restore**. A privileged operator who rewinds the database **and the witness**, or restores a pre-enrollment database with no R12 binding, can defeat this local-only technique. The witness is not cryptographically signed, physically monotonic or hosted in a trustworthy external authority.

## Operator setup

Stop PhiCloud and use two existing, distinct, owner-private 256-bit local test KEKs created using the R10 `sealed_key_operator`. Both KEKs must be located outside the SQLite directory. Prepare a **third separate private directory** (`0700`) for the R12 witness, kept independently from both SQLite and the KEK backup.

Enrollment is **one time**. The existing R11 envelope table and active key must have been initialized first. An invalid destination is rejected before SQLite is marked; an interruption after SQLite is marked forces startup to fail closed.

```sh
export PHICLOUD_ROTATION_WITNESS_OPERATOR_DEV=1
python -m phicloud.envelope_rotation_enroll \
  --db /private/phi-test/tenant.sqlite \
  --active-key /private/phi-keys/kek-v1.key \
  --rotation-witness /private/phi-epochs/rotations.jsonl \
  --confirm 'ENROLL SYNTHETIC KEY ROTATION WITNESS'
```

If the private SQLite fixture is enrolled in R9 tenant-revocation witness protection, also supply `--tenant-fence` pointing to its own witness.

The witness file is created with `O_EXCL`, `O_NOFOLLOW`, owner-only permissions (`0600`), a fsynced header, and an fsynced parent directory. SQLite stores a separate random binding ID. The witness header records the initial KEK's nonsecret fingerprint. Each appended event records exactly one prior-to-next fingerprint transition. There are no passwords, raw key bytes, bearer tokens, subjects, file contents or user plaintext. Epochs cannot repeat or go backward through normal operator commands.

### Rotation after enrollment

Enable R11 as usual, with these two additional settings for **local development**:

```text
PHICLOUD_ENABLE_ROTATION_FENCE_DEV=1
PHICLOUD_ENVELOPE_ROTATION_WITNESS_PATH=/private/phi-epochs/rotations.jsonl
```

Run the existing R11 operator with the independent witness while the server is stopped:

```sh
export PHICLOUD_ENVELOPE_OPERATOR_DEV=1
python -m phicloud.envelope_operator \
  --db /private/phi-test/tenant.sqlite \
  --old-key /private/phi-keys/kek-v1.key \
  --new-key /private/phi-keys/kek-v2.key \
  --rotation-witness /private/phi-epochs/rotations.jsonl \
  --confirm 'REWRAP SYNTHETIC ENVELOPES'
```

Add the existing `--fence` argument if SQLite is enrolled in R9. The operator obtains the same exclusive POSIX database lease used by R8/R9/R11. It verifies **every** existing DEK wrap and synthetic payload first. It then **appends and fsyncs** the next KEK epoch in the separate witness **before** modifying SQLite. Only afterward does it rewrap every DEK and update the active key fingerprint in one SQLite transaction.

The encrypted payload ciphertext and record IDs stay exactly the same; only the DEK wrapping fields change. The operator does not automatically delete old keys, export data or create any users.

## Fail-closed restore and recovery

If SQLite commit fails after the independent witness was fsynced, or if someone restores an older SQLite snapshot while keeping the witness, the witness will be **ahead** of SQLite. On startup, even an old KEK matching the restored database is rejected because the surviving independent witness records the newer rotation.

To recover, the operator must preserve both copies for investigation and explicitly complete **one exact pending rotation**, with the old and new private keys:

```sh
python -m phicloud.envelope_operator \
  --db /private/phi-test/tenant.sqlite \
  --old-key /private/phi-keys/kek-v1.key \
  --new-key /private/phi-keys/kek-v2.key \
  --rotation-witness /private/phi-epochs/rotations.jsonl \
  --resume-pending \
  --confirm 'RECONCILE SYNTHETIC KEY ROTATION'
```

A pending repair is allowed only when the database's active key equals the **immediate previous** fingerprint and the witness's latest event has exactly that old and new key pair. It refuses an absent/mismatched witness, earlier multi-epoch restores, wrong keys and arbitrary transition skips. It appends **no new witness event**. The same all-record AEAD verification and atomic SQLite rewrap then complete the already-recorded transition. It cannot regrant tenant membership, revoke upstream tokens, bypass R9, or restore deleted records.

If the witness is missing, truncated, altered, shared-permission, placed with database/keys, bound to another database, or contains invalid/repeated epochs, protected startup fails. Deleting the witness or simply disabling R12 is **not** an accepted recovery for an enrolled database. There is no silent reset or downgrade.

## Demonstrated tests

- Unit tests simulate SQLite plus old-KEK restore while the independent witness survives, and verify default startup denial followed by exact one-step offline reconciliation, payload-byte preservation and owner-isolated reads.
- Inject a failing SQLite rewrap trigger after the witness append. Normal reopening fails; a separately confirmed exact pending repair restores the expected key epoch. Out-of-order/old-key transitions remain rejected.
- Wrong destination and unsafe witness modes fail; enrollment refuses to overwrite a prior witness. A concurrent operator cannot change a running database because of the exclusive process lease.
- The pinned real-Keycloak CI uses two separate disposable users and independently scoped envelope read/write tokens. It reproduces a stale SQLite plus old KEK snapshot after a second rotation, checks that protected startup fails, performs offline exact-key reconciliation, and verifies both users can still read **only** their own canaries. Existing R9 stale tenant revocation tests remain separate and must still pass.

## Limits

This single-host JSONL witness is **not immutable**, hardware-bound, cryptographically authenticated, multi-node-safe or protected against a malicious host operator. If the witness is also restored to the matching old epoch, rotation can roll back. A database snapshot created **before** R12 enrollment has no binding and needs independent external tracking; R12 does not solve this. Recovery spanning several older epochs is not automated, by design.

R12 is **not production KMS/HSM, escrow, key backup, customer-managed keys, real storage encryption, account recovery or PhiVault integration**. Tenant/owner metadata, audit and earlier R6 synthetic records remain plaintext in SQLite. No remote service or actual files were touched. Before real user data: separately trusted monotonic authority, encrypted backup design, key custody and retirement protocol, production-grade audit, export/deletion and an independent security review.
