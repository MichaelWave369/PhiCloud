# PhiCloud R6: durable, one-use local synthetic-profile review ledger

**Status:** Optional POSIX-only SQLite reference implementation. No public
service/API, production authentication, cryptographic human approval, real
resource storage, device authorization, or cloud service is introduced.

## Purpose

R5 kept reviews and owner revocations in process memory. Restarting the
process erased both, so an old approval could not be distinguished from a
never-seen request ID and a revoked owner might be re-registered by an
otherwise valid login.

R6 adds `phicloud/durable_consent.py` as a separate opt-in backend:
`DurableOwnerConsentPolicy`. It implements the same local owner/review
operations but stores **operator-local** state in SQLite with atomic
`BEGIN IMMEDIATE` transactions and `synchronous=FULL`.

- The exact verified `(issuer,subject)` owns only the **synthetic**
  `profile:synthetic-self` resource and `profile.read` operation.
- Staged reviews expire after 60 seconds. Explicitly acknowledged reviews
  are valid for at most 30 seconds. An operator may use the existing
  `operator_console_review` terminal helper, which requires typing
  `APPROVE <request_id>` on an interactive TTY.
- `consume()` atomically marks approval as spent before generating
  request-bound, non-authoritative policy evidence. Separate connections
  and processes share the SQLite lock and cannot both consume a review.
- **Request-ID tombstones are retained indefinitely** within the bounded
  reference ledger, even after denial, expiry and restart. Capacity
  exhaustion denies new reviews; it does not evict used IDs.
- `revoke_owner()` atomically records a persistent revocation tombstone
  and invalidates pending and approved reviews. Even a freshly validated
  Keycloak login cannot automatically re-register the revoked owner.
  Explicit re-enrollment or unrevocation is intentionally **not
  implemented**.
- Unsupported actions/resources, wrong subjects, stale approval, missing
  database, incompatible schema and unsafe storage paths fail closed.

**Important:** This is a persistence mechanism, not an identity verifier.
It relies on the existing R3 Keycloak introspection path for a validated
subject and on a trusted, local operator process for staging/review. There
is no API that accepts browser consent JSON or client-selected owners.
`CANDIDATE` is **never** executable authorization.

## Setup

Python 3.11+, standard library only. For this rung, secure POSIX directory
checks are required. **Windows-native usage fails closed** until a proper
Windows ACL and filesystem threat review is implemented. WSL or a private
Linux test container can be used for development, but neither turns this
into a production control.

Create a directory owned by the operator with mode `0700`, outside your
repository and outside web-served or shared storage:

```sh
install -d -m 700 "$HOME/.local/share/phicloud-r6"
python -m unittest discover -s tests -v
```

In trusted Python application code, construct:

```python
from pathlib import Path
from phicloud.durable_consent import DurableOwnerConsentPolicy

policy = DurableOwnerConsentPolicy(
    Path.home() / ".local/share/phicloud-r6/reviews.sqlite3"
)
```

Pass `policy` into `stage_verified_profile_review()`,
`operator_console_review()`, and
`evaluate_reviewed_profile_candidate()` **inside the trusted local
process**. Those functions still require an independently verified, scoped
PhiID Keycloak access token plus a signed local ANC risk advisory. Reopen
the same database path after restart to reuse approved-but-unexpired
reviews and to retain spent requests and revoked owners.

This does **not** enable any policy HTTP route, real file resource,
user data synchronization, or native OS effect.

## Verification

The unit suite `tests/test_durable_consent.py` exercises:
restart after staged and approved reviews, replay after consumption,
denial and timeout persistence, wrong owner/action/resource binding,
revocation before/after registration, SQL connection contention,
bounded ledger and insecure-file/symlink rejection.

The existing pinned real-Keycloak integration suite additionally runs
`tests/durable_consent_e2e.py`, passing a **real, short-lived Keycloak
access token** through subprocess stdin (not URLs, arguments or logs).
It simulates local operator acceptance/denial, restarts the SQLite
policy object, checks one-use acceptance and persistent owner
revocation, and verifies wrong audience/scope and provider-side
session revocation fail closed.

CI input is **synthetic** and does not prove any live human accepted.
The ANC risk input in this smoke is generated as a synthetic test
envelope, not from production detector telemetry.

## Threat model and production blockers

- **Trust boundary:** File mode and parent directory checks are
  POSIX-only; the parent directory must be private and operator-owned.
  Checks do not defend against hostile same-user processes,
  malicious path substitution races, filesystem tampering, or malware.
- **At-rest privacy:** The SQLite DB includes opaque OIDC issuer/sub,
  exact proposed request metadata, and approval state in *plaintext*.
  This is not suitable for storing real user data without encrypted
  storage, a privacy/deletion policy, secure backups and owner review.
  Do not store tokens, signing keys or email addresses in it.
- **Non-distributed:** Atomicity is valid only against the same local
  database on a supported SQLite filesystem, not across synced copies,
  machines or network mounts. There is no centralized revocation
  service or tamper-evident signature chain.
- **Finite capacity:** Tombstones are intentionally never silently
  evicted. At capacity the operator must start a new independently
  reviewed policy epoch; a safe migration path is not implemented.
- **Time source:** The ledger relies on host wall-clock time and is
  not proof against deliberate system-clock rollback or host takeover.
- **No signed human evidence:** Typed local console acknowledgment
  does not prove user presence, WebAuthn verification, independent
  intent or resistance to malware. R2 PhiID consent receipts and R6
  PocketMesh-specific approvals do not become generic permission.
- **No production enforcement:** No HTTP policy endpoint, resource
  authorization policy for real data, signed permission tokens,
  tenant-aware durable ownership, offline account requirement, live
  ANC trusted producer, or PhiOS effect gate is created.

**Next rung:** a separately controlled, cryptographically verifiable
operator approval service, secure key and revocation lifecycle, and
authoritative owner/tenant storage. Keep PhiOS local approval independent
even after all other checks pass.
