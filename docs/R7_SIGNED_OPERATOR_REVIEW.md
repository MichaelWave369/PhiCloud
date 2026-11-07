# PhiCloud R7: independently verifiable signed operator review (development)

**Status:** Local-only, opt-in Ed25519 signature verification for ONE synthetic
profile-read action. This is not human-presence attestation, a production
consent service, a remote API, a credential issuer, or permission to perform
PhiOS device/file effects.

## Why this rung

R6 introduced a durable SQLite owner/review ledger but accepted a local
boolean acknowledgment from trusted code. R7 adds an **independent public
verification boundary**: an operator-controlled signing process can sign
exactly one staged review, while PhiCloud holds only the **public** verifier
key. Private operator signing keys are NEVER kept in the PhiCloud SQLite
database, committed to GitHub, sent with the approval, or accepted as
arguments to the reference verifier.

### Exact signed body

The strict `phicloud.operator-review.ed25519.v1` body includes:

- Domain-separated purpose `synthetic-profile-read-review`.
- Operator ID and immutable key ID (`kid`).
- Unpredictable pending review ID.
- All seven proposed `EffectRequest` fields: request ID, scope,
  issuer, subject, audience, action, and resource.
- Short issuance/expiry timestamps (maximum **30 seconds**, never later
  than the staged review deadline).
- A fresh 128-bit random nonce.

`phicloud/operator_approval.py` canonicalizes this precise body and
verifies the Ed25519 signature using PyCA `cryptography==50.0.2`.
Unknown body fields, arbitrary keys embedded in a receipt, noncanonical
signature encodings, forged signatures, different subjects/resources,
expired or future-dated receipts, and unsupported purposes are rejected.

The signer must sign the bytes returned by
`canonical_message(body)`. The signature is encoded as unpadded
base64url and added under `signature`. No receipt is accepted without
the previously staged, matching review.

### Durable trusted signer registry

R7 migrates R6 SQLite schema version 1 to version 2 **in place**.
Existing pending/approved/spent review records, owner revocation
tombstones and request IDs are preserved.

`DurableOwnerConsentPolicy.register_operator_key(...)` enrolls a 32-byte
Ed25519 **public** key by operator ID + kid. Enrollment can happen only
through trusted Python code, not an HTTP or browser endpoint. Reusing a
key ID is refused permanently. Rotating keys is explicit:

1. Register a new kid with its separately generated public key.
2. Have the independent operator signer begin signing new reviews with
   that kid.
3. Revoke the old kid by `revoke_operator_key(...)`.

The revocation is persisted transactionally and burns any already
approved, unconsumed reviews linked to the revoked kid. A revoked key
can never be re-enrolled under the same ID. Previously staged tickets
signed by the revoked key also fail. Owner revocation is a separate
deny-first control and remains effective.

### Signed-only consumption

- `approve_signed(receipt, now=...)` validates the receipt against
  the **pinned public key stored in SQLite**, never a key supplied in the
  receipt. The exact pending ticket is atomically approved or spent.
- `evaluate_signed_profile_candidate(...)` does a **fresh actual PhiID
  Keycloak token introspection**, derives a fixed synthetic profile-read
  request, atomically consumes a matching R7 signed approval, and checks
  a separately authenticated ANC risk advisory.
- Consumption **reverifies** the stored signature and active key within
  the same SQLite transaction, which prevents a key revoked after
  initial approval from authorizing a subsequent candidate.
- Old R6 unsigned approvals are **explicitly denied** by R7's
  signed-only entry point. Existing R6 legacy methods are preserved for
  backward compatibility and never silently upgraded to signed status.
- A successful evaluation remains **non-authoritative `CANDIDATE`**.
  Neither signatures nor a safe ANC risk score grant permission to execute.

## Dependencies and setup

The existing R0-R6 reference remains Python standard-library-only.
Only R7 signed verification needs the optional, pinned cryptography
package:

```sh
python -m pip install --only-binary=:all: -r requirements-operator.txt
python -m unittest discover -s tests -v
```

The SQLite path must be an operator-owned private `0700` POSIX
directory, with the database mode `0600`. Native Windows creation
fails closed until Windows ACL semantics are reviewed. No private key
files are supplied, generated or managed by the project itself.

To create a receipt, a separately controlled operator signing process
must read and **show the full request to the person**, authenticate
their intended approval, and sign exactly the canonical message.
The reference module provides verification and canonicalization only.
It does **not** implement that trusted signing ceremony or prove that
the correct human is present.

## CI proof

`tests/test_signed_operator.py` exercises valid signing, exact identity
binding, tampering, wrong private key, replay, expiry, duplicate key ID,
key rotation/revocation, owner revocation, restart, and independent
SQLite connection contention.

The existing pinned disposable Keycloak workflow additionally runs
`tests/signed_operator_e2e.py` using real OAuth login/PKCE and fresh
access-token introspection, then an ephemeral **synthetic signer** for
the local receipt. It checks valid signed-only candidate, invalid
signature, unsigned fallback, signer-key revocation, wrong token
audience/scope, and Keycloak-session revocation.

These tests do NOT prove actual human consent, hardware key protection,
WebAuthn step-up, security of key provisioning, public-host deployment,
or protection against compromised same-user processes. The synthetic
ANC risk fixture is also not a live production detector.

## Security follow-on

Before any real data or device action: independently authenticate the
operator's physical/user presence, bind key enrollment to that user
with protected key management and audited recovery, add tenant-aware
durable permissions and protected storage, encrypt sensitive SQLite
data, review rollback/fork/snapshot attacks and Windows ACLs, define
time-source assurances, and independently implement PhiOS device-side
approval.

**No account or connectivity requirement is added to offline PhiOS.
Authentication, consent, risk advice and actual execution remain
separate boundaries.**
