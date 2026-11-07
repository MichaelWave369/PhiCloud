# PhiCloud R9: WebAuthn user-verification step-up for signed operator review

**Status:** local-only, opt-in **reference** relying-party verification for
the single synthetic `profile.read` action. No browser workflow, actual
passkey registration, real user account/credential enrollment, hosted
service, real resource access, or PhiOS execution permission is provided.

R7 verifies an operator's signed request but cannot distinguish a real
human-present decision from an unattended process holding a signer key.
R9 adds a separately verified WebAuthn authentication assertion with
`userVerification: "required"`, exact purpose binding, persistent
one-use challenge, enrolled credential key, and current revocation status.

## Separate security checks

```text
Local trusted operator sets one R7 signed review
                     |
                     v
R7 Ed25519 signature over exact action and subject
                     |
                     v
Trusted local RP issues random challenge for that *receipt*
                     |
                     v
WebAuthn authenticator signs challenge with UP + UV flags
                     |
                     v
py_webauthn verifies:
  - challenge, assertion signature, registered public key
  - fixed RP ID: localhost
  - fixed origin: http://localhost:8769
  - user present AND user verified
  - authenticator counter rollback when counter is nonzero
                     |
                     v
One atomic SQLite transition:
  - spend pending challenge
  - update authenticator counter
  - record signed and UV-verified approval
                     |
                     v
Fresh Keycloak access-token introspection
  + current signer/credential owner and revocation
  + one-use approval consumption
  + authenticated ANC advisory
                     |
                     v
DENY / REVIEW / CANDIDATE (never executable)
```

R9 deliberately adds a **separate** `evaluate_user_verified_profile_candidate`
entry point. R6 local confirmation and R7 signed-only approvals cannot
enter it without an actual verified R9 assertion. Existing R3-R8
interfaces and default read-only service registry remain unchanged.

## What is implemented

- `phicloud/webauthn_presence.py`: a strict adapter around the maintained
  `webauthn==3.0.1` library, not a hand-written WebAuthn signature
  parser. Challenges are domain-separated and bound to the *complete*
  R7 canonical signed receipt, including its signer signature.
- `DurableOwnerConsentPolicy` schema version **3**, upgrading R6 v1 and
  R7 v2 in place. It adds a trusted-operator credential registry,
  one-time challenge, receipt digest, UV status, and signed counter.
  Previously stored unsigned and signed-only approvals are never
  relabeled as user-verified.
- `register_operator_credential`: stores an **already independently
  registered and validated** credential's ID and COSE public key.
  This method requires trusted local code and an active enrolled
  R7 signing operator. It is **not** a WebAuthn registration ceremony
  and cannot be called by remote clients.
- `begin_operator_stepup`: verifies the R7 signed receipt, checks the
  pending ticket, registered operator credential and fixed RP/origin,
  and issues one unpredictable 32-byte challenge linked to that one
  receipt. Repeat issuance is denied.
- `approve_signed_with_stepup`: verifies the WebAuthn assertion
  against the pinned credential public key, fixed RP/origin,
  user presence, user verification and monotonic sign counter.
  Invalid assertions spend the pending review; valid assertions
  persist a short-lived user-verified approval.
- `revoke_operator_credential`: durable credential tombstone
  invalidating pending and approved but unspent reviews. Separately
  revoking R7's signer key or the profile owner also denies R9.
- Consumption requires **both** the R7 signature and unrevoked R9
  credential proof, checks remaining expiry in the same SQLite
  transaction, and cannot be replayed by another process.

## Fixed local configuration

- RP ID: `localhost`
- Expected origin: `http://localhost:8769`
- Purpose: R7's `synthetic-profile-read-review`
- Challenge: unpredictable 32 bytes, at most 30 seconds and never
  beyond the R7 signed review deadline.
- Only action/resource: `profile.read` on `profile:synthetic-self`.
- Database: private POSIX `0700` operator-owned directory, mode `0600`.
  Native Windows continues to fail closed until reviewed ACL handling
  is implemented.

No HTTP endpoint serving the WebAuthn API has been added. Future browser
work must use a trusted localhost RP and a real registration ceremony,
display the **full exact request** to the operator, enforce
`userVerification: "required"`, and transmit assertion data through an
authenticated operator session. Client-provided credential public keys
must **never** be trusted during sign-in or approval.

## Verification

```sh
python -m pip install --only-binary=:all: -r requirements-operator.txt
python -m unittest discover -s tests -v
```

Unit tests use a **synthetic** ES256 authenticator with correct WebAuthn
signature syntax, separate from the R7 Ed25519 signing key. Tests assert
valid acceptance, missing UV/UP, wrong RP/origin, wrong private key,
wrong credential ID, challenge substitution, duplicate challenge,
sign-counter reuse, one-use behavior across SQLite handles, expiry,
key/credential/owner revocation, and signed-only fallback rejection.

The existing pinned real-Keycloak CI adds R9 checks for actual short-lived
OAuth access tokens and upstream session revocation. The simulated
WebAuthn authenticator in CI sets UV bits in a **synthetic fixture**.
This verifies the RP's acceptance logic, **not a real user physically
authenticating with a hardware passkey or phone**.

## Production blockers

- No real registration flow, authenticated operator enrollment,
  trusted credential provisioning, passkey UX, hardware attestation,
  secure browser-to-service channel, account-to-operator linking,
  or recovery policy.
- Authenticator UV is cryptographic evidence reported by an enrolled
  authenticator, not a guarantee of how or which human approved an
  action. Enrollment and the human-facing request display are
  essential prerequisites.
- Counter-zero/multi-device passkeys cannot reliably prove
  nonclonability. Single-device counters are checked where supported.
- No durable tamper-evident audit, encrypted SQLite, backup-aware
  revocation across restores, secure time source, Windows ACL support,
  remote multi-device synchronization, or device-side PhiOS enforcement.
- A compromised trusted host/process can alter local SQLite and
  provisioning calls. These prototypes do not establish a production
  cross-process security boundary.

`CANDIDATE` remains advisory and non-executable, and PhiOS stays
usable offline without a PhiID account.
