# PhiCloud R12: five-minute unsigned preview, independent late signing

**Status:** Operator-local, disabled-by-default Linux development prototype,
restricted to **one synthetic `profile.read` on `profile:synthetic-self`**.
No production signing server, public API, real resource access, OS effect, or
PhiOS account requirement is introduced.

## Why R12

In R11, the operator needed a pre-existing R7 signed receipt with an absolute
30-second maximum lifetime *before* opening the browser. That was too short
for thoughtful review, and simply making signatures valid five minutes would
weaken the replay/expiry boundary.

R12 separates **time to understand** from **time a signed review can be used**:

1. A **trusted caller** freshly verifies a real short-lived PhiID token,
   derives the exact synthetic owner and action, and calls
   `stage_verified_operator_preview(...)`. Its one-use review ticket
   remains `pending` for **up to 300 seconds**, unsigned and non-executable.
   The older R6 `stage()` remains at **60 seconds**.
2. A local operator, with an already enrolled R7 Ed25519 signer and R10
   WebAuthn credential, starts a standalone localhost R12 review process,
   supplying only a private review-ID file and *path* to an independently
   controlled Unix-domain signing service. Neither signing key nor PhiID
   token is transferred to the browser.
3. The same protected R11 localhost page displays every exact request field
   after the one-use terminal pairing code. In R12 the text labels the
   fields explicitly **unsigned until operator confirmation** and displays
   the preview expiry.
4. When the operator explicitly confirms, the server **rechecks current
   owner/signer/credential trust**, constructs a canonical R7 receipt
   binding the exact request, nonce, review ID, operator ID and key ID,
   with an expiry of **at most 30 seconds**, and asks the separately
   administered signer over the private Unix socket to sign *those bytes*.
5. Before any WebAuthn challenge, PhiCloud verifies the returned Ed25519
   signature against the key already enrolled in the durable local
   operator registry. Missing service, bad peer, invalid signature,
   revoked key, expired review or malformed reply denies and burns the
   review, with **no fallback to local signing**.
6. The existing R9 WebAuthn verifier issues a separate receipt-bound
   challenge requiring an already enrolled credential, fixed
   `http://localhost:8769` origin, signature, user presence, user
   verification and monotonic counter where supported. It records
   the signed+UV review exactly once. **No access or OS effect occurs.**
7. Any subsequent PhiShield **CANDIDATE** still needs a fresh live PhiID
   token, current signer/credential trust, the unspent exact review
   and an independently authenticated ANC risk advisory. CANDIDATE
   is NEVER permission for PhiOS to perform an effect.

A preview may last five minutes, **not** its signature. Signing at the
last moment preserves the existing 30-second R7 receipt limit and one-use
R9 consumption behavior.

## Independent signer protocol

R12 deliberately includes a **verifying client**, not a signing daemon or
private-key loader. A production-grade signer needs its own independently
authenticated operator interaction, key-protection service and decision
policy, outside this repository.

The Linux client uses a non-symlink, operator-owned Unix socket inside a
private 0700 directory with mode 0600. It validates SO_PEERCRED for the
same OS UID and limits the request/reply size and timeout. A malicious
process with the same UID can still impersonate a signer or alter the
private SQLite database. Same-UID Unix socket control is **not** proof
of human presence or HSM custody. An independently protected signer
must itself refuse requests not covered by its own trusted policy.

A single JSON line is sent to the Unix socket:

```json
{"schema":"phicloud.detached-sign.v1","operator_id":"local-fixture-operator","kid":"registered-kid","message":"BASE64URL_DOMAIN_SEPARATED_R7_CANONICAL_BYTES"}
```

The independent signer must interpret and verify the full
domain-separated R7 canonical body, including the seven request fields,
operator, key ID, 30-second expiry, purpose and nonce. Only **after its
own approval policy** may it answer one line:

```json
{"signature":"UNPADDED_BASE64URL_64_BYTE_ED25519_SIGNATURE"}
```

The client never accepts a public key in the reply. PhiCloud independently
reverifies the signature with the pinned R7 registry key, then R9
does the same during atomic consumption. **Never deploy a signer that
blindly signs any socket request.**

## Local development

The private database must already contain the trusted operator signing
key, previously enrolled WebAuthn credential, and one *pending*
synthetic review. A trusted backend that has just done real PhiID
introspection can stage the longer preview using:

```python
from phicloud.shield_identity import stage_verified_operator_preview

ticket = stage_verified_operator_preview(
    valid_short_lived_access_token,
    request_id=unique_one_use_request_id,
    introspector=trusted_local_introspector,
    policy=private_operator_policy,
)
```

The variables above are inputs from a separately trusted process, not
environment-variable defaults or browser claims. Write only
`{"review_id":ticket.review_id}` to a 0600 private JSON file in a
separate trusted local setup step. The reviewer must not construct
subjects from browser payloads; the stage helper obtains them from
fresh confidential-client Keycloak introspection.

With a **separately running, policy-checking** signer already available
on a private Unix socket:

```sh
python -m pip install --only-binary=:all: -r requirements-operator.txt
export PHICLOUD_DEFERRED_REVIEW_DEV=1
python -m phicloud.deferred_review \
  --db "$HOME/.local/share/phicloud-r6/reviews.sqlite3" \
  --review-file "$HOME/.local/share/phicloud-r6/pending-review.json" \
  --operator existing-registered-operator \
  --kid existing-registered-ed25519-key-id \
  --signer-socket "$HOME/.local/share/phicloud-signer/private.sock"
```

All example identifiers are placeholders. The CLI refuses non-interactive
use, production flags, missing/non-private database and selector, or
unsafe/missing Unix socket. The one-shot browser UI reuses the
existing `http://localhost:8769` origin; stop R0, R10 or R11
listeners on that port first. Linux/WSL only, with no native Windows
ACL support.

**There is no general signer bootstrap or production signer server in
this PR.** To test with a signer, use the disposable synthetic test
fixture. Never copy the disposable test private key into a real setup.

## Tests and remaining limitations

```sh
python -m unittest discover -s tests -v
node --check phicloud/static/operator_deferred.js
```

`tests/test_deferred_review.py` exercises expiry of five-minute
unsigned preview versus max-30-second signed evidence, one-time
terminal pairing, late valid signature, signer failure and wrong key,
SO_PEERCRED-backed Unix socket transport, stale/expired/revoked
signer or credential, denial, UV-flag validation, WebAuthn replay,
and no legacy approval downgrade. Its mock signer key exists
**only inside disposable unit tests**.

This does not prove a real authenticated human reviewed an action.
It does not implement a tamper-evident external audit witness, protected
signer key custody, rollback-proof/recovery-safe approval ledger,
distributed policy, real resource access, production browser
compatibility or PhiOS effect authorization.

The next engineering rung is an independently authenticated signer
with explicit operator presence and a separately protected,
durable audit witness. Keep actual local PhiOS effect approval
separate, and preserve standalone offline PhiOS operation.
