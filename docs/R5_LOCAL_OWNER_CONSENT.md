# PhiCloud R5: owned synthetic profile and one-use local operator review

**Status:** Tested in-process reference policy with a real-Keycloak identity
smoke. This is not a production consent service, identity provider, persistent
resource ownership database, OS authorizer, or remotely accessible policy API.

## What changes from R4

R4 accepts a separately injected `ConsentEvidence` object from trusted test
code. R5 adds an explicit local state machine, so the test integration no
longer accepts a caller-provided `true` value or externally supplied
`ConsentEvidence` as its independent review.

For this milestone, the **only supported action** is:

- Audience: `phicloud-resource-dev`
- Issuer: `http://127.0.0.1:8080/realms/phiid-dev` (disposable Keycloak)
- Resource: `profile:synthetic-self`
- Action: `profile.read`
- Scope: `pre_service`

The resource is synthetic, not a real stored file or database row. Its owner
is the exact issuer/subject pair derived from a *freshly introspected*
Keycloak access token. A browser cannot choose a different subject, account,
action, audience or resource.

## Trust flow

```text
       Keycloak access token
                |
                v
  LocalTokenIntrospector (existing R3)
    active + exact issuer/audience/scope
                |
                v
       Verified EffectRequest
                |
                v
     LocalOwnerConsentPolicy
     - register exact synthetic owner
     - stage one-use 60-second review
     - show subject / exact action
     - typed "APPROVE <request_id>" on local TTY
     - record max 30-second approval
                |
                v
      Check same owner & same action
      Atomically CONSUME approval
                |
                +--- signed ANC risk evidence
                         |
                         v
     PhiShield DENY / REVIEW / CANDIDATE
           (never executable)
```

**A login alone does not create an approval.** A reviewed action can be
consumed exactly once, even under concurrent requests. The review is
explicitly bound to one principal, request ID, audience, action and
resource. A mismatch, decline, timeout, repeated request ID or full
bounded ledger produces denial, not implicit approval.

The local-only policy can cancel every outstanding review and
approval for one owner. Revocation does not undo completed reads or a
previous candidate; candidates remain non-authoritative regardless.

## Code

- `phicloud/local_consent.py`: bounded local owner registry, staged
  review and one-use approval state machine, owner revocation and optional
  interactive operator-console confirmation.
- `phicloud/shield_identity.py`:
  `stage_verified_profile_review` derives the exact owner from live
  token introspection and stages a review.
  `evaluate_reviewed_profile_candidate` fresh-introspects again,
  atomically consumes the local approval, then passes the verified
  request and signed ANC advisory into existing PhiShield.
- `tests/test_local_consent.py`: denial, wrong owner/resource/scope,
  explicit acknowledgment, replay, expiry, owner revocation, provider
  outage, risk veto and concurrent consumption.
- `tests/owner_consent_e2e.py`: disposable real-Keycloak token plus
  **synthetic** TTY input for CI, with one-use assertion.
- `tests/keycloak_authz_e2e.mjs`: extends the pinned Keycloak job
  to check review denied/approved, scope/audience denial, and
  token revocation before any owner review can proceed.

## How to review locally

The following are examples of the *API*, not permission to access
real resources. Only an operator-trusted Python process should construct
the policy or supply a token introspector:

```python
from datetime import datetime, timezone
from phicloud.local_consent import (
    LocalOwnerConsentPolicy, operator_console_review,
)
from phicloud.shield_identity import stage_verified_profile_review

policy = LocalOwnerConsentPolicy()
# A real, already configured localhost Keycloak introspector and a valid
# audience-specific access token are required. Not shown here to avoid
# suggesting that demo text can authenticate.
#
# ticket = stage_verified_profile_review(
#     access_token, request_id="one-short-lived-request",
#     introspector=trusted_introspector, policy=policy,
# )
# accepted = operator_console_review(
#     policy, ticket, now=datetime.now(timezone.utc)
# )
```

The interactive helper requires a real TTY in normal use and displays the
*exact* principal and effect. It does **not** cryptographically verify
which human is at the terminal. Tests inject `StringIO` to simulate
that acknowledgment; passing CI does not prove genuine human consent.

After approval, the separate evaluation requires fresh Keycloak token
introspection, an intact signed ANC envelope, an exact owner/action
match, and a still-unused review. A clean assessment can produce only
`CANDIDATE`, **never** an executable `ALLOW`.

## Important limitations

- The policy is **in memory**. No persistent/restart-safe revocation,
  encrypted consent database, distributed atomicity, account lifecycle,
  external system consent proof, or independent verifier identity exists.
- A trusted process may instantiate the policy and call its review
  methods. **The Python object does not authenticate its caller.** No
  untrusted API may expose `stage`, `approve`, `register_synthetic_self`,
  or `consume`.
- The built-in operator-console review proves only local typed
  acknowledgment, not device-bound/WebAuthn human presence, resistance
  to local malware or non-repudiation.
- The `profile:synthetic-self` resource has no actual stored object.
  Real storage must obtain ownership and tenant identity from an
  independent authoritative database and use durable revisions before
  extending this policy beyond the fixture resource.
- The HMAC envelope is symmetric and uses disposable keys; persistent
  replay protection, key lifecycle and secure transport remain future work.
- The R4 test fixture API stays for compatibility. R5 intentionally
  uses its **separate reviewed-ledger API** so client-asserted booleans
  cannot be mistaken for review.
- Current Keycloak is **HTTP loopback development only**. No remote
  exposure, real mailbox integration, device-effect control or
  account requirement for offline PhiOS is introduced.

## Reproduce

```sh
python -m unittest discover -s tests -v
```

The preexisting `.github/workflows/keycloak-authz.yml` also runs an
ephemeral real-provider test with approved and declined simulated local
review, no-scope/no-audience denial, and revocation. Private token values
are passed through subprocess stdin, not command arguments or logs.

**Next acceptance gate:** independently verified user/device presence,
durable owner/tenant records, revocation, and resource-specific permission
receipts must exist before any real data or executable action is considered.
