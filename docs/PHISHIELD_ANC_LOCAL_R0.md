# PhiShield R0: local in-process ANC risk consumer

**Status:** Experimental Python standard-library module and tests in PhiCloud.
**Not a PhiShield deployment, privileged enforcement service, verified OIDC
integration, anti-malware product, or remote authentication API.**

The planned PhiShield service now has a *reference* policy consumer under
`phicloud/shield_policy.py`. It accepts ANC's versioned **R1 risk advisory**
plus two independent, request-bound evidence objects, checks their mutual
consistency and expiry, and returns a non-authoritative disposition.

## Trust boundaries

```text
trusted PhiCloud service action context
  |-- verified PhiID principal (FUTURE: vetted OIDC verifier)
  |-- scoped capability (FUTURE: resource policy / revocation)
  |-- operator consent receipt (FUTURE: independently validated)
  |-- ANC local risk advisory (EXISTING: advisory-only, unsigned)
  |          |
  v          v
PhiCloud PhiShield R0 (pure library, no HTTP endpoints)
          |
          +--> DENY      = reject candidate
          +--> REVIEW    = never execute automatically
          +--> CANDIDATE = proceed to independent policy / enforcement
                              (NOT an authorization)
```

**No disposition permits direct side effects.** PhiOS retains authority over
local files, OS tools, code execution and device activity. The server at
`127.0.0.1:8769` remains a read-only *registry* and does not expose policy
requests. No code here loads real accounts, signing keys, secrets, or mailboxes.

## What it actually validates

The in-process policy checks:

- Exact request identity and binding across `request_id`, `scope`,
  `subject_issuer`, `subject_id`, `audience`, `action` and `resource`.
- Independent, **externally obtained** authorization and consent evidence
  objects, each bound to that exact request with valid expiration.
- The exact ANC `phi369.anc.phishield.advisory.v1` field set and version:
  matching request ID/scope, timezone-aware freshness, valid posture/action,
  bounded finite risk metrics, `authority_granted=false`, no extra fields.
- Hostile/quarantined ANC posture or blocking recommendation triggers `DENY`.
  Uncertain signals/posture trigger `REVIEW`; clean signals can produce
  only `CANDIDATE`, never `ALLOW`.

**Crucial limit:** `AuthorityEvidence` and `ConsentEvidence` dataclasses
are not signed credentials. A caller could fabricate them. They are usable
only in a trusted in-process test/integration, populated by a separate
verified authority/consent engine. **Never parse these types from user JSON,
a browser, unverified logs, or a remote client's assertion of permission.**
Likewise, ANC's current R1 advisory is unsigned: parsing validates structure,
not origin. For remote operation, producer authentication, verified tokens,
audience restrictions, nonce/replay protection, revocation and concrete
enforcement must be supplied by independently reviewed components.

## One-process demonstration

```python
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from phicloud.shield_policy import (
    EffectRequest, AuthorityEvidence, ConsentEvidence, evaluate_candidate
)

now = datetime.now(timezone.utc)
request = EffectRequest(
    request_id="local-example-1",
    scope="pre_service",
    subject_issuer="https://phiid.example.invalid/realms/phi",
    subject_id="example-subject",
    audience="phicloud-example",
    action="service.execute",
    resource="service:echo",
)
# Only for a *synthetic demonstration*: production evidence MUST come from
# an independently verified authority and consent provider.
expires = (now + timedelta(seconds=60)).isoformat()
authority = AuthorityEvidence(**asdict(request), not_after=expires)
consent = ConsentEvidence(**asdict(request), not_after=expires)

# Caller must supply an ANC R1 advisory generated for this same request.
# No advisory means the policy fails closed:
result = evaluate_candidate(
    request, authority=authority, consent=consent, anc_advisory=None, now=now
)
assert result.disposition == "DENY"
assert result.authoritative is False
```

## CI verification

1. `python -m unittest discover -s tests -v` tests denial,
   binding, expiry, forged `authority_granted`, unknown schema,
   malformed evidence, high risk veto, and no credential leakage.
2. A separate CI job checks out **ANC at an exact pinned commit**
   and generates actual R1 advisory payloads with ANC's detector/scoring
   pipeline. They are JSON serialized and evaluated by PhiCloud's
   independent reference consumer, exercising clean, injected and
   no-consent paths. This does **not** make ANC a Python runtime
   dependency or vendor its source into PhiCloud.

The dependency commit is pinned in `.github/workflows/ci.yml`; update it
deliberately after ANC API changes, rather than silently tracking `main`.

## Next engineering steps

1. A real trust root: use PhiID's independently validated OpenID Connect
   identity; use verified resource-specific capabilities and operator consent
   evidence from trusted internal components. Never use a score as identity.
2. Define an authenticated, local-only PhiShield IPC service with request
   nonces and replay tracking. No unauthenticated HTTP policy endpoint.
3. Implement deny-by-default service enforcement in a separately reviewed
   policy engine, with deliberately constrained capabilities and explicit
   PhiOS authority for any OS effects.
4. Add incident receipts, revocation, replay, negative-path service smoke,
   and operator visibility. Test the failure cases before remote exposure.

ANC tokens, staking, and a public ledger play no part in identity or access.
PhiOS remains independently functional offline.
