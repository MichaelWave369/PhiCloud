# PhiShield R1: authenticated **local** ANC advisory envelope

**Status:** Opt-in in-process reference implementation using Python's standard
`hmac` and `hashlib` primitives, with bounded JSON, freshness and a
thread-safe single-process nonce cache.

This does **not** deploy an API, enroll trusted devices, validate PhiID OIDC
tokens, implement network authentication or authorize PhiOS actions.

## Problem solved

The original [ANC advisory R1](https://github.com/MichaelWave369/ANC/blob/main/docs/ANC_PHISHIELD_R1_CONTRACT.md)
has strict structure and expiry but is *unsigned*. Someone could submit a
fabricated `safe` advisory through an untrusted boundary.

The new `phicloud/shield_transport.py` defines a second envelope around a
valid ANC advisory, signed with HMAC-SHA256 using an explicit, server-owned
shared secret provisioned by a **trusted** local operator. This adds
message integrity and key-possession authentication at this local
prototype boundary, *not* end-user identity or a replacement for TLS.

```text
trusted local ANC integration
    -> ANC detector / scoring
    -> ANC R1 advisory {request_id, scope, risk}
    -> HMAC envelope {producer_id, kid, audience, nonce, times, advisory}
    -> PhiCloud verifies MAC, freshness, binding and single-use nonce
    -> separately checks trusted authority evidence + operator consent
    -> DENY / REVIEW / CANDIDATE only
    -> no executable permission or side effect
```

## Invariants

- Do not accept a `producer_id` from a remote client as a trusted identity.
  The verifier receives its expected producer name from independent
  trusted configuration.
- A verified MAC establishes that the sender knew the **shared** key,
  not that a particular human signed in or that the ANC risk model is correct.
  Neither producer nor consumer should expose the key to browsers.
- A verified MAC never makes `authority_granted=true` valid, elevates
  coherence to a capability, grants consent, or authorizes an OS effect.
- The signed canonical JSON binds producer, key ID, audience, request ID,
  scope, 128-bit random nonce, issuance/expiry and the entire ANC advisory.
  Extra/missing fields, invalid keys, expired envelopes and mismatched
  fields are denied.
- The one-use nonce cache is guarded by a lock and has finite capacity.
  A full cache **denies** new requests, rather than silently evicting
  unexpired nonces and allowing replay.
- JSON parsing rejects duplicate keys, non-finite values and oversize
  bodies. The caller must use `parse_envelope_json` at a byte-oriented
  boundary, never a generic permissive decoder that silently overwrites
  duplicate keys.
- Signing is optional for existing tests and offline simulations. This
  change adds no HTTP routes to PhiCloud's read-only registry and creates
  no token or account dependency for PhiOS.

## Small local-only example

```python
import secrets
from datetime import datetime, timezone
from dataclasses import asdict

from phicloud.shield_policy import (
    EffectRequest, AuthorityEvidence, ConsentEvidence,
)
from phicloud.shield_transport import (
    LocalReplayCache, sign_local_advisory, evaluate_authenticated_candidate,
)

now = datetime.now(timezone.utc)
request = EffectRequest(
    request_id="example-369", scope="pre_service",
    subject_issuer="https://phiid.example.invalid",
    subject_id="test-only", audience="phicloud-local",
    action="service.execute", resource="service:test",
)

# A hypothetical trusted signer creates an ANC advisory for this request.
# In real code this MUST come from local ANC's detectors, not client input.
# See tests/anc_contract_smoke.py for the pinned end-to-end demonstration.
#
# Generate keys in a trusted process. Never store or display them in
# README files, browser bundles, public repos, or application logs.
local_key = secrets.token_bytes(32)
trusted_keys = {("anc-local", "key1"): local_key}
replay_cache = LocalReplayCache()

# The verifier must obtain verified, request-bound authority and consent
# from separate trusted systems, never from an ANC score or client JSON.
# Both are omitted here, so no side effect can be authorized.
```

For complete runnable examples see `tests/test_shield_transport.py` and
`tests/anc_contract_smoke.py`. The CI smoke checks out ANC at a pinned
commit and creates a real ANC advisory before signing it.

## Critical limitations before actual service deployment

1. **Trusted key distribution is missing.** Current HMAC keys are injected
   in-process for testing. Production would require secure storage,
   issuance, rotation, revocation, compartmentalization, and recovery.
   HMAC is symmetric; either party holding the key can forge a sender.
2. **Replay storage is ephemeral.** Nonces disappear after restart and
   are not coordinated between instances. Use an atomic, durable or
   appropriately shared replay mechanism before any remote boundary.
3. **No transport is deployed.** There is no TLS/mTLS/Unix-socket
   credential verification, no remote peer authentication, no API policy
   endpoint, and no cross-process trust establishment yet.
4. **No independently verified authorization engine exists here.**
   The R0 authority/consent evidence classes are test fixtures, not
   signed grants. Future PhiID integration must validate an audited
   OIDC issuer/signature/audience/scopes and separate local PhiOS approval.
5. **Not an audited security control.** The pattern detectors can miss
   attacks or flag harmless text. This envelope protects the message
   within its declared test assumptions, not the model's reasoning.

The safe default remains **deny on missing, invalid or uncertain identity/
provenance**. Production enforcement, governance and audits need separate work.
