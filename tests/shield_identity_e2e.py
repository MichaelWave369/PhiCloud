"""Disposable CI-only REAL Keycloak -> internal PhiShield R4 handoff.

Reads a test access token from stdin and a confidential-client secret from a
private process environment. Never prints the token, profile or secrets.
Consent is an explicit synthetic fixture here, NOT a live user approval.
No public policy route, OS action, or real data access.
"""
from __future__ import annotations

import os
import secrets
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from phicloud.authz import AuthorizationDenied, AuthorizationUnavailable, LocalTokenIntrospector
from phicloud.shield_identity import (
    PRODUCER,
    evaluate_verified_profile_candidate,
    verified_profile_request,
)
from phicloud.shield_policy import ANC_SCHEMA, ConsentEvidence
from phicloud.shield_transport import LocalReplayCache, sign_local_advisory


def main() -> int:
    if (
        os.environ.get("PHICLOUD_REAL_E2E") != "1"
        or os.environ.get("NODE_ENV") == "production"
    ):
        raise RuntimeError("disposable localhost test opt-in required")
    secret = os.environ.get("PHICLOUD_OAUTH_CLIENT_SECRET", "")
    introspector = LocalTokenIntrospector(secret)
    token = sys.stdin.read(8193).strip()
    if len(token) > 4096 or not token:
        print("DENY")
        return 0

    now = datetime.now(timezone.utc)
    req_id = "phiid-bridge-ci-request"
    try:
        trusted_request = verified_profile_request(
            token, introspector=introspector, request_id=req_id
        )
    except (AuthorizationDenied, AuthorizationUnavailable):
        print("DENY")
        return 0

    # Test-only local signer and synthetic risk data. The production path
    # needs a real, trusted ANC producer and operator consent service.
    risk = {
        "schema": ANC_SCHEMA, "request_id": trusted_request.request_id,
        "scope": trusted_request.scope, "posture": "safe",
        "recommended_action": "allow", "signal_count": 0,
        "weakest_face": "foundation", "weakest_face_score": 0.95,
        "anchor_integrity": 0.9, "observed_at": now.isoformat(),
        "not_after": (now + timedelta(seconds=25)).isoformat(),
        "authority_granted": False,
    }
    key = secrets.token_bytes(32)
    key_id = "disposable-ci"
    envelope = sign_local_advisory(
        risk, request=trusted_request, producer_id=PRODUCER,
        kid=key_id, secret=key, now=now,
    )

    def fixture_consent(request, instant):
        return ConsentEvidence(
            **asdict(request),
            not_after=(instant + timedelta(seconds=10)).isoformat(),
        )

    provider = (
        fixture_consent
        if os.environ.get("PHICLOUD_SHIELD_CONSENT_FIXTURE") == "1"
        else None
    )
    result = evaluate_verified_profile_candidate(
        token, request_id=req_id, introspector=introspector,
        envelope=envelope, trusted_keys={(PRODUCER, key_id): key},
        replay_cache=LocalReplayCache(),
        consent_provider=provider, now=now,
    )
    if result.authoritative:
        raise AssertionError("PhiShield candidate must never be authoritative")
    print(result.disposition)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
