"""Disposable R5 Keycloak -> one-use local operator-review smoke fixture.

Real token introspection and revocation, SIMULATED terminal confirmation.
No production operator authentication, durable permission DB or OS effects.
Bearer token arrives on stdin; no sensitive details are printed or logged.
"""
from __future__ import annotations

import os
import secrets
import sys
from datetime import datetime, timedelta, timezone
from io import StringIO

from phicloud.authz import (
    AuthorizationDenied, AuthorizationUnavailable, LocalTokenIntrospector,
)
from phicloud.local_consent import (
    LocalOwnerConsentPolicy, PolicyDenied, operator_console_review,
)
from phicloud.shield_identity import (
    PRODUCER, evaluate_reviewed_profile_candidate, stage_verified_profile_review,
)
from phicloud.shield_policy import ANC_SCHEMA
from phicloud.shield_transport import LocalReplayCache, sign_local_advisory


def main() -> int:
    if (
        os.environ.get("PHICLOUD_REAL_E2E") != "1"
        or os.environ.get("NODE_ENV") == "production"
    ):
        raise RuntimeError("isolated Keycloak fixture only")
    secret = os.environ.get("PHICLOUD_OAUTH_CLIENT_SECRET", "")
    gate = LocalTokenIntrospector(secret)
    token = sys.stdin.read(8193).strip()
    if not 20 <= len(token) <= 4096:
        print("DENY")
        return 0
    mode = os.environ.get("PHICLOUD_R5_REVIEW_FIXTURE")
    if mode not in {"approve", "deny"}:
        raise RuntimeError("R5 simulated review mode not explicitly configured")

    now = datetime.now(timezone.utc)
    policy = LocalOwnerConsentPolicy()
    request_id = "r5-disposable-oidc-profile"
    try:
        ticket = stage_verified_profile_review(
            token, request_id=request_id,
            introspector=gate, policy=policy, now=now,
        )
    except (AuthorizationDenied, AuthorizationUnavailable, PolicyDenied, ValueError):
        print("DENY")
        return 0

    # CI simulates operator input, NOT actual human consent.
    answer = ("APPROVE " + request_id + "\n") if mode == "approve" else "NO\n"
    operator_console_review(
        policy, ticket, now=now,
        input_stream=StringIO(answer), output_stream=StringIO(),
    )
    risk = {
        "schema": ANC_SCHEMA, "request_id": ticket.request.request_id,
        "scope": ticket.request.scope, "posture": "safe",
        "recommended_action": "allow", "signal_count": 0,
        "weakest_face": "foundation", "weakest_face_score": 0.9,
        "anchor_integrity": 0.9, "observed_at": now.isoformat(),
        "not_after": (now + timedelta(seconds=20)).isoformat(),
        "authority_granted": False,
    }
    key = secrets.token_bytes(32)
    kid = "r5-ci"
    envelope = sign_local_advisory(
        risk, request=ticket.request, producer_id=PRODUCER,
        kid=kid, secret=key, now=now,
    )
    kwargs = {
        "request_id": request_id, "introspector": gate, "policy": policy,
        "envelope": envelope, "trusted_keys": {(PRODUCER, kid): key},
        "replay_cache": LocalReplayCache(), "now": now,
    }
    verdict = evaluate_reviewed_profile_candidate(token, **kwargs)
    if verdict.authoritative:
        raise AssertionError("inert candidate gained authority")
    if verdict.disposition == "CANDIDATE":
        # Approval cannot be replayed, even with a still-valid MAC.
        duplicate = evaluate_reviewed_profile_candidate(
            token, **kwargs,
        )
        if duplicate.disposition != "DENY":
            raise AssertionError("approval replay unexpectedly accepted")
    print(verdict.disposition)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
