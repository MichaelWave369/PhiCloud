"""Real disposable Keycloak token, simulated review, durable SQLite R6 ledger.

CI-only. Bearer token on stdin, confidential Keycloak secret in process env.
No live human consent, real data or OS effects. No token/subject logged.
"""
from __future__ import annotations

import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

from phicloud.authz import AuthorizationDenied, AuthorizationUnavailable, LocalTokenIntrospector
from phicloud.durable_consent import DurableOwnerConsentPolicy
from phicloud.local_consent import PolicyDenied, operator_console_review
from phicloud.shield_identity import (
    PRODUCER, stage_verified_profile_review, evaluate_reviewed_profile_candidate,
)
from phicloud.shield_policy import ANC_SCHEMA
from phicloud.shield_transport import LocalReplayCache, sign_local_advisory


def run() -> int:
    if os.environ.get("PHICLOUD_REAL_E2E") != "1" or os.environ.get("NODE_ENV") == "production":
        raise RuntimeError("disposable localhost-only test required")
    mode = os.environ.get("PHICLOUD_R6_REVIEW_FIXTURE")
    if mode not in {"approve", "deny", "revoke"}:
        raise RuntimeError("unknown simulated review mode")
    gate = LocalTokenIntrospector(os.environ.get("PHICLOUD_OAUTH_CLIENT_SECRET", ""))
    token = sys.stdin.read(8193).strip()
    if not 20 <= len(token) <= 4096:
        print("DENY")
        return 0
    now = datetime.now(timezone.utc)
    request_id = "r6-keycloak-durable"
    with tempfile.TemporaryDirectory(prefix="phicloud-r6-ci-") as folder:
        root = Path(folder)
        root.chmod(0o700)
        db = root / "operator-consent.sqlite3"
        policy = DurableOwnerConsentPolicy(db)
        try:
            ticket = stage_verified_profile_review(
                token, request_id=request_id, introspector=gate,
                policy=policy, now=now,
            )
        except (AuthorizationDenied, AuthorizationUnavailable, PolicyDenied, ValueError):
            print("DENY")
            return 0
        text = f"APPROVE {request_id}\n" if mode != "deny" else "DECLINE\n"
        operator_console_review(
            policy, ticket, now=now,
            input_stream=StringIO(text), output_stream=StringIO(),
        )
        if mode == "revoke":
            policy.revoke_owner(
                issuer=ticket.request.subject_issuer,
                sub=ticket.request.subject_id,
            )
        # Open a completely fresh policy handle, simulating process restart.
        restarted = DurableOwnerConsentPolicy(db)
        req = ticket.request
        risk = {
            "schema": ANC_SCHEMA, "request_id": req.request_id,
            "scope": req.scope, "posture": "safe",
            "recommended_action": "allow", "signal_count": 0,
            "weakest_face": "foundation", "weakest_face_score": 0.9,
            "anchor_integrity": 0.9, "observed_at": now.isoformat(),
            "not_after": (now + timedelta(seconds=20)).isoformat(),
            "authority_granted": False,
        }
        key = secrets.token_bytes(32)
        envelope = sign_local_advisory(
            risk, request=req, producer_id=PRODUCER,
            kid="r6-ci", secret=key, now=now,
        )
        options = dict(
            request_id=request_id, introspector=gate,
            policy=restarted, envelope=envelope,
            trusted_keys={(PRODUCER, "r6-ci"): key},
            replay_cache=LocalReplayCache(), now=now,
        )
        verdict = evaluate_reviewed_profile_candidate(token, **options)
        if verdict.authoritative:
            raise AssertionError("R6 candidate must not grant execution")
        if verdict.disposition == "CANDIDATE":
            duplicate = evaluate_reviewed_profile_candidate(token, **options)
            if duplicate.disposition != "DENY":
                raise AssertionError("persisted approval replay accepted")
        if mode == "revoke":
            try:
                restarted.register_synthetic_self(req)
            except PolicyDenied:
                pass
            else:
                raise AssertionError("revoked owner was reenabled on restart")
        print(verdict.disposition)
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
