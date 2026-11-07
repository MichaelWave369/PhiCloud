"""Disposable real-Keycloak + simulated Ed25519 operator signature CI smoke.

The cryptographic signature is real, but the signer key is ephemeral in
this test process. No human-presence proof, real resources or OS actions.
Token via stdin; never logs token, subject, secret or private signing key.
"""
from __future__ import annotations

import base64
import os
import secrets
import sys
import tempfile
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phicloud.authz import AuthorizationDenied, AuthorizationUnavailable, LocalTokenIntrospector
from phicloud.durable_consent import DurableOwnerConsentPolicy
from phicloud.local_consent import PolicyDenied
from phicloud.operator_approval import SCHEMA, PURPOSE, canonical_message
from phicloud.shield_identity import (
    PRODUCER, stage_verified_profile_review, evaluate_signed_profile_candidate,
)
from phicloud.shield_policy import ANC_SCHEMA
from phicloud.shield_transport import LocalReplayCache, sign_local_advisory


def run() -> int:
    if os.environ.get("PHICLOUD_REAL_E2E")!="1" or os.environ.get("NODE_ENV")=="production":
        raise RuntimeError("R7 is a disposable localhost integration fixture only")
    mode=os.environ.get("PHICLOUD_R7_REVIEW_FIXTURE")
    if mode not in ("good","wrong-signature","revoke-key","unsigned"):
        raise RuntimeError("invalid R7 test fixture mode")
    token=sys.stdin.read(8193).strip()
    if not 20<=len(token)<=4096:
        print("DENY")
        return 0
    gate=LocalTokenIntrospector(os.environ.get("PHICLOUD_OAUTH_CLIENT_SECRET",""))
    now=datetime.now(timezone.utc)
    request_id="r7-disposable-keycloak"
    with tempfile.TemporaryDirectory(prefix="phicloud-r7-ci-") as folder:
        root=Path(folder)
        root.chmod(0o700)
        path=root/"signed-reviews.sqlite3"
        policy=DurableOwnerConsentPolicy(path)
        try:
            ticket=stage_verified_profile_review(
                token,request_id=request_id,introspector=gate,policy=policy,now=now,
            )
        except (AuthorizationDenied,AuthorizationUnavailable,PolicyDenied,ValueError):
            print("DENY")
            return 0
        if mode=="unsigned":
            policy.approve(
                ticket.review_id,shown_request=ticket.request,
                acknowledged=True,now=now,
            )
        else:
            private=Ed25519PrivateKey.generate()
            public=private.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            policy.register_operator_key(
                operator_id="disposable-ci-operator",kid="ci-key-01",public_key=public,
            )
            t=int(now.timestamp()*1000)
            body={
                "schema":SCHEMA,"purpose":PURPOSE,
                "operator_id":"disposable-ci-operator","kid":"ci-key-01",
                "review_id":ticket.review_id,"request":asdict(ticket.request),
                "issued_at_ms":t,"expires_at_ms":t+20_000,
                "nonce":secrets.token_hex(16),
            }
            receipt={
                **body,
                "signature":base64.urlsafe_b64encode(
                    private.sign(canonical_message(body))
                ).decode("ascii").rstrip("="),
            }
            if mode=="wrong-signature":
                receipt["signature"]="A"*86
            signed=policy.approve_signed(receipt,now=now)
            if signed != (mode!="wrong-signature"):
                raise AssertionError("R7 signature verifier accepted incorrect receipt")
            if mode=="revoke-key":
                policy.revoke_operator_key(
                    operator_id="disposable-ci-operator",kid="ci-key-01"
                )
        # New policy handle represents a fresh process/connection.
        reopened=DurableOwnerConsentPolicy(path)
        req=ticket.request
        advisory={
            "schema":ANC_SCHEMA,"request_id":req.request_id,
            "scope":req.scope,"posture":"safe","recommended_action":"allow",
            "signal_count":0,"weakest_face":"foundation",
            "weakest_face_score":0.9,"anchor_integrity":0.9,
            "observed_at":now.isoformat(),
            "not_after":(now+timedelta(seconds=25)).isoformat(),
            "authority_granted":False,
        }
        key=secrets.token_bytes(32)
        envelope=sign_local_advisory(
            advisory,request=req,producer_id=PRODUCER,kid="r7-anc-ci",
            secret=key,now=now,
        )
        options={
            "request_id":request_id,"introspector":gate,"policy":reopened,
            "envelope":envelope,
            "trusted_keys":{(PRODUCER,"r7-anc-ci"):key},
            "replay_cache":LocalReplayCache(),"now":now,
        }
        decision=evaluate_signed_profile_candidate(token,**options)
        if decision.authoritative:
            raise AssertionError("Ed25519 signature became execution authority")
        if decision.disposition=="CANDIDATE":
            if evaluate_signed_profile_candidate(token,**options).disposition!="DENY":
                raise AssertionError("signed approval replay accepted")
        if mode=="revoke-key":
            try:
                reopened.register_operator_key(
                    operator_id="disposable-ci-operator",kid="ci-key-01",public_key=public
                )
            except PolicyDenied:
                pass
            else:
                raise AssertionError("revoked public key ID could be reused")
        print(decision.disposition)
    return 0


if __name__=="__main__":
    raise SystemExit(run())
