"""Real disposable Keycloak principal + SYNTHETIC UV WebAuthn authenticator.

No real authenticator enrollment, credential delivery, human UX or OS effect.
Bearer access token is read on stdin, secrets and subject never logged.
"""
from __future__ import annotations

import os
import secrets
import sys
import tempfile
from datetime import datetime,timedelta,timezone
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519

from phicloud.authz import LocalTokenIntrospector,AuthorizationDenied,AuthorizationUnavailable
from phicloud.durable_consent import DurableOwnerConsentPolicy
from phicloud.local_consent import PolicyDenied
from phicloud.shield_identity import (
    PRODUCER,stage_verified_profile_review,evaluate_user_verified_profile_candidate,
)
from phicloud.shield_transport import LocalReplayCache,sign_local_advisory
from phicloud.shield_policy import ANC_SCHEMA
from webauthn_fixture import SyntheticAuthenticator,ed25519_public_bytes,sign_review


def main() -> int:
    if os.environ.get("PHICLOUD_REAL_E2E")!="1" or os.environ.get("NODE_ENV")=="production":
        raise RuntimeError("disposable localhost only")
    mode=os.environ.get("PHICLOUD_R9_WEBAUTHN_MODE")
    if mode not in ("uv","no-uv","revoke-credential","revoke-signer","unsigned"):
        raise RuntimeError("unrecognized synthetic WebAuthn mode")
    token=sys.stdin.read(8193).strip()
    if not 20<=len(token)<=4096:
        print("DENY")
        return 0
    gate=LocalTokenIntrospector(os.environ.get("PHICLOUD_OAUTH_CLIENT_SECRET",""))
    now=datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix="phicloud-r9-ci-") as directory:
        root=Path(directory)
        root.chmod(0o700)
        db=root/"webauthn-stepup.sqlite3"
        policy=DurableOwnerConsentPolicy(db)
        signer=ed25519.Ed25519PrivateKey.generate()
        authenticator=SyntheticAuthenticator()
        try:
            ticket=stage_verified_profile_review(
                token,request_id="r9-test-webauthn",
                introspector=gate,policy=policy,now=now,
            )
        except (AuthorizationDenied,AuthorizationUnavailable,PolicyDenied,ValueError):
            print("DENY")
            return 0
        policy.register_operator_key(
            operator_id="ci-operator",kid="ci-signing-key",
            public_key=ed25519_public_bytes(signer),
        )
        policy.register_operator_credential(
            operator_id="ci-operator",
            credential_id=authenticator.credential_id,
            public_key=authenticator.cose_public,
        )
        receipt=sign_review(
            ticket,signer,now=now,
            operator="ci-operator",kid="ci-signing-key",
        )
        if mode=="unsigned":
            policy.approve_signed(receipt,now=now)
        else:
            challenge=policy.begin_operator_stepup(
                receipt,credential_id=authenticator.credential_id,now=now
            )
            assertion=authenticator.assertion(
                challenge,verified=(mode!="no-uv"),
            )
            accepted=policy.approve_signed_with_stepup(
                receipt,assertion,now=now,
            )
            if accepted != (mode!="no-uv"):
                raise AssertionError("R9 UV verifier accepted wrong assertion state")
        if mode=="revoke-credential":
            policy.revoke_operator_credential(
                credential_id=authenticator.credential_id
            )
        elif mode=="revoke-signer":
            policy.revoke_operator_key(
                operator_id="ci-operator",kid="ci-signing-key"
            )
        reopened=DurableOwnerConsentPolicy(db)
        req=ticket.request
        advisory={
            "schema":ANC_SCHEMA,"request_id":req.request_id,"scope":req.scope,
            "posture":"safe","recommended_action":"allow","signal_count":0,
            "weakest_face":"foundation","weakest_face_score":0.9,
            "anchor_integrity":0.9,"observed_at":now.isoformat(),
            "not_after":(now+timedelta(seconds=25)).isoformat(),
            "authority_granted":False,
        }
        key=secrets.token_bytes(32)
        envelope=sign_local_advisory(
            advisory,request=req,producer_id=PRODUCER,
            kid="r9-ci",secret=key,now=now,
        )
        kwargs={
            "request_id":req.request_id,"introspector":gate,
            "policy":reopened,"envelope":envelope,
            "trusted_keys":{(PRODUCER,"r9-ci"):key},
            "replay_cache":LocalReplayCache(),"now":now,
        }
        verdict=evaluate_user_verified_profile_candidate(token,**kwargs)
        if verdict.authoritative:
            raise AssertionError("WebAuthn UV granted OS authority")
        if verdict.disposition=="CANDIDATE":
            if evaluate_user_verified_profile_candidate(token,**kwargs).disposition!="DENY":
                raise AssertionError("R9 approval replay accepted")
        print(verdict.disposition)
    return 0


if __name__=="__main__":
    raise SystemExit(main())
