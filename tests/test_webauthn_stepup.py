"""R9 WebAuthn UV gate negative tests. Synthetic authenticator fixture only."""
from __future__ import annotations

import os
import secrets
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from phicloud.authz import AUDIENCE, ISSUER, REQUIRED_SCOPE, LocalTokenIntrospector
from phicloud.durable_consent import DurableOwnerConsentPolicy
from phicloud.local_consent import PolicyDenied
from phicloud.shield_identity import (
    PRODUCER, evaluate_user_verified_profile_candidate,
    stage_verified_profile_review,
)
from phicloud.shield_policy import ANC_SCHEMA
from phicloud.shield_transport import LocalReplayCache, sign_local_advisory
from phicloud.webauthn_presence import RP_ID,ORIGIN
from webauthn_fixture import (
    SyntheticAuthenticator, ed25519_public_bytes, sign_review,
)

TOKEN="r9-unit-token-"+"x"*35
SECRET="r9-unit-client-secret-"+"s"*35


def gate(subject="operator-owner", active=True):
    def check(token, secret):
        if token!=TOKEN or secret!=SECRET:
            raise RuntimeError("unexpected fixture token")
        return {
            "active":active,"iss":ISSUER,"sub":subject,
            "aud":[AUDIENCE],"scope":"openid "+REQUIRED_SCOPE,
            "exp":int(time.time())+300,
            "nbf":int(time.time())-1,
            "token_type":"Bearer",
        }
    return LocalTokenIntrospector(SECRET,transport=check)


class WebAuthnOperatorStepupTests(unittest.TestCase):
    def setUp(self):
        if os.name!="posix":
            self.skipTest("R9 private database permissions are POSIX-only")
        self.temp=tempfile.TemporaryDirectory(prefix="phicloud-r9-")
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        root.chmod(0o700)
        self.db=root/"operator-stepup.sqlite3"
        self.policy=DurableOwnerConsentPolicy(self.db)
        self.now=datetime.now(timezone.utc)
        self.gate=gate()
        self.signer=ed25519.Ed25519PrivateKey.generate()
        self.authenticator=SyntheticAuthenticator()
        self.policy.register_operator_key(
            operator_id="test-operator",kid="signing-key",
            public_key=ed25519_public_bytes(self.signer),
        )
        self.policy.register_operator_credential(
            operator_id="test-operator",
            credential_id=self.authenticator.credential_id,
            public_key=self.authenticator.cose_public,
        )
        self.anc_secret=secrets.token_bytes(32)

    def reopened(self):
        return DurableOwnerConsentPolicy(self.db)

    def stage(self):
        ticket=stage_verified_profile_review(
            TOKEN,request_id="r9-"+secrets.token_hex(10),
            introspector=self.gate,policy=self.reopened(),now=self.now,
        )
        receipt=sign_review(ticket,self.signer,now=self.now)
        return ticket,receipt

    def challenge(self, receipt):
        return self.reopened().begin_operator_stepup(
            receipt,credential_id=self.authenticator.credential_id,now=self.now,
        )

    def assert_signed_stepup(self,ticket,receipt,*,counter=1,**assertion_options):
        challenge=self.challenge(receipt)
        assertion=self.authenticator.assertion(
            challenge,counter=counter,**assertion_options,
        )
        return self.reopened().approve_signed_with_stepup(
            receipt,assertion,now=self.now,
        )

    def verdict(self,ticket,**kwargs):
        req=ticket.request
        advisory={
            "schema":ANC_SCHEMA,"request_id":req.request_id,
            "scope":req.scope,"posture":"safe",
            "recommended_action":"allow","signal_count":0,
            "weakest_face":"foundation","weakest_face_score":0.9,
            "anchor_integrity":0.9,"observed_at":self.now.isoformat(),
            "not_after":(self.now+timedelta(seconds=25)).isoformat(),
            "authority_granted":False,
        }
        envelope=sign_local_advisory(
            advisory,request=req,producer_id=PRODUCER,
            kid="r9-anc",secret=self.anc_secret,now=self.now,
        )
        opts={
            "token":TOKEN,"request_id":req.request_id,
            "introspector":self.gate,"policy":self.reopened(),
            "envelope":envelope,
            "trusted_keys":{(PRODUCER,"r9-anc"):self.anc_secret},
            "replay_cache":LocalReplayCache(),"now":self.now,
        }
        opts.update(kwargs)
        return evaluate_user_verified_profile_candidate(**opts)

    def test_real_signatures_and_uv_only_inert_candidate(self):
        ticket,receipt=self.stage()
        self.assertTrue(self.assert_signed_stepup(ticket,receipt))
        self.assertEqual(self.verdict(ticket).disposition,"CANDIDATE")
        self.assertFalse(self.verdict(ticket).authoritative)
        self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_signed_without_webauthn_is_rejected(self):
        ticket,receipt=self.stage()
        self.assertTrue(self.reopened().approve_signed(receipt,now=self.now))
        self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_correct_rp_origin_user_verified_and_present_required(self):
        variants=[
            {"verified":False},
            {"present":False},
            {"origin":"https://lookalike.invalid"},
            {"rp_id":"other.local"},
            {"wrong_private":ec.generate_private_key(ec.SECP256R1())},
            {"credential_id":secrets.token_bytes(32)},
        ]
        for variant in variants:
            with self.subTest(variant=str(variant)[:55]):
                ticket,receipt=self.stage()
                self.assertFalse(
                    self.assert_signed_stepup(ticket,receipt,**variant)
                )
                self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_mismatch_signed_receipt_cannot_reuse_challenge(self):
        ticket,receipt=self.stage()
        challenge=self.challenge(receipt)
        swapped=dict(receipt)
        swapped["nonce"]="0"*32
        assertion=self.authenticator.assertion(challenge)
        self.assertFalse(
            self.reopened().approve_signed_with_stepup(
                swapped,assertion,now=self.now,
            )
        )
        self.assertFalse(
            self.reopened().approve_signed_with_stepup(
                receipt,assertion,now=self.now,
            )
        )

    def test_wrong_challenge_and_duplicate_assertion_denied(self):
        ticket,receipt=self.stage()
        self.challenge(receipt)
        with self.assertRaises(PolicyDenied):
            self.challenge(receipt)
        wrong=self.authenticator.assertion(secrets.token_bytes(32))
        self.assertFalse(
            self.reopened().approve_signed_with_stepup(receipt,wrong,now=self.now)
        )
        self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_counter_replay_rejected_across_restart(self):
        first,receipt=self.stage()
        self.assertTrue(self.assert_signed_stepup(first,receipt,counter=1))
        self.assertEqual(self.verdict(first).disposition,"CANDIDATE")
        second,receipt2=self.stage()
        self.assertFalse(self.assert_signed_stepup(second,receipt2,counter=1))
        third,receipt3=self.stage()
        self.assertTrue(self.assert_signed_stepup(third,receipt3,counter=2))
        self.assertEqual(self.verdict(third).disposition,"CANDIDATE")

    def test_credential_revocation_burns_approved_review(self):
        ticket,receipt=self.stage()
        self.assertTrue(self.assert_signed_stepup(ticket,receipt))
        self.reopened().revoke_operator_credential(
            credential_id=self.authenticator.credential_id
        )
        self.assertEqual(self.verdict(ticket).disposition,"DENY")
        with self.assertRaises(PolicyDenied):
            self.reopened().register_operator_credential(
                operator_id="test-operator",
                credential_id=self.authenticator.credential_id,
                public_key=self.authenticator.cose_public,
            )

    def test_signer_revocation_burns_stepup_review(self):
        ticket,receipt=self.stage()
        self.assertTrue(self.assert_signed_stepup(ticket,receipt))
        self.reopened().revoke_operator_key(
            operator_id="test-operator",kid="signing-key"
        )
        self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_owner_revocation_burns_stepup_review(self):
        ticket,receipt=self.stage()
        self.assertTrue(self.assert_signed_stepup(ticket,receipt))
        self.reopened().revoke_owner(
            issuer=ISSUER,sub="operator-owner"
        )
        self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_expired_challenge_and_request_denied(self):
        ticket,receipt=self.stage()
        challenge=self.challenge(receipt)
        late=self.now+timedelta(seconds=31)
        assertion=self.authenticator.assertion(challenge)
        self.assertFalse(self.reopened().approve_signed_with_stepup(
            receipt,assertion,now=late
        ))
        self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_signed_review_must_be_staged_before_challenge(self):
        ticket,receipt=self.stage()
        receipt["operator_id"]="some-other-person"
        with self.assertRaises(PolicyDenied):
            self.challenge(receipt)
        ticket2,receipt2=self.stage()
        with self.assertRaises(PolicyDenied):
            self.reopened().begin_operator_stepup(
                receipt2,credential_id=secrets.token_bytes(32),now=self.now
            )

    def test_two_threads_only_one_can_consume_user_verified_approval(self):
        ticket,receipt=self.stage()
        self.assertTrue(self.assert_signed_stepup(ticket,receipt))
        handles=[self.reopened() for _ in range(10)]
        def consume(handle):
            try:
                handle.consume(
                    ticket.request,now=self.now,
                    require_signed=True,require_presence=True,
                )
                return True
            except PolicyDenied:
                return False
        with ThreadPoolExecutor(max_workers=10) as executor:
            results=list(executor.map(consume,handles))
        self.assertEqual(sum(results),1)

    def test_preexisting_r7_signed_records_are_not_uv(self):
        ticket,receipt=self.stage()
        self.assertTrue(self.reopened().approve_signed(receipt,now=self.now))
        with self.assertRaises(PolicyDenied):
            self.reopened().consume(
                ticket.request,now=self.now,require_presence=True
            )

    def test_origin_is_fixed_to_localhost_and_no_http_route(self):
        self.assertEqual(RP_ID,"localhost")
        self.assertEqual(ORIGIN,"http://localhost:8769")
        self.assertEqual(
            self.reopened()._path,self.db
        )


if __name__=="__main__":
    unittest.main()
