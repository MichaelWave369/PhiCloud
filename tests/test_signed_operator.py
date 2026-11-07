"""R7 trusted-public-key Ed25519 approvals, migration and revoked-key tests.

Private keys in these tests are disposable fixtures, never persisted.
"""
from __future__ import annotations

import base64
import os
import secrets
import sqlite3
import stat
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phicloud.authz import AUDIENCE, ISSUER, REQUIRED_SCOPE, LocalTokenIntrospector
from phicloud.durable_consent import DurableOwnerConsentPolicy
from phicloud.local_consent import PolicyDenied
from phicloud.operator_approval import (
    SCHEMA, PURPOSE, canonical_message, verified_receipt_expiry,
)
from phicloud.shield_identity import (
    PRODUCER, evaluate_signed_profile_candidate, stage_verified_profile_review,
)
from phicloud.shield_policy import ANC_SCHEMA, EffectRequest
from phicloud.shield_transport import LocalReplayCache, sign_local_advisory

TOKEN = "local-fixture-token-" + "x" * 40
SECRET = "local-fixture-secret-" + "s" * 40


def gate_for(subject="signed-owner", active=True):
    def verify(token, secret):
        if token != TOKEN or secret != SECRET:
            raise RuntimeError("wrong fixture token")
        return {
            "active": active, "iss": ISSUER, "sub": subject,
            "aud": [AUDIENCE], "scope": "openid " + REQUIRED_SCOPE,
            "exp": int(time.time()) + 300, "nbf": int(time.time()) - 1,
            "token_type": "Bearer",
        }
    return LocalTokenIntrospector(SECRET,transport=verify)


def public_bytes(key):
    return key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def receipt_for(ticket, signer, *, now, operator="operator-local", kid="key-a", **overrides):
    stamp = int(now.timestamp()*1000)
    body = {
        "schema": SCHEMA,
        "purpose": PURPOSE,
        "operator_id": operator,
        "kid": kid,
        "review_id": ticket.review_id,
        "request": asdict(ticket.request),
        "issued_at_ms": stamp,
        "expires_at_ms": stamp+20_000,
        "nonce": secrets.token_hex(16),
    }
    body.update(overrides)
    return {
        **body,
        "signature": base64.urlsafe_b64encode(
            signer.sign(canonical_message(body))
        ).decode("ascii").rstrip("="),
    }


class SignedOperatorApprovalTests(unittest.TestCase):
    def setUp(self):
        if os.name!="posix":
            self.skipTest("R7 requires POSIX private storage fixture")
        self.temp=tempfile.TemporaryDirectory(prefix="phicloud-r7-")
        self.addCleanup(self.temp.cleanup)
        self.folder=Path(self.temp.name)
        self.folder.chmod(0o700)
        self.db=self.folder/"operator-review.sqlite3"
        self.policy=DurableOwnerConsentPolicy(self.db)
        self.now=datetime.now(timezone.utc)
        self.gate=gate_for()
        self.signer=Ed25519PrivateKey.generate()
        self.policy.register_operator_key(
            operator_id="operator-local",kid="key-a",public_key=public_bytes(self.signer)
        )
        self.anc_key=secrets.token_bytes(32)

    def fresh(self):
        return DurableOwnerConsentPolicy(self.db)

    def stage(self, id=None):
        return stage_verified_profile_review(
            TOKEN,request_id=id or "r7-"+secrets.token_hex(8),
            introspector=self.gate,policy=self.fresh(),now=self.now,
        )

    def sign(self,ticket,**options):
        return receipt_for(ticket,self.signer,now=self.now,**options)

    def risk_envelope(self, req):
        advisory = {
            "schema":ANC_SCHEMA,"request_id":req.request_id,"scope":req.scope,
            "posture":"safe","recommended_action":"allow","signal_count":0,
            "weakest_face":"foundation","weakest_face_score":0.9,
            "anchor_integrity":0.9,"observed_at":self.now.isoformat(),
            "not_after":(self.now+timedelta(seconds=25)).isoformat(),
            "authority_granted":False,
        }
        return sign_local_advisory(
            advisory,request=req,producer_id=PRODUCER,
            kid="anc-test",secret=self.anc_key,now=self.now,
        )

    def verdict(self,ticket,**overrides):
        arguments = {
            "token":TOKEN,"request_id":ticket.request.request_id,
            "introspector":self.gate,"policy":self.fresh(),
            "envelope":self.risk_envelope(ticket.request),
            "trusted_keys":{(PRODUCER,"anc-test"):self.anc_key},
            "replay_cache":LocalReplayCache(),"now":self.now,
        }
        arguments.update(overrides)
        return evaluate_signed_profile_candidate(**arguments)

    def test_valid_signed_approval_only_candidate_and_replay_denied(self):
        ticket=self.stage()
        self.assertTrue(self.policy.approve_signed(self.sign(ticket),now=self.now))
        result=self.verdict(ticket)
        self.assertEqual(result.disposition,"CANDIDATE")
        self.assertFalse(result.authoritative)
        self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_restart_preserves_signed_receipt_and_verifier_key(self):
        ticket=self.stage()
        receipt=self.sign(ticket)
        self.assertTrue(self.fresh().approve_signed(receipt,now=self.now))
        self.assertEqual(
            self.fresh().consume(ticket.request,now=self.now,require_signed=True)[0].request_id,
            ticket.request.request_id,
        )
        with self.assertRaises(PolicyDenied):
            self.fresh().consume(ticket.request,now=self.now,require_signed=True)

    def test_unsigned_legacy_approval_denied_by_signed_only_gate(self):
        ticket=self.stage()
        self.assertTrue(self.policy.approve(
            ticket.review_id,shown_request=ticket.request,
            acknowledged=True,now=self.now,
        ))
        self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_tampering_and_wrong_purpose_all_denied(self):
        mutations=[
            {"purpose":"something-else"},
            {"schema":"phicloud.operator-review.ed25519.v999"},
            {"kid":"unknown-key"},
            {"operator_id":"other-operator"},
            {"review_id":"other-review"},
            {"nonce":"0"*32},
            {"expires_at_ms":int(self.now.timestamp()*1000)+1000},
        ]
        for change in mutations:
            with self.subTest(change=change):
                ticket=self.stage()
                receipt=self.sign(ticket)
                receipt.update(change)
                self.assertFalse(self.fresh().approve_signed(receipt,now=self.now))
                self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_signed_other_subject_action_and_resource_are_rejected(self):
        for field,value in (
            ("subject_id","other-person"),("subject_issuer","https://other.invalid"),
            ("action","mail.read"),("resource","file:private"),("audience","phimail"),
        ):
            with self.subTest(field=field):
                ticket=self.stage()
                payload=asdict(ticket.request)
                payload[field]=value
                forged=self.sign(ticket,request=payload)
                self.assertFalse(self.fresh().approve_signed(forged,now=self.now))

    def test_extra_fields_including_embedded_public_key_denied(self):
        ticket=self.stage()
        receipt=self.sign(ticket)
        receipt["public_key"]=public_bytes(self.signer).hex()
        self.assertFalse(self.policy.approve_signed(receipt,now=self.now))

    def test_wrong_private_key_even_same_kid_denied(self):
        ticket=self.stage()
        wrong=Ed25519PrivateKey.generate()
        self.assertFalse(self.policy.approve_signed(
            receipt_for(ticket,wrong,now=self.now),now=self.now,
        ))

    def test_expired_and_oversized_signed_receipts_denied(self):
        for modifications in (
            {"expires_at_ms":int(self.now.timestamp()*1000)-1},
            {"expires_at_ms":int(self.now.timestamp()*1000)+31_000},
            {"issued_at_ms":int(self.now.timestamp()*1000)+10_000},
            {"nonce":"n"*5000},
        ):
            with self.subTest(modifications=modifications):
                ticket=self.stage()
                signed=self.sign(ticket,**modifications)
                self.assertFalse(self.fresh().approve_signed(signed,now=self.now))

    def test_public_key_rotation_and_revocation_persist(self):
        old=self.stage("r7-old")
        self.assertTrue(self.policy.approve_signed(self.sign(old),now=self.now))
        replacement=Ed25519PrivateKey.generate()
        self.policy.register_operator_key(
            operator_id="operator-local",kid="key-b",public_key=public_bytes(replacement)
        )
        newer=self.stage("r7-new")
        signed=receipt_for(newer,replacement,now=self.now,kid="key-b")
        self.assertTrue(self.fresh().approve_signed(signed,now=self.now))
        self.fresh().revoke_operator_key(operator_id="operator-local",kid="key-a")
        self.assertEqual(self.verdict(old).disposition,"DENY")
        self.assertEqual(self.verdict(newer).disposition,"CANDIDATE")
        with self.assertRaises(PolicyDenied):
            self.fresh().register_operator_key(
                operator_id="operator-local",kid="key-a",public_key=public_bytes(self.signer)
            )

    def test_key_revoked_before_approval_rejects_signature(self):
        ticket=self.stage()
        self.fresh().revoke_operator_key(operator_id="operator-local",kid="key-a")
        self.assertFalse(self.fresh().approve_signed(self.sign(ticket),now=self.now))

    def test_owner_revocation_independent_of_operator_key(self):
        ticket=self.stage()
        self.assertTrue(self.policy.approve_signed(self.sign(ticket),now=self.now))
        self.fresh().revoke_owner(issuer=ISSUER,sub="signed-owner")
        self.assertEqual(self.verdict(ticket).disposition,"DENY")

    def test_two_concurrent_handles_only_one_signed_consumption(self):
        ticket=self.stage()
        self.assertTrue(self.policy.approve_signed(self.sign(ticket),now=self.now))
        handles=[self.fresh() for _ in range(12)]
        def consume(handle):
            try:
                handle.consume(ticket.request,now=self.now,require_signed=True)
                return True
            except PolicyDenied:
                return False
        with ThreadPoolExecutor(max_workers=12) as pool:
            results=list(pool.map(consume,handles))
        self.assertEqual(sum(results),1)

    def test_failed_review_not_replayable_even_when_valid_signature_present(self):
        ticket=self.stage()
        invalid=self.sign(ticket)
        invalid["signature"]="A"*86
        self.assertFalse(self.fresh().approve_signed(invalid,now=self.now))
        self.assertFalse(self.fresh().approve_signed(self.sign(ticket),now=self.now))

    def test_bad_enrollment_and_duplicate_kid_denied(self):
        with self.assertRaises(PolicyDenied):
            self.policy.register_operator_key(
                operator_id="operator-local",kid="key-a",
                public_key=public_bytes(self.signer),
            )
        with self.assertRaises(PolicyDenied):
            self.policy.register_operator_key(
                operator_id="operator-local",kid="key-c",public_key=b"x"*31
            )

    def test_stored_receipt_cannot_be_changed_without_signature_denial(self):
        ticket=self.stage()
        self.assertTrue(self.policy.approve_signed(self.sign(ticket),now=self.now))
        with sqlite3.connect(self.db) as conn:
            row=conn.execute("SELECT signed_receipt FROM requests WHERE review_id=?",
                             (ticket.review_id,)).fetchone()
            altered=row[0].replace("synthetic-self","another-resource")
            conn.execute(
                "UPDATE requests SET signed_receipt=? WHERE review_id=?",
                (altered,ticket.review_id),
            )
        self.assertEqual(self.verdict(ticket).disposition,"DENY")


if __name__=="__main__":
    unittest.main()
