"""R11 manual local exact-action approval test suite.

Signed Ed25519 receipts and WebAuthn ES256 assertions are synthetic test
fixtures. No real hardware authenticator, user or PhiOS effect is involved.
"""
from __future__ import annotations

import http.client
import json
import os
import secrets
import sqlite3
import tempfile
import threading
import unittest
from dataclasses import asdict
from datetime import datetime,timedelta,timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phicloud.authz import ISSUER,AUDIENCE
from phicloud.durable_consent import DurableOwnerConsentPolicy
from phicloud.local_consent import PolicyDenied
from phicloud.operator_review import (
    LocalOperatorApproval,handler_factory,_read_private_receipt,
    OneShotServer,
)
from phicloud.shield_policy import EffectRequest
from webauthn_fixture import (
    SyntheticAuthenticator, ed25519_public_bytes, sign_review,
)

PAIRING="r11-review-only-secret-"+("a"*32)
OPERATOR="local-r11-operator"
KID="review-signer"


def synthetic_request(request_id="r11-local-read",sub="synthetic-r11-owner"):
    return EffectRequest(
        request_id=request_id,scope="pre_service",
        subject_issuer=ISSUER,subject_id=sub,
        audience=AUDIENCE,action="profile.read",
        resource="profile:synthetic-self",
    )


class LocalOperatorReviewTests(unittest.TestCase):
    def setUp(self):
        if os.name!="posix":
            self.skipTest("POSIX private R9 policy required")
        self.temp=tempfile.TemporaryDirectory(prefix="phicloud-r11-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.root.chmod(0o700)
        self.db=self.root/"consent.sqlite3"
        self.policy=DurableOwnerConsentPolicy(self.db)
        self.now=datetime.now(timezone.utc)
        self.signer=Ed25519PrivateKey.generate()
        self.auth=SyntheticAuthenticator()
        self.policy.register_operator_key(
            operator_id=OPERATOR,kid=KID,
            public_key=ed25519_public_bytes(self.signer),
        )
        self.policy.register_operator_credential(
            operator_id=OPERATOR,credential_id=self.auth.credential_id,
            public_key=self.auth.cose_public,
        )
        self.req=synthetic_request()
        self.policy.register_synthetic_self(self.req)
        self.ticket=self.policy.stage(self.req,now=self.now)
        self.receipt=sign_review(
            self.ticket,self.signer,now=self.now,
            operator=OPERATOR,kid=KID,
        )

    def controller(self,receipt=None,credential_id=None):
        return LocalOperatorApproval(
            policy=DurableOwnerConsentPolicy(self.db),
            receipt=receipt if receipt is not None else self.receipt,
            pairing_code=PAIRING,now=self.now,
            credential_id=credential_id,
        )

    def unlocked(self,controller=None):
        controller=controller or self.controller()
        preview=controller.unlock(pairing_code=PAIRING,now=self.now)
        return controller,preview

    def challenge(self,controller,preview):
        return controller.challenge(
            session=preview["session"],acknowledged=True,now=self.now,
        )

    def approve(self,controller=None,**assertion_options):
        controller,preview=self.unlocked(controller)
        options=self.challenge(controller,preview)
        from base64 import urlsafe_b64decode
        challenge=urlsafe_b64decode(options["challenge"]+"==")
        assertion=self.auth.assertion(challenge,**assertion_options)
        return controller,preview,options,assertion

    def test_preview_displays_every_signed_field_only_after_pairing(self):
        controller=self.controller()
        self.assertFalse(controller._paired)
        self.assertIsNone(controller._session)
        _,preview=self.unlocked(controller)
        self.assertEqual(preview["operator"],OPERATOR)
        self.assertEqual(preview["request"],asdict(self.req))
        self.assertEqual(set(preview["request"]),{
            "request_id","scope","subject_issuer","subject_id",
            "audience","action","resource",
        })
        self.assertFalse(preview["execution_authority"])
        with self.assertRaises(PolicyDenied):
            controller.unlock(pairing_code=PAIRING,now=self.now)

    def test_verified_passkey_records_review_no_execution(self):
        controller,preview,options,assertion=self.approve()
        self.assertEqual(options["rpId"],"localhost")
        self.assertEqual(options["userVerification"],"required")
        self.assertEqual(len(options["allowCredentials"]),1)
        result=controller.complete(
            session=preview["session"],assertion=assertion,now=self.now,
        )
        self.assertTrue(result["review_recorded"])
        self.assertTrue(result["webauthn_uv_verified"])
        self.assertFalse(result["execution_authority"])
        self.assertFalse(result["resource_read"])
        with self.assertRaises(PolicyDenied):
            controller.complete(
                session=preview["session"],assertion=assertion,now=self.now,
            )
        # It remains a non-executable receipt until separate PhiID+ANC policy.
        authority,consent=DurableOwnerConsentPolicy(self.db).consume(
            self.req,now=self.now,
            require_signed=True,require_presence=True,
        )
        self.assertEqual(authority.request_id,self.req.request_id)
        self.assertEqual(consent.resource,"profile:synthetic-self")
        with self.assertRaises(PolicyDenied):
            DurableOwnerConsentPolicy(self.db).consume(
                self.req,now=self.now,
                require_signed=True,require_presence=True,
            )

    def test_pairing_wrong_secret_locked_at_five_attempts(self):
        controller=self.controller()
        for _ in range(5):
            with self.assertRaises(PolicyDenied):
                controller.unlock(pairing_code="incorrect",now=self.now)
        with self.assertRaises(PolicyDenied):
            controller.unlock(pairing_code=PAIRING,now=self.now)

    def test_unpaired_or_wrong_session_cannot_get_challenge(self):
        controller=self.controller()
        with self.assertRaises(PolicyDenied):
            controller.challenge(session="attacker",acknowledged=True,now=self.now)
        _,preview=self.unlocked(controller)
        with self.assertRaises(PolicyDenied):
            controller.challenge(session="wrong",acknowledged=True,now=self.now)
        with self.assertRaises(PolicyDenied):
            controller.challenge(
                session=preview["session"],acknowledged=False,now=self.now,
            )
        self.challenge(controller,preview)
        with self.assertRaises(PolicyDenied):
            self.challenge(controller,preview)

    def test_webauthn_missing_uv_wrong_origin_or_challenge_denied(self):
        variants=(
            {"verified":False},
            {"present":False},
            {"origin":"https://attacker.example"},
            {"rp_id":"not-localhost"},
        )
        for data in variants:
            with self.subTest(data=data):
                controller,preview,options,assertion=self.approve(**data)
                with self.assertRaises(PolicyDenied):
                    controller.complete(
                        session=preview["session"],assertion=assertion,now=self.now,
                    )
                with self.assertRaises(PolicyDenied):
                    self.policy.consume(
                        self.req,now=self.now,
                        require_signed=True,require_presence=True,
                    )
                # Re-use the spent request ID is intentionally impossible.
                break

    def test_wrong_passkey_challenge_is_not_accepted(self):
        controller,preview,options,_=self.approve()
        wrong=self.auth.assertion(secrets.token_bytes(32))
        with self.assertRaises(PolicyDenied):
            controller.complete(session=preview["session"],assertion=wrong,now=self.now)

    def test_decline_before_challenge_burns_review(self):
        controller,preview=self.unlocked()
        outcome=controller.decline(session=preview["session"],now=self.now)
        self.assertTrue(outcome["declined"])
        self.assertFalse(outcome["execution_authority"])
        with self.assertRaises(PolicyDenied):
            self.policy.consume(self.req,now=self.now,require_signed=True)
        with self.assertRaises(PolicyDenied):
            self.challenge(controller,preview)

    def test_decline_after_challenge_burns_review(self):
        controller,preview,options,assertion=self.approve()
        outcome=controller.decline(session=preview["session"],now=self.now)
        self.assertTrue(outcome["declined"])
        with self.assertRaises(PolicyDenied):
            self.policy.consume(self.req,now=self.now,require_signed=True)
        with self.assertRaises(PolicyDenied):
            controller.complete(session=preview["session"],assertion=assertion,now=self.now)

    def test_cannot_downgrade_issued_challenge_into_legacy_r6_or_r7(self):
        controller,preview,options,assertion=self.approve()
        self.assertFalse(self.policy.approve(
            self.ticket.review_id,shown_request=self.req,
            acknowledged=True,now=self.now,
        ))
        self.assertFalse(self.policy.approve_signed(self.receipt,now=self.now))
        self.assertTrue(controller.complete(
            session=preview["session"],assertion=assertion,now=self.now,
        ))

    def test_r9_verified_review_cannot_downgrade_revoked_credential(self):
        controller,preview,options,assertion=self.approve()
        controller.complete(session=preview["session"],assertion=assertion,now=self.now)
        self.policy.revoke_operator_credential(credential_id=self.auth.credential_id)
        with self.assertRaises(PolicyDenied):
            self.policy.consume(
                self.req,now=self.now,require_signed=True,require_presence=False,
            )

    def test_revoked_operator_key_or_credential_blocks_completion(self):
        controller,preview,options,assertion=self.approve()
        self.policy.revoke_operator_key(operator_id=OPERATOR,kid=KID)
        with self.assertRaises(PolicyDenied):
            controller.complete(
                session=preview["session"],assertion=assertion,now=self.now,
            )

    def test_signed_receipt_tampering_rejected_before_browser_opens(self):
        for field,value in (
            ("operator_id","attacker"),
            ("review_id","different-review"),
            ("nonce","0"*32),
            ("signature","A"*86),
        ):
            with self.subTest(field=field),self.assertRaises(PolicyDenied):
                self.controller(receipt={**self.receipt,field:value})

    def test_extra_registered_authenticator_requires_trusted_selection(self):
        second=SyntheticAuthenticator()
        self.policy.register_operator_credential(
            operator_id=OPERATOR,credential_id=second.credential_id,
            public_key=second.cose_public,
        )
        with self.assertRaises(PolicyDenied):
            self.controller()
        selected=self.controller(credential_id=self.auth.credential_id)
        self.assertEqual(selected.credential_id,self.auth.credential_id)
        with self.assertRaises(PolicyDenied):
            self.controller(credential_id=secrets.token_bytes(32))

    def test_expired_session_and_signed_review_fail_closed(self):
        controller,preview=self.unlocked()
        with self.assertRaises(PolicyDenied):
            controller.challenge(
                session=preview["session"],acknowledged=True,
                now=self.now+timedelta(seconds=31),
            )
        with self.assertRaises(PolicyDenied):
            LocalOperatorApproval(
                policy=self.policy,receipt=self.receipt,pairing_code=PAIRING,
                now=self.now+timedelta(seconds=31),
            )

    def test_private_receipt_file_permissions_symlink_and_json_structure(self):
        path=self.root/"receipt.json"
        path.write_text(json.dumps(self.receipt))
        path.chmod(0o600)
        parsed=_read_private_receipt(str(path))
        self.assertEqual(parsed,self.receipt)
        path.chmod(0o644)
        with self.assertRaises(PolicyDenied):
            _read_private_receipt(str(path))
        path.chmod(0o600)
        link=self.root/"shortcut.json"
        link.symlink_to(path)
        with self.assertRaises(PolicyDenied):
            _read_private_receipt(str(link))
        path.write_text('{"schema":"x","schema":"y"}')
        with self.assertRaises(PolicyDenied):
            _read_private_receipt(str(path))

    def test_http_does_not_leak_request_before_pairing_and_rejects_csrf(self):
        controller=self.controller()
        server=OneShotServer(("127.0.0.1",0),handler_factory(controller))
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            def send(method,path,payload=None,headers=None):
                connection=http.client.HTTPConnection(
                    "127.0.0.1",server.server_port,timeout=4,
                )
                connection.request(
                    method,path,body=payload,headers=headers or {},
                )
                response=connection.getresponse()
                status=response.status
                body=response.read()
                connection.close()
                return status,body
            status,body=send("GET","/",headers={"Host":"attacker.example:8769"})
            self.assertEqual(status,403)
            status,body=send("GET","/",headers={"Host":"localhost:8769"})
            self.assertEqual(status,200)
            self.assertNotIn(self.req.subject_id.encode(),body)
            self.assertNotIn(PAIRING.encode(),body)
            payload=json.dumps({"code":PAIRING}).encode()
            for origin in ("http://attacker.invalid",None):
                headers={
                    "Host":"localhost:8769","Content-Type":"application/json",
                }
                if origin is not None:
                    headers["Origin"]=origin
                status,_=send(
                    "POST","/v1/review/unlock",payload,headers=headers
                )
                self.assertEqual(status,403)
            status,body=send(
                "POST","/v1/review/unlock",payload,headers={
                    "Host":"localhost:8769","Origin":"http://localhost:8769",
                    "Content-Type":"application/json",
                },
            )
            self.assertEqual(status,200)
            self.assertEqual(json.loads(body)["request"]["subject_id"],self.req.subject_id)
        finally:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()


if __name__=="__main__":
    unittest.main()
