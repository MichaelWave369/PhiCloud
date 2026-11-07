"""R12 delayed-signing preview tests with disposable external signer fixture.

These tests generate a private Ed25519 key only in test memory. Production
PhiCloud must NEVER implement its own signer or load its private key.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import socket
import stat
import tempfile
import threading
import unittest
from dataclasses import asdict
from datetime import datetime,timedelta,timezone
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from phicloud.authz import ISSUER,AUDIENCE,REQUIRED_SCOPE,LocalTokenIntrospector
from phicloud.deferred_review import (
    DeferredOperatorApproval,UnixOperatorSigner,
    SIGNER_SCHEMA,_read_private_review_id,
)
from phicloud.durable_consent import DurableOwnerConsentPolicy
from phicloud.local_consent import PolicyDenied
from phicloud.shield_identity import stage_verified_operator_preview
from phicloud.shield_policy import EffectRequest
from phicloud.operator_review import handler_factory
from webauthn_fixture import SyntheticAuthenticator,ed25519_public_bytes


PAIR="r12-private-pair-"+("a"*40)
OPERATOR="r12-operator"
KID="trusted-r12-key"


class TestSigner:
    """Injected disposable signer, intentionally only in tests."""
    __test__=False

    def __init__(self,private,broken=False):
        self.private=private
        self.broken=broken
        self.calls=0
        self.signed_messages=[]

    def sign(self,message,*,operator_id,kid):
        self.calls+=1
        self.signed_messages.append((message,operator_id,kid))
        if self.broken:
            return secrets.token_bytes(64)
        return self.private.sign(message)


def request(id="r12-preview",sub="synthetic-operator-owner"):
    return EffectRequest(
        request_id=id,scope="pre_service",subject_issuer=ISSUER,
        subject_id=sub,audience=AUDIENCE,action="profile.read",
        resource="profile:synthetic-self",
    )


def keycloak_stub():
    def introspect(token,secret):
        if token!="r12-test-token" or secret!="r12-disposable-fixture-confidential-secret-0123456789abcdef":
            raise RuntimeError("wrong synthetic token")
        from time import time
        return {
            "active":True,"iss":ISSUER,"sub":"synthetic-operator-owner",
            "aud":[AUDIENCE],"scope":"openid "+REQUIRED_SCOPE,
            "exp":int(time())+500,"nbf":int(time())-1,
            "token_type":"Bearer",
        }
    return LocalTokenIntrospector("r12-disposable-fixture-confidential-secret-0123456789abcdef",transport=introspect)


class DeferredOperatorReviewTests(unittest.TestCase):
    def setUp(self):
        if os.name!="posix":
            self.skipTest("R12 operator ledger is POSIX-only")
        self.temp=tempfile.TemporaryDirectory(prefix="phi-r12-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.root.chmod(0o700)
        self.db=self.root/"consent.sqlite3"
        self.policy=DurableOwnerConsentPolicy(self.db)
        self.now=datetime.now(timezone.utc)
        self.private=Ed25519PrivateKey.generate()
        self.signer=TestSigner(self.private)
        self.auth=SyntheticAuthenticator()
        self.policy.register_operator_key(
            operator_id=OPERATOR,kid=KID,
            public_key=ed25519_public_bytes(self.private),
        )
        self.policy.register_operator_credential(
            operator_id=OPERATOR,credential_id=self.auth.credential_id,
            public_key=self.auth.cose_public,
        )
        self.req=request()
        self.policy.register_synthetic_self(self.req)
        self.ticket=self.policy.stage_operator_preview(self.req,now=self.now)

    def controller(self,*,signer=None,now=None,ticket=None):
        return DeferredOperatorApproval(
            policy=DurableOwnerConsentPolicy(self.db),
            review_id=(ticket or self.ticket).review_id,
            operator_id=OPERATOR,kid=KID,
            signer=signer if signer is not None else self.signer,
            pairing_code=PAIR,now=now if now is not None else self.now,
        )

    def unlock(self,controller=None,now=None):
        controller=controller or self.controller()
        return controller,controller.unlock(
            pairing_code=PAIR,now=now if now is not None else self.now,
        )

    def webauthn(self,controller,preview,*,when=None,**variations):
        when=when if when is not None else self.now
        options=controller.challenge(
            session=preview["session"],acknowledged=True,now=when,
        )
        challenge=base64.urlsafe_b64decode(options["challenge"]+"==")
        return options,self.auth.assertion(challenge,**variations)

    def test_five_minute_preview_and_thirty_second_signed_receipt(self):
        controller,preview=self.unlock()
        self.assertEqual(self.signer.calls,0)
        self.assertEqual(preview["request"],asdict(self.req))
        self.assertFalse(preview["execution_authority"])
        self.assertEqual(
            preview["expires_at_ms"]-int(self.now.timestamp()*1000),300000,
        )
        late=self.now+timedelta(seconds=245)
        opts,assertion=self.webauthn(controller,preview,when=late)
        self.assertEqual(self.signer.calls,1)
        self.assertEqual(opts["rpId"],"localhost")
        self.assertEqual(opts["userVerification"],"required")
        self.assertLessEqual(opts["timeout"],30000)
        signed=self.signer.signed_messages[0][0]
        self.assertTrue(signed.startswith(b"PHICLOUD_OPERATOR_REVIEW_ED25519_V1\x00"))
        body=json.loads(signed.split(b"\x00",1)[1])
        self.assertEqual(body["request"],asdict(self.req))
        self.assertEqual(body["review_id"],self.ticket.review_id)
        self.assertLessEqual(
            body["expires_at_ms"]-body["issued_at_ms"],30000,
        )
        result=controller.complete(
            session=preview["session"],assertion=assertion,now=late,
        )
        self.assertTrue(result["review_recorded"])
        self.assertFalse(result["execution_authority"])
        self.assertFalse(result["resource_read"])
        self.assertEqual(
            self.policy.consume(
                self.req,now=late,
                require_signed=True,require_presence=True,
            )[0].request_id,self.req.request_id,
        )
        with self.assertRaises(PolicyDenied):
            self.policy.consume(
                self.req,now=late,
                require_signed=True,require_presence=True,
            )

    def test_legacy_stage_still_only_sixty_seconds(self):
        other=request("ordinary-r6-stage")
        t=self.policy.stage(other,now=self.now)
        self.assertEqual(
            int((t.expires_at-self.now).total_seconds()),60,
        )

    def test_preview_from_fresh_live_oidc_not_from_browser_claims(self):
        gate=keycloak_stub()
        preview=stage_verified_operator_preview(
            "r12-test-token",request_id="new-r12-verified",
            introspector=gate,policy=self.policy,now=self.now,
        )
        self.assertEqual(preview.request.subject_id,"synthetic-operator-owner")
        self.assertEqual(
            int((preview.expires_at-self.now).total_seconds()),300,
        )
        with self.assertRaises(Exception):
            stage_verified_operator_preview(
                "wrong-token",request_id="untrusted",
                introspector=gate,policy=self.policy,now=self.now,
            )

    def test_signer_unavailable_or_wrong_signature_burns_review(self):
        controller,preview=self.unlock(
            self.controller(signer=TestSigner(self.private,broken=True))
        )
        with self.assertRaises(PolicyDenied):
            controller.challenge(
                session=preview["session"],acknowledged=True,now=self.now,
            )
        with self.assertRaises(PolicyDenied):
            self.policy.consume(self.req,now=self.now,require_signed=True)
        with self.assertRaises(PolicyDenied):
            controller.challenge(
                session=preview["session"],acknowledged=True,now=self.now,
            )

    def test_explicit_denial_and_no_signer_call(self):
        controller,preview=self.unlock()
        with self.assertRaises(PolicyDenied):
            controller.challenge(
                session=preview["session"],acknowledged=False,now=self.now,
            )
        self.assertEqual(self.signer.calls,0)
        result=controller.decline(session=preview["session"],now=self.now)
        self.assertTrue(result["declined"])
        self.assertFalse(result["execution_authority"])
        self.assertEqual(self.signer.calls,0)
        with self.assertRaises(PolicyDenied):
            self.policy.consume(self.req,now=self.now,require_signed=True)

    def test_decline_after_signature_burns_r9_challenge(self):
        controller,preview=self.unlock()
        opts,assertion=self.webauthn(controller,preview)
        self.assertEqual(self.signer.calls,1)
        outcome=controller.decline(session=preview["session"],now=self.now)
        self.assertTrue(outcome["declined"])
        with self.assertRaises(PolicyDenied):
            controller.complete(
                session=preview["session"],assertion=assertion,now=self.now,
            )
        with self.assertRaises(PolicyDenied):
            self.policy.consume(self.req,now=self.now,require_signed=True)

    def test_no_legacy_r6_or_r7_downgrade_after_challenge(self):
        controller,preview=self.unlock()
        opts,assertion=self.webauthn(controller,preview)
        self.assertFalse(self.policy.approve(
            self.ticket.review_id,shown_request=self.req,
            acknowledged=True,now=self.now,
        ))
        self.assertFalse(self.policy.approve_signed(
            controller._receipt,now=self.now,
        ))
        self.assertTrue(controller.complete(
            session=preview["session"],assertion=assertion,now=self.now,
        ))
        self.policy.revoke_operator_credential(credential_id=self.auth.credential_id)
        with self.assertRaises(PolicyDenied):
            self.policy.consume(
                self.req,now=self.now,
                require_signed=True,require_presence=False,
            )

    def test_user_verification_is_mandatory(self):
        controller,preview=self.unlock()
        opts,assertion=self.webauthn(controller,preview,verified=False)
        with self.assertRaises(PolicyDenied):
            controller.complete(
                session=preview["session"],assertion=assertion,now=self.now,
            )
        with self.assertRaises(PolicyDenied):
            self.policy.consume(
                self.req,now=self.now,require_signed=True,require_presence=True,
            )

    def test_paired_challenge_and_signing_are_one_attempt(self):
        controller,preview=self.unlock()
        with self.assertRaises(PolicyDenied):
            controller.challenge(
                session="wrong",acknowledged=True,now=self.now,
            )
        self.assertEqual(self.signer.calls,0)
        opts,assertion=self.webauthn(controller,preview)
        with self.assertRaises(PolicyDenied):
            controller.challenge(
                session=preview["session"],acknowledged=True,now=self.now,
            )
        self.assertEqual(self.signer.calls,1)

    def test_preview_expiry_prevents_delayed_signature(self):
        controller,preview=self.unlock()
        too_late=self.now+timedelta(seconds=301)
        with self.assertRaises(PolicyDenied):
            controller.challenge(
                session=preview["session"],acknowledged=True,now=too_late,
            )
        self.assertEqual(self.signer.calls,0)

    def test_revoked_signer_or_credential_fails_closed(self):
        controller,preview=self.unlock()
        self.policy.revoke_operator_key(operator_id=OPERATOR,kid=KID)
        with self.assertRaises(PolicyDenied):
            controller.challenge(
                session=preview["session"],acknowledged=True,now=self.now,
            )
        self.assertEqual(self.signer.calls,0)

    def test_pairing_lock_and_non_ascii_denied(self):
        controller=self.controller()
        for _ in range(5):
            with self.assertRaises(PolicyDenied):
                controller.unlock(pairing_code="wrong",now=self.now)
        with self.assertRaises(PolicyDenied):
            controller.unlock(pairing_code=PAIR,now=self.now)
        with self.assertRaises(PolicyDenied):
            DeferredOperatorApproval(
                policy=self.policy,review_id=self.ticket.review_id,
                operator_id=OPERATOR,kid=KID,signer=self.signer,
                pairing_code="non-ascii-☃"+("x"*25),now=self.now,
            )

    def test_private_review_file_has_only_review_id_and_no_symlink(self):
        path=self.root/"selector.json"
        path.write_text(json.dumps({"review_id":self.ticket.review_id}))
        path.chmod(0o600)
        self.assertEqual(_read_private_review_id(str(path)),self.ticket.review_id)
        path.chmod(0o644)
        with self.assertRaises(PolicyDenied):
            _read_private_review_id(str(path))
        path.chmod(0o600)
        path.write_text('{"review_id":"x","review_id":"y"}')
        with self.assertRaises(PolicyDenied):
            _read_private_review_id(str(path))
        path.write_text(json.dumps({"review_id":self.ticket.review_id}))
        link=self.root/"shortcut.json"
        link.symlink_to(path)
        with self.assertRaises(PolicyDenied):
            _read_private_review_id(str(link))

    def test_unix_signer_rpc_against_separate_test_process(self):
        if not hasattr(socket,"SO_PEERCRED"):
            self.skipTest("Linux Unix peer credentials required")
        path=self.root/"external-signer.sock"
        service=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        service.bind(str(path))
        path.chmod(0o600)
        service.listen(1)
        self.addCleanup(service.close)
        responses=[]
        def serve():
            peer,_=service.accept()
            with peer:
                data=bytearray()
                while not data.endswith(b"\n") and len(data)<4096:
                    x=peer.recv(512)
                    if not x:
                        break
                    data.extend(x)
                msg=json.loads(data)
                responses.append(msg)
                raw=base64.urlsafe_b64decode(msg["message"]+"==")
                sig=self.private.sign(raw)
                peer.sendall(
                    json.dumps({"signature":base64.urlsafe_b64encode(sig).decode().rstrip("=")}).encode()+b"\n"
                )
        thread=threading.Thread(target=serve,daemon=True)
        thread.start()
        signer=UnixOperatorSigner(path)
        controller,preview=self.unlock(self.controller(signer=signer))
        opts,assertion=self.webauthn(controller,preview)
        thread.join(timeout=3)
        self.assertEqual(len(responses),1)
        self.assertEqual(responses[0]["schema"],SIGNER_SCHEMA)
        self.assertEqual(responses[0]["operator_id"],OPERATOR)
        result=controller.complete(
            session=preview["session"],assertion=assertion,now=self.now,
        )
        self.assertTrue(result["review_recorded"])

    def test_signer_socket_permissions_and_missing_path_fail_closed(self):
        if not hasattr(socket,"SO_PEERCRED"):
            self.skipTest("Linux only")
        with self.assertRaises((PolicyDenied,OSError)):
            UnixOperatorSigner(self.root/"does-not-exist.sock")
        path=self.root/"signer.sock"
        service=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        service.bind(str(path))
        try:
            path.chmod(0o666)
            with self.assertRaises(PolicyDenied):
                UnixOperatorSigner(path)
        finally:
            service.close()
            path.unlink()


if __name__=="__main__":
    unittest.main()
