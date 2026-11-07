"""R10 local operator-paired WebAuthn registration and R9 compatibility tests.

Registration assertions here come from synthetic ES256 authenticators.
They test RP verification, NOT live human presence or hardware attestation.
"""
from __future__ import annotations

import base64
import http.client
import json
import os
import secrets
import tempfile
import threading
import unittest
from datetime import datetime,timedelta,timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from phicloud.durable_consent import DurableOwnerConsentPolicy
from phicloud.local_consent import PolicyDenied
from phicloud.operator_enrollment import (
    LocalOperatorEnrollment,OneShotServer,handler_factory,
    MAX_ATTEMPTS,_json_object,
)
from phicloud.webauthn_presence import RP_ID,ORIGIN
from phicloud.shield_policy import EffectRequest
from tests.webauthn_fixture import (
    SyntheticAuthenticator,ed25519_public_bytes,sign_review,
)

PAIRING="one-time-ci-pairing-code-"+("p"*32)
OPERATOR="local-fixture-operator"


def decode(text):
    return base64.urlsafe_b64decode(text+"="*((-len(text))%4))


class LocalOperatorEnrollmentTests(unittest.TestCase):
    def setUp(self):
        if os.name!="posix":
            self.skipTest("POSIX private local operator database only")
        self.temp=tempfile.TemporaryDirectory(prefix="phi-r10-")
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        root.chmod(0o700)
        self.path=root/"operator.sqlite3"
        self.policy=DurableOwnerConsentPolicy(self.path)
        self.signer=ed25519.Ed25519PrivateKey.generate()
        self.policy.register_operator_key(
            operator_id=OPERATOR,kid="key-01",
            public_key=ed25519_public_bytes(self.signer),
        )
        self.now=datetime.now(timezone.utc)
        self.auth=SyntheticAuthenticator()

    def ceremony(self,*,code=PAIRING, operator=OPERATOR):
        return LocalOperatorEnrollment(
            policy=DurableOwnerConsentPolicy(self.path),operator_id=operator,
            pairing_code=code,now=self.now,
        )

    def begin(self, ceremony=None):
        ceremony=ceremony or self.ceremony()
        started=ceremony.begin(pairing_code=PAIRING,now=self.now)
        challenge=decode(started["options"]["challenge"])
        return ceremony,started,challenge

    def verified(self):
        ceremony,started,challenge=self.begin()
        result=ceremony.finish(
            session=started["session"],
            credential=self.auth.registration(challenge),
            now=self.now,
        )
        return ceremony,started,result

    def test_real_rp_verifies_synthetic_registration_and_persists_public_only(self):
        ceremony,started,result=self.verified()
        self.assertEqual(result["enrolled"],True)
        self.assertEqual(result["approval_granted"],False)
        self.assertEqual(result["execution_authority"],False)
        self.assertEqual(started["options"]["rp"]["id"],"localhost")
        self.assertEqual(
            started["options"]["authenticatorSelection"]["userVerification"],
            "required",
        )
        with DurableOwnerConsentPolicy(self.path)._open() as conn:
            row=conn.execute(
                "SELECT operator_id,public_key,sign_count,revoked FROM operator_credentials"
            ).fetchone()
        self.assertEqual(row[0],OPERATOR)
        self.assertEqual(bytes(row[1]),self.auth.cose_public)
        self.assertEqual(row[2],0)
        self.assertEqual(row[3],0)

    def test_registered_passkey_integrates_with_r9_review(self):
        self.verified()
        policy=DurableOwnerConsentPolicy(self.path)
        now=self.now
        req=EffectRequest(
            request_id="r10-verified-bridge",scope="pre_service",
            subject_issuer="http://127.0.0.1:8080/realms/phiid-dev",
            subject_id="synthetic-owner",audience="phicloud-resource-dev",
            action="profile.read",resource="profile:synthetic-self",
        )
        policy.register_synthetic_self(req)
        ticket=policy.stage(req,now=now)
        receipt=sign_review(
            ticket,self.signer,now=now,operator=OPERATOR,kid="key-01",
        )
        challenge=policy.begin_operator_stepup(
            receipt,credential_id=self.auth.credential_id,now=now
        )
        self.assertTrue(policy.approve_signed_with_stepup(
            receipt,self.auth.assertion(challenge,counter=1),now=now,
        ))
        auth,consent=DurableOwnerConsentPolicy(self.path).consume(
            req,now=now,require_signed=True,require_presence=True,
        )
        self.assertEqual(auth.request_id,req.request_id)
        self.assertEqual(consent.resource,"profile:synthetic-self")
        with self.assertRaises(PolicyDenied):
            policy.consume(req,now=now,require_signed=True,require_presence=True)

    def test_duplicate_credential_rejected_after_first_registration(self):
        self.verified()
        new=self.ceremony()
        _,started,challenge=self.begin(new)
        with self.assertRaises(PolicyDenied):
            new.finish(
                session=started["session"],
                credential=self.auth.registration(challenge),now=self.now,
            )

    def test_mismatched_rp_origin_challenge_and_uv_are_denied(self):
        scenarios=(
            {"verified":False},
            {"present":False},
            {"origin":"http://localhost:8888"},
            {"origin":"https://lookalike.invalid"},
            {"rp_id":"another.localhost"},
        )
        for config in scenarios:
            with self.subTest(config=config):
                ceremony,started,challenge=self.begin()
                with self.assertRaises(PolicyDenied):
                    ceremony.finish(
                        session=started["session"],
                        credential=self.auth.registration(challenge,**config),
                        now=self.now,
                    )
                self.assertIsNone(ceremony._pending)
        ceremony,started,challenge=self.begin()
        with self.assertRaises(PolicyDenied):
            ceremony.finish(
                session=started["session"],
                credential=self.auth.registration(secrets.token_bytes(32)),
                now=self.now,
            )

    def test_invalid_pairing_never_registers_and_limits_attempts(self):
        ceremony=self.ceremony()
        for _ in range(MAX_ATTEMPTS):
            with self.assertRaises(PolicyDenied):
                ceremony.begin(pairing_code="wrong!",now=self.now)
        with self.assertRaises(PolicyDenied):
            ceremony.begin(pairing_code=PAIRING,now=self.now)
        with DurableOwnerConsentPolicy(self.path)._open() as conn:
            self.assertEqual(conn.execute(
                "SELECT count(*) FROM operator_credentials"
            ).fetchone()[0],0)

    def test_pairing_challenge_and_session_are_single_use(self):
        ceremony,started,challenge=self.begin()
        with self.assertRaises(PolicyDenied):
            ceremony.begin(pairing_code=PAIRING,now=self.now)
        with self.assertRaises(PolicyDenied):
            ceremony.finish(
                session="incorrect",credential=self.auth.registration(challenge),
                now=self.now,
            )
        with self.assertRaises(PolicyDenied):
            ceremony.finish(
                session=started["session"],
                credential=self.auth.registration(challenge),now=self.now,
            )

    def test_expiry_prevents_enrollment(self):
        c=self.ceremony()
        with self.assertRaises(PolicyDenied):
            c.begin(pairing_code=PAIRING,now=self.now+timedelta(minutes=6))
        ceremony,started,challenge=self.begin()
        with self.assertRaises(PolicyDenied):
            ceremony.finish(
                session=started["session"],
                credential=self.auth.registration(challenge),
                now=self.now+timedelta(minutes=3),
            )

    def test_revoked_signer_cannot_initialize_or_enroll(self):
        self.policy.revoke_operator_key(operator_id=OPERATOR,kid="key-01")
        with self.assertRaises(PolicyDenied):
            self.ceremony()

    def test_invalid_operator_and_untrusted_policy_rejected(self):
        with self.assertRaises(PolicyDenied):
            self.ceremony(operator="not-enrolled")
        with self.assertRaises(PolicyDenied):
            LocalOperatorEnrollment(
                policy=None,operator_id=OPERATOR,
                pairing_code=PAIRING,now=self.now,
            )

    def test_duplicate_json_fields_and_long_input_denied(self):
        for data in (b'{"code":"a","code":"b"}',b"[]",b"x"*20000):
            with self.subTest(data=data[:20]),self.assertRaises(PolicyDenied):
                _json_object(data)

    def test_http_origin_host_and_csrf_fail_closed(self):
        ceremony=self.ceremony()
        server=OneShotServer(("127.0.0.1",0),handler_factory(ceremony))
        thread=threading.Thread(target=server.serve_forever,daemon=True)
        thread.start()
        try:
            def request(method,path,body=None,headers=None):
                conn=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=4)
                headers=headers or {}
                conn.request(method,path,body=body,headers=headers)
                response=conn.getresponse()
                data=response.read()
                code=response.status
                conn.close()
                return code,data
            s,_=request("GET","/",headers={"Host":"attacker.example:8769"})
            self.assertEqual(s,403)
            bad_body=json.dumps({"code":PAIRING}).encode()
            s,_=request("POST","/v1/enroll/start",bad_body,headers={
                "Host":"localhost:8769",
                "Origin":"http://malicious.invalid",
                "Content-Type":"application/json",
            })
            self.assertEqual(s,403)
            s,_=request("POST","/v1/enroll/start",bad_body,headers={
                "Host":"localhost:8769",
                "Content-Type":"application/json",
            })
            self.assertEqual(s,403)
            s,data=request("GET","/",headers={"Host":"localhost:8769"})
            self.assertEqual(s,200)
            self.assertIn(b"Local Passkey Enrollment",data)
            self.assertNotIn(PAIRING.encode(),data)
        finally:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()


if __name__=="__main__":
    unittest.main()
