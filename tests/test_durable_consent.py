"""R6 SQLite ledger: durable revocation, exact binding and one-use tests."""
from __future__ import annotations

import os
import secrets
import stat
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

from phicloud.authz import AUDIENCE, ISSUER, REQUIRED_SCOPE, LocalTokenIntrospector
from phicloud.durable_consent import DurableOwnerConsentPolicy
from phicloud.local_consent import PolicyDenied, operator_console_review
from phicloud.shield_identity import (
    PRODUCER, stage_verified_profile_review, evaluate_reviewed_profile_candidate,
)
from phicloud.shield_policy import ANC_SCHEMA, EffectRequest
from phicloud.shield_transport import LocalReplayCache, sign_local_advisory

TOKEN = "fixture-access-" + "x" * 40
SECRET = "fixture-secret-" + "s" * 40


def request(request_id="r6-001", subject="owner-a"):
    return EffectRequest(
        request_id=request_id, scope="pre_service", subject_issuer=ISSUER,
        subject_id=subject, audience=AUDIENCE, action="profile.read",
        resource="profile:synthetic-self",
    )


def introspector():
    def backend(token, secret):
        if token != TOKEN or secret != SECRET:
            raise RuntimeError("bad fixture token")
        return {
            "active": True, "iss": ISSUER, "sub": "owner-a",
            "aud": [AUDIENCE], "scope": REQUIRED_SCOPE,
            "exp": int(time.time()) + 300, "nbf": int(time.time()) - 1,
            "token_type": "Bearer",
        }
    return LocalTokenIntrospector(SECRET,transport=backend)


class DurableOwnerConsentTests(unittest.TestCase):
    def setUp(self):
        if os.name != "posix":
            self.skipTest("POSIX private storage required")
        self.temp = tempfile.TemporaryDirectory(prefix="phicloud-r6-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.folder.chmod(0o700)
        self.path = self.folder / "consent.sqlite3"
        self.policy = DurableOwnerConsentPolicy(self.path)
        self.now = datetime.now(timezone.utc)
        self.req = request()

    def fresh(self):
        return DurableOwnerConsentPolicy(self.path)

    def stage(self, req=None):
        req = req or self.req
        self.policy.register_synthetic_self(req)
        return self.policy.stage(req,now=self.now)

    def approve(self, req=None):
        ticket = self.stage(req)
        self.assertTrue(self.policy.approve(
            ticket.review_id,shown_request=ticket.request,
            acknowledged=True,now=self.now,
        ))
        return ticket

    def test_restart_and_one_use(self):
        ticket = self.approve()
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)
        evidence = self.fresh().consume(ticket.request,now=self.now)
        self.assertEqual(evidence[0].subject_id,"owner-a")
        self.assertEqual(evidence[1].resource,"profile:synthetic-self")
        with self.assertRaises(PolicyDenied):
            self.fresh().consume(ticket.request,now=self.now)

    def test_pending_review_can_be_approved_after_restart(self):
        ticket = self.stage()
        fresh = self.fresh()
        self.assertTrue(fresh.approve(
            ticket.review_id,shown_request=ticket.request,
            acknowledged=True,now=self.now,
        ))
        fresh.consume(ticket.request,now=self.now)

    def test_decline_and_expiry_burn_replay_state(self):
        first = self.stage(request("r6-deny"))
        self.assertFalse(self.fresh().approve(
            first.review_id,shown_request=first.request,
            acknowledged=False,now=self.now,
        ))
        self.assertFalse(self.fresh().approve(
            first.review_id,shown_request=first.request,
            acknowledged=True,now=self.now,
        ))
        second = self.approve(request("r6-expire"))
        with self.assertRaises(PolicyDenied):
            self.fresh().consume(second.request,now=self.now+timedelta(seconds=31))
        with self.assertRaises(PolicyDenied):
            self.fresh().consume(second.request,now=self.now)

    def test_owner_and_effect_substitution_denied(self):
        ticket = self.approve()
        variants = (
            replace(ticket.request,subject_id="owner-b"),
            replace(ticket.request,action="file.write"),
            replace(ticket.request,resource="mail:inbox"),
            replace(ticket.request,request_id="different"),
            replace(ticket.request,audience="phimail-bff-dev"),
        )
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(PolicyDenied):
                self.fresh().consume(changed,now=self.now)
        self.fresh().consume(ticket.request,now=self.now)

    def test_owner_revocation_persists_and_cannot_auto_restore(self):
        ticket = self.approve()
        self.fresh().revoke_owner(issuer=ISSUER,sub="owner-a")
        for operation in (
            lambda: self.fresh().consume(ticket.request,now=self.now),
            lambda: self.fresh().register_synthetic_self(ticket.request),
            lambda: self.fresh().stage(ticket.request,now=self.now),
        ):
            with self.assertRaises(PolicyDenied):
                operation()

    def test_unknown_owner_tombstone_prevents_future_registration(self):
        other = request("unknown",subject="later-owner")
        self.policy.revoke_owner(issuer=ISSUER,sub=other.subject_id)
        with self.assertRaises(PolicyDenied):
            self.fresh().register_synthetic_self(other)

    def test_id_tombstone_survives_restart(self):
        ticket = self.approve()
        self.fresh().consume(ticket.request,now=self.now)
        with self.assertRaises(PolicyDenied):
            self.fresh().stage(ticket.request,now=self.now+timedelta(seconds=300))

    def test_concurrent_independent_connections_only_one_accepts(self):
        ticket = self.approve()
        instances = [self.fresh() for _ in range(12)]
        def try_consume(policy):
            try:
                policy.consume(ticket.request,now=self.now)
                return "candidate"
            except PolicyDenied:
                return "deny"
        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(try_consume,instances))
        self.assertEqual(results.count("candidate"),1)
        self.assertEqual(results.count("deny"),11)

    def test_capacity_and_file_safety(self):
        limited = DurableOwnerConsentPolicy(self.folder/"small.sqlite3",capacity=2)
        limited.register_synthetic_self(self.req)
        limited.stage(self.req,now=self.now)
        limited.stage(request("another"),now=self.now)
        with self.assertRaises(PolicyDenied):
            limited.stage(request("third"),now=self.now)
        bad = self.folder/"bad.sqlite3"
        bad.write_text("bad data")
        bad.chmod(0o644)
        with self.assertRaises(ValueError):
            DurableOwnerConsentPolicy(bad)
        link = self.folder/"linked.sqlite3"
        link.symlink_to(self.path)
        with self.assertRaises(ValueError):
            DurableOwnerConsentPolicy(link)

    def test_missing_file_is_fail_closed(self):
        self.approve()
        self.path.unlink()
        with self.assertRaises(PolicyDenied):
            self.policy.consume(self.req,now=self.now)

    def test_bridge_uses_durable_review_not_client_boolean(self):
        gate = introspector()
        ticket = stage_verified_profile_review(
            TOKEN,request_id="r6-bridge",introspector=gate,
            policy=self.policy,now=self.now,
        )
        self.assertTrue(operator_console_review(
            self.fresh(),ticket,now=self.now,
            input_stream=StringIO("APPROVE r6-bridge\n"),
            output_stream=StringIO(),
        ))
        req = ticket.request
        risk = {
            "schema":ANC_SCHEMA,"request_id":req.request_id,
            "scope":req.scope,"posture":"safe","recommended_action":"allow",
            "signal_count":0,"weakest_face":"foundation",
            "weakest_face_score":0.9,"anchor_integrity":0.9,
            "observed_at":self.now.isoformat(),
            "not_after":(self.now+timedelta(seconds=25)).isoformat(),
            "authority_granted":False,
        }
        key = secrets.token_bytes(32)
        envelope = sign_local_advisory(
            risk,request=req,producer_id=PRODUCER,kid="r6-key",
            secret=key,now=self.now,
        )
        opts = {
            "token":TOKEN,"request_id":req.request_id,
            "introspector":gate,"policy":self.fresh(),
            "envelope":envelope,"trusted_keys":{(PRODUCER,"r6-key"):key},
            "replay_cache":LocalReplayCache(),"now":self.now,
        }
        outcome = evaluate_reviewed_profile_candidate(**opts)
        self.assertEqual(outcome.disposition,"CANDIDATE")
        self.assertFalse(outcome.authoritative)
        self.assertEqual(evaluate_reviewed_profile_candidate(**opts).disposition,"DENY")


if __name__=="__main__":
    unittest.main()
