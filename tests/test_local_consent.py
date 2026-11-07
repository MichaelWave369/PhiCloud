"""R5 exact-profile ownership and explicit local review contract tests.

These are trusted-process unit fixtures. They do not prove real human
presence, persistence, cryptographic consent, or secure remote authorization.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from io import StringIO
import secrets
import time
import unittest

from phicloud.authz import (
    AUDIENCE, ISSUER, REQUIRED_SCOPE, AuthorizationDenied, LocalTokenIntrospector,
)
from phicloud.local_consent import (
    LocalOwnerConsentPolicy, PolicyDenied, operator_console_review,
)
from phicloud.shield_identity import (
    PRODUCER, evaluate_reviewed_profile_candidate, stage_verified_profile_review,
)
from phicloud.shield_policy import ANC_SCHEMA
from phicloud.shield_transport import LocalReplayCache, sign_local_advisory

TOKEN = "r5-test-access-token-" + "x" * 40
SECRET = "r5-test-introspector-" + "s" * 40
KID = "r5-key"


def mock_introspector(*, subject="owner-369", active=True, scope=None, audience=None):
    def verify(token, secret):
        if token != TOKEN or secret != SECRET:
            raise AuthorizationDenied("unrecognized_token")
        return {
            "active": active, "iss": ISSUER, "sub": subject,
            "aud": [AUDIENCE if audience is None else audience],
            "scope": "openid " + (REQUIRED_SCOPE if scope is None else scope),
            "token_type": "Bearer", "exp": int(time.time()) + 300,
            "nbf": int(time.time()) - 1,
        }
    return LocalTokenIntrospector(SECRET, transport=verify)


def anc_risk(request, now, *, posture="safe", action="allow", signals=0):
    return {
        "schema": ANC_SCHEMA, "request_id": request.request_id,
        "scope": request.scope, "posture": posture,
        "recommended_action": action, "signal_count": signals,
        "weakest_face": "foundation", "weakest_face_score": 0.9,
        "anchor_integrity": 0.9, "observed_at": now.isoformat(),
        "not_after": (now + timedelta(seconds=28)).isoformat(),
        "authority_granted": False,
    }


class OwnerConsentTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.policy = LocalOwnerConsentPolicy()
        self.introspector = mock_introspector()
        self.secret = secrets.token_bytes(32)
        self.keys = {(PRODUCER, KID): self.secret}
        self.replay = LocalReplayCache()

    def stage(self, request_id="r5-369", **kwargs):
        return stage_verified_profile_review(
            TOKEN, request_id=request_id,
            introspector=kwargs.get("introspector", self.introspector),
            policy=kwargs.get("policy", self.policy), now=self.now,
        )

    def sign(self, req, **risk_kwargs):
        return sign_local_advisory(
            anc_risk(req, self.now, **risk_kwargs),
            request=req, producer_id=PRODUCER, kid=KID,
            secret=self.secret, now=self.now,
        )

    def decide(self, request_id, envelope, **overrides):
        opts = {
            "token": TOKEN, "request_id": request_id,
            "introspector": self.introspector,
            "policy": self.policy, "envelope": envelope,
            "trusted_keys": self.keys, "replay_cache": self.replay,
            "now": self.now,
        }
        opts.update(overrides)
        return evaluate_reviewed_profile_candidate(**opts)

    def approve(self, ticket):
        return self.policy.approve(
            ticket.review_id, shown_request=ticket.request,
            acknowledged=True, now=self.now,
        )

    def test_freshly_verified_owner_explicit_approval_only_candidate(self):
        ticket = self.stage()
        self.assertTrue(self.approve(ticket))
        outcome = self.decide(ticket.request.request_id, self.sign(ticket.request))
        self.assertEqual(outcome.disposition, "CANDIDATE")
        self.assertFalse(outcome.authoritative)

    def test_login_without_review_denied(self):
        ticket = self.stage()
        self.assertEqual(
            self.decide(ticket.request.request_id, self.sign(ticket.request)).disposition,
            "DENY",
        )

    def test_decline_and_wrong_acknowledgment_deny(self):
        for decision in (False, "true", None):
            with self.subTest(decision=decision):
                ticket = self.stage(secrets.token_hex(10))
                self.assertFalse(self.policy.approve(
                    ticket.review_id, shown_request=ticket.request,
                    acknowledged=decision, now=self.now,
                ))
                self.assertEqual(
                    self.decide(ticket.request.request_id, self.sign(ticket.request)).disposition,
                    "DENY",
                )

    def test_exact_request_review_and_one_use(self):
        ticket = self.stage()
        tampered = replace(ticket.request, action="profile.delete")
        self.assertFalse(self.policy.approve(
            ticket.review_id, shown_request=tampered,
            acknowledged=True, now=self.now,
        ))
        self.assertFalse(self.approve(ticket), "a rejected review must be consumed")
        self.assertEqual(self.decide(ticket.request.request_id, self.sign(ticket.request)).disposition, "DENY")

    def test_revision_of_request_id_fails_closed(self):
        ticket = self.stage()
        self.assertTrue(self.approve(ticket))
        with self.assertRaises(PolicyDenied):
            self.stage(ticket.request.request_id)
        envelope = self.sign(ticket.request)
        self.assertEqual(self.decide(ticket.request.request_id, envelope).disposition, "CANDIDATE")
        self.assertEqual(self.decide(ticket.request.request_id, envelope).disposition, "DENY")

    def test_cross_subject_mismatched_identity_does_not_consume_owner_review(self):
        ticket = self.stage()
        self.assertTrue(self.approve(ticket))
        other_user = mock_introspector(subject="not-the-owner")
        env = self.sign(ticket.request)
        self.assertEqual(
            self.decide(ticket.request.request_id, env, introspector=other_user).disposition,
            "DENY",
        )
        self.assertEqual(self.decide(ticket.request.request_id, env).disposition, "CANDIDATE")

    def test_owner_revocation_invalidates_pending_and_approved(self):
        first = self.stage("first-review")
        second = self.stage("second-review")
        self.assertTrue(self.approve(first))
        self.policy.revoke_owner(issuer=ISSUER, sub=first.request.subject_id)
        self.assertFalse(self.approve(second))
        self.assertEqual(self.decide(first.request.request_id, self.sign(first.request)).disposition, "DENY")
        with self.assertRaises(PolicyDenied):
            self.policy.consume(first.request, now=self.now)

    def test_keycloak_revocation_and_provider_unavailability_deny(self):
        ticket = self.stage()
        self.assertTrue(self.approve(ticket))
        dead = mock_introspector(active=False)
        result = self.decide(
            ticket.request.request_id,
            self.sign(ticket.request),
            introspector=dead,
        )
        self.assertEqual(result.disposition, "DENY")
        # A later trusted introspection succeeds; revoked test result was
        # never allowed to consume the owner's pending local approval.
        self.assertEqual(
            self.decide(ticket.request.request_id, self.sign(ticket.request)).disposition,
            "CANDIDATE",
        )

    def test_wrong_scope_audience_and_unsupported_resource_denied(self):
        for fake in (
            mock_introspector(scope="phicloud.profile.read-all"),
            mock_introspector(audience="phimail-bff-dev"),
        ):
            with self.subTest(fake=fake):
                with self.assertRaises(AuthorizationDenied):
                    self.stage(secrets.token_hex(8), introspector=fake)
        ticket = self.stage("limited-action")
        for changed in (
            replace(ticket.request, action="file.write"),
            replace(ticket.request, resource="mail:inbox"),
            replace(ticket.request, audience="phimail-bff-dev"),
        ):
            with self.subTest(request=changed), self.assertRaises(PolicyDenied):
                self.policy.register_synthetic_self(changed)
        # A trusted service may register another synthetic self-owner;
        # it must NOT be able to consume a different owner's review.
        other_owner = replace(ticket.request, subject_id="other-person")
        with self.assertRaises(PolicyDenied):
            self.policy.consume(other_owner, now=self.now)
        self.assertTrue(self.approve(ticket))
        with self.assertRaises(PolicyDenied):
            self.policy.consume(other_owner, now=self.now)
        self.assertEqual(
            self.decide(ticket.request.request_id, self.sign(ticket.request)).disposition,
            "CANDIDATE",
        )

    def test_expiry_denies_pending_and_approved(self):
        pending = self.stage("pending-expiry")
        self.assertFalse(self.policy.approve(
            pending.review_id, shown_request=pending.request,
            acknowledged=True, now=self.now + timedelta(seconds=61),
        ))
        approved = self.stage("approved-expiry")
        self.assertTrue(self.approve(approved))
        with self.assertRaises(PolicyDenied):
            self.policy.consume(
                approved.request, now=self.now + timedelta(seconds=31)
            )

    def test_high_risk_invalid_mac_and_wrong_resource_remain_denied(self):
        for index, kind in enumerate(("hostile", "tampered", "mismatch")):
            ticket = self.stage(f"risk-{index}")
            self.assertTrue(self.approve(ticket))
            envelope = self.sign(
                ticket.request,
                **({"posture":"hostile","action":"refuse","signals":1} if kind=="hostile" else {})
            )
            if kind == "tampered":
                envelope = {**envelope, "mac": "0" * 64}
            if kind == "mismatch":
                envelope = self.sign(replace(ticket.request, request_id="different"))
            result = self.decide(ticket.request.request_id, envelope)
            self.assertEqual(result.disposition, "DENY")
            self.assertFalse(result.authoritative)
            # Consent is spent even on a denied risk evaluation.
            self.assertEqual(self.decide(ticket.request.request_id, self.sign(ticket.request)).disposition, "DENY")

    def test_console_acknowledgment_requires_exact_text(self):
        denied = self.stage("console-no")
        self.assertFalse(operator_console_review(
            self.policy, denied, now=self.now,
            input_stream=StringIO("yes\n"), output_stream=StringIO(),
        ))
        approved = self.stage("console-yes")
        out = StringIO()
        self.assertTrue(operator_console_review(
            self.policy, approved, now=self.now,
            input_stream=StringIO("APPROVE console-yes\n"), output_stream=out,
        ))
        self.assertIn("profile:synthetic-self", out.getvalue())
        self.assertIn("APPROVE console-yes", out.getvalue())
        self.assertEqual(
            self.decide(approved.request.request_id, self.sign(approved.request)).disposition,
            "CANDIDATE",
        )

    def test_concurrent_approval_consumption_only_one_candidate(self):
        ticket = self.stage("race-single-use")
        self.assertTrue(self.approve(ticket))
        # Independent signed envelopes use different nonces, but just one
        # operator-reviewed action exists.
        envelopes = [self.sign(ticket.request) for _ in range(12)]
        with ThreadPoolExecutor(max_workers=6) as pool:
            outcomes = list(pool.map(
                lambda env: self.decide(ticket.request.request_id, env).disposition,
                envelopes,
            ))
        self.assertEqual(outcomes.count("CANDIDATE"), 1)
        self.assertEqual(outcomes.count("DENY"), 11)

    def test_capacity_exhaustion_denies_instead_of_recycling(self):
        ledger = LocalOwnerConsentPolicy(capacity=1)
        self.stage("one", policy=ledger)
        with self.assertRaises(PolicyDenied):
            self.stage("two", policy=ledger)


if __name__ == "__main__":
    unittest.main()
