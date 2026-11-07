"""R4 identity -> PhiShield unit fixtures, not actual Keycloak credentials.

Real disposable-Keycloak integration runs separately in keycloak-authz CI.
"""
from __future__ import annotations

import json
import secrets
import time
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone

from phicloud.authz import (
    AUDIENCE, ISSUER, REQUIRED_SCOPE,
    AuthorizationDenied, AuthorizationUnavailable, LocalTokenIntrospector,
)
from phicloud.shield_identity import (
    ACTION, RESOURCE, SCOPE, PRODUCER,
    evaluate_verified_profile_candidate, verified_profile_request,
)
from phicloud.shield_policy import ANC_SCHEMA, ConsentEvidence, EffectRequest
from phicloud.shield_transport import LocalReplayCache, sign_local_advisory

TOKEN = "synthetic-token-" + "x" * 32
SECRET = "unit-test-introspection-secret-" + "x" * 32
KID = "local-test-key"


def claims(*, sub="fixture-subject", **changes):
    result = {
        "active": True, "iss": ISSUER, "sub": sub, "aud": [AUDIENCE],
        "scope": "openid " + REQUIRED_SCOPE, "token_type": "Bearer",
        "exp": int(time.time()) + 300,
        "nbf": int(time.time()) - 1,
    }
    return dict(result, **changes)


def make_introspector(result):
    def transport(token, secret):
        if token != TOKEN or secret != SECRET:
            raise AuthorizationDenied("not_the_fixture_token")
        return result
    return LocalTokenIntrospector(SECRET, transport=transport)


def clean_risk(request: EffectRequest, now: datetime):
    return {
        "schema": ANC_SCHEMA, "request_id": request.request_id,
        "scope": request.scope, "posture": "safe",
        "recommended_action": "allow", "signal_count": 0,
        "weakest_face": "foundation", "weakest_face_score": 0.95,
        "anchor_integrity": 0.90, "observed_at": now.isoformat(),
        "not_after": (now + timedelta(seconds=20)).isoformat(),
        "authority_granted": False,
    }


class VerifiedIdentityShieldBridgeTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.key = secrets.token_bytes(32)
        self.keys = {(PRODUCER, KID): self.key}
        self.cache = LocalReplayCache()
        self.introspector = make_introspector(claims())
        self.request = verified_profile_request(
            TOKEN, introspector=self.introspector, request_id="r4-identity-test"
        )

    def envelope(self, request=None, payload=None):
        request = request or self.request
        return sign_local_advisory(
            payload or clean_risk(request, self.now),
            request=request, producer_id=PRODUCER, kid=KID,
            secret=self.key, now=self.now,
        )

    def consent(self, request, now):
        return ConsentEvidence(
            **asdict(request), not_after=(now + timedelta(seconds=10)).isoformat()
        )

    def evaluate(self, envelope=None, **kwargs):
        options = {
            "request_id": self.request.request_id, "introspector": self.introspector,
            "token": TOKEN, "envelope": envelope if envelope is not None else self.envelope(),
            "trusted_keys": self.keys, "replay_cache": self.cache,
            "consent_provider": self.consent, "now": self.now,
        }
        options.update(kwargs)
        return evaluate_verified_profile_candidate(**options)

    def test_verified_principal_is_exact_profile_scope(self):
        req = self.request
        self.assertEqual(req.subject_issuer, ISSUER)
        self.assertEqual(req.subject_id, "fixture-subject")
        self.assertEqual(req.audience, AUDIENCE)
        self.assertEqual((req.action, req.resource, req.scope), (ACTION, RESOURCE, SCOPE))

    def test_token_and_authenticated_anc_with_independent_consent_only_candidate(self):
        outcome = self.evaluate()
        self.assertEqual(outcome.disposition, "CANDIDATE")
        self.assertFalse(outcome.authoritative)
        serialized = json.dumps(asdict(outcome))
        self.assertNotIn("fixture-subject", serialized)
        self.assertNotIn(TOKEN, serialized)

    def test_login_without_independent_consent_never_candidate(self):
        env = self.envelope()
        self.assertEqual(self.evaluate(env, consent_provider=None).disposition, "DENY")
        self.assertEqual(self.evaluate(env, consent_provider=lambda req, now: True).disposition, "DENY")
        self.assertEqual(self.evaluate(env, consent_provider=lambda req, now: {"yes": True}).disposition, "DENY")

    def test_consent_must_match_exact_principal_and_action(self):
        env = self.envelope()
        for field, value in (
            ("subject_id", "another"), ("subject_issuer", "https://other.invalid"),
            ("action", "service.delete"), ("resource", "mail:inbox"),
            ("audience", "phimail-bff-dev"), ("request_id", "wrong"),
            ("scope", "memory_write"),
        ):
            with self.subTest(field=field):
                def wrong(req, now):
                    return replace(self.consent(req, now), **{field: value})
                self.assertEqual(
                    self.evaluate(env, consent_provider=wrong).disposition, "DENY"
                )

    def test_provider_unavailable_and_missing_token_fail_closed(self):
        def offline(token, secret):
            raise OSError("Keycloak offline")
        offline_introspector = LocalTokenIntrospector(SECRET, transport=offline)
        self.assertEqual(self.evaluate(introspector=offline_introspector).disposition, "DENY")
        for token in ("", "not-a-real-token", "x" * 40, None):
            with self.subTest(token=token):
                self.assertEqual(self.evaluate(token=token).disposition, "DENY")

    def test_wrong_issuer_audience_scope_expiry_and_inactive_denied(self):
        bads = [
            claims(iss="https://other.example.invalid"),
            claims(aud=["phimail-bff-dev"]),
            claims(scope="openid profile"),
            claims(scope="phicloud.profile.read-all"),
            claims(exp=int(time.time()) - 10),
            claims(active=False),
            claims(sub=""),
            claims(token_type="refresh_token"),
        ]
        for response in bads:
            with self.subTest(claim=response):
                self.assertEqual(
                    self.evaluate(introspector=make_introspector(response)).disposition,
                    "DENY",
                )

    def test_swapping_verified_principal_does_not_reuse_signed_risk(self):
        # OIDC introspection succeeds for a DIFFERENT actual identity.
        # An identical request ID cannot move a signature to that person.
        other = make_introspector(claims(sub="another-verified-subject"))
        self.assertEqual(
            self.evaluate(envelope=self.envelope(), introspector=other).disposition,
            "DENY",
        )

    def test_different_nonce_for_each_attempt_and_replay_denied(self):
        env = self.envelope()
        self.assertEqual(self.evaluate(env).disposition, "CANDIDATE")
        self.assertEqual(self.evaluate(env).disposition, "DENY")

    def test_risk_not_signed_or_high_risk_never_candidate(self):
        for env in (clean_risk(self.request, self.now), dict(self.envelope(), mac="0" * 64)):
            with self.subTest(env=env):
                self.assertEqual(self.evaluate(env).disposition, "DENY")
        hostile = clean_risk(self.request, self.now)
        hostile["posture"] = "hostile"
        hostile["recommended_action"] = "refuse"
        hostile["signal_count"] = 1
        self.assertEqual(self.evaluate(self.envelope(payload=hostile)).disposition, "DENY")

    def test_consent_service_error_is_denial(self):
        def provider_failure(req, now):
            raise RuntimeError("verification backend unavailable")
        self.assertEqual(
            self.evaluate(consent_provider=provider_failure).disposition, "DENY"
        )

    def test_untrusted_introspector_object_is_not_accepted(self):
        class Fake:
            def authorize(self, token):
                return self.request
        with self.assertRaises(AuthorizationDenied):
            verified_profile_request(
                TOKEN, introspector=Fake(), request_id=self.request.request_id
            )


if __name__ == "__main__":
    unittest.main()
