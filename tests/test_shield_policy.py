"""PhiCloud PhiShield R0: independent authority/consent AND ANC advisory gates."""
from __future__ import annotations

import json
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone

from phicloud.shield_policy import (
    ANC_SCHEMA, AuthorityEvidence, ConsentEvidence, EffectRequest,
    evaluate_candidate,
)

NOW = datetime(2026, 11, 6, 23, 0, tzinfo=timezone.utc)


def iso(offset: int) -> str:
    return (NOW + timedelta(seconds=offset)).isoformat()


def effect() -> EffectRequest:
    return EffectRequest(
        request_id="req-369", scope="pre_service",
        subject_issuer="https://phiid.example.invalid/realms/phi",
        subject_id="test-subject-369", audience="phicloud-test",
        action="service.execute", resource="service:echo",
    )


def authority(request=None):
    request = request or effect()
    return AuthorityEvidence(**asdict(request), not_after=iso(90))


def consent(request=None):
    request = request or effect()
    return ConsentEvidence(**asdict(request), not_after=iso(90))


def anc(request=None):
    request = request or effect()
    return {
        "schema": ANC_SCHEMA,
        "request_id": request.request_id,
        "scope": request.scope,
        "posture": "safe",
        "recommended_action": "allow",
        "signal_count": 0,
        "weakest_face": "foundation",
        "weakest_face_score": 0.85,
        "anchor_integrity": 0.90,
        "observed_at": iso(0),
        "not_after": iso(30),
        "authority_granted": False,
    }


def gate(request=None, *, auth=None, receipt=None, risk=None, at=None):
    request = request or effect()
    return evaluate_candidate(
        request, authority=auth if auth is not None else authority(request),
        consent=receipt if receipt is not None else consent(request),
        anc_advisory=risk if risk is not None else anc(request),
        now=at or NOW,
    )


class ShieldPolicyR0Tests(unittest.TestCase):
    def test_clean_request_is_candidate_only_never_grant(self):
        decision = gate()
        self.assertEqual(decision.disposition, "CANDIDATE")
        self.assertFalse(decision.authoritative)
        self.assertNotEqual(decision.disposition, "ALLOW")

    def test_empty_or_missing_authority_is_denied(self):
        request = effect()
        for invalid in (None, {}, "true", consent()):
            with self.subTest(invalid=invalid):
                result = evaluate_candidate(
                    request, authority=invalid, consent=consent(),
                    anc_advisory=anc(), now=NOW,
                )
                self.assertEqual(result.disposition, "DENY")
                self.assertFalse(result.authoritative)

    def test_missing_consent_is_denied(self):
        result = evaluate_candidate(
            effect(), authority=authority(), consent=None,
            anc_advisory=anc(), now=NOW,
        )
        self.assertEqual(result.disposition, "DENY")

    def test_grant_must_match_all_request_dimensions(self):
        req = effect()
        for key, bad in (
            ("subject_issuer", "https://wrong.example.invalid"),
            ("subject_id", "different-subject"),
            ("audience", "another-service"),
            ("action", "service.delete"),
            ("resource", "service:other"),
            ("request_id", "req-370"),
            ("scope", "memory_write"),
        ):
            with self.subTest(dimension=key):
                wrong_grant = replace(authority(req), **{key: bad})
                result = evaluate_candidate(
                    req, authority=wrong_grant, consent=consent(req),
                    anc_advisory=anc(req), now=NOW,
                )
                self.assertEqual(result.disposition, "DENY")

    def test_consent_must_match_all_request_dimensions(self):
        req = effect()
        for key in ("subject_id", "resource", "action", "request_id", "scope"):
            with self.subTest(dimension=key):
                wrong_consent = replace(consent(req), **{key: "other"})
                result = evaluate_candidate(
                    req, authority=authority(req), consent=wrong_consent,
                    anc_advisory=anc(req), now=NOW,
                )
                self.assertEqual(result.disposition, "DENY")

    def test_expired_independent_contexts_fail_closed(self):
        req = effect()
        for grant, approval in (
            (replace(authority(req), not_after=iso(-1)), consent(req)),
            (authority(req), replace(consent(req), not_after=iso(0))),
            (replace(authority(req), not_after="not-a-time"), consent(req)),
        ):
            with self.subTest(grant=grant, approval=approval):
                self.assertEqual(
                    evaluate_candidate(
                        req, authority=grant, consent=approval,
                        anc_advisory=anc(req), now=NOW,
                    ).disposition,
                    "DENY",
                )

    def test_no_anc_advisory_is_denied(self):
        req = effect()
        result = evaluate_candidate(
            req, authority=authority(req), consent=consent(req),
            anc_advisory=None, now=NOW,
        )
        self.assertEqual(result.disposition, "DENY")

    def test_replayed_request_id_or_scope_is_denied(self):
        for key, value in (("request_id", "different"), ("scope", "memory_write")):
            with self.subTest(field=key):
                payload = dict(anc(), **{key: value})
                self.assertEqual(gate(risk=payload).disposition, "DENY")

    def test_stale_future_and_excessive_anc_lifetime_denied(self):
        variants = [
            dict(anc(), not_after=iso(-1)),
            dict(anc(), observed_at=iso(6), not_after=iso(30)),
            dict(anc(), not_after=iso(121)),
            dict(anc(), observed_at=iso(30), not_after=iso(0)),
            dict(anc(), observed_at="broken"),
        ]
        for payload in variants:
            with self.subTest(payload=payload):
                self.assertEqual(gate(risk=payload).disposition, "DENY")

    def test_unknown_schema_fake_authority_extra_fields_and_invalid_numbers_denied(self):
        variants = [
            dict(anc(), schema="phicloud.shield.v999"),
            dict(anc(), authority_granted=True),
            dict(anc(), authority_granted="false"),
            dict(anc(), token="do-not-ever-forward"),
            dict(anc(), signal_count=True),
            dict(anc(), signal_count=-1),
            dict(anc(), weakest_face_score=float("nan")),
            dict(anc(), anchor_integrity=float("inf")),
            dict(anc(), weakest_face="unknown"),
            dict(anc(), posture=["safe"]),
        ]
        for payload in variants:
            with self.subTest(payload=payload):
                self.assertEqual(gate(risk=payload).disposition, "DENY")

    def test_high_risk_veto_and_uncertain_risk_review(self):
        for posture, action in (
            ("hostile", "allow"),
            ("quarantined", "allow"),
            ("safe", "quarantine"),
            ("safe", "seal"),
            ("safe", "refuse"),
        ):
            with self.subTest(posture=posture, action=action):
                self.assertEqual(
                    gate(risk=dict(anc(), posture=posture, recommended_action=action)).disposition,
                    "DENY",
                )
        for posture, action, count in (
            ("watch", "warn", 1),
            ("degraded", "sandbox", 2),
            ("safe", "allow", 1),
            ("safe", "warn", 0),
        ):
            with self.subTest(posture=posture, action=action, count=count):
                self.assertEqual(
                    gate(risk=dict(anc(), posture=posture, recommended_action=action, signal_count=count)).disposition,
                    "REVIEW",
                )

    def test_invalid_request_and_unverified_offline_context(self):
        cases = [
            replace(effect(), request_id=" "),
            replace(effect(), scope="unknown"),
            replace(effect(), action="service execute"),
            replace(effect(), subject_id=""),
        ]
        for req in cases:
            with self.subTest(req=req):
                self.assertEqual(gate(request=req).disposition, "DENY")

    def test_reference_does_not_forward_identity_or_sensitive_evidence(self):
        result = gate()
        result_bytes = json.dumps(asdict(result))
        self.assertNotIn(effect().subject_id, result_bytes)
        self.assertNotIn(effect().subject_issuer, result_bytes)
        self.assertNotIn(effect().resource, result_bytes)
        self.assertNotIn("token", result_bytes)


if __name__ == "__main__":
    unittest.main()
