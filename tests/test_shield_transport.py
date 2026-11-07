"""Local authenticated ANC advisory tests: no account or network privileges."""
import copy
import json
import secrets
import unittest
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone

from phicloud.shield_policy import (
    ANC_SCHEMA, AuthorityEvidence, ConsentEvidence, EffectRequest,
)
from phicloud.shield_transport import (
    LocalReplayCache, evaluate_authenticated_candidate, parse_envelope_json,
    sign_local_advisory, verify_local_advisory,
)

NOW = datetime(2026, 11, 6, 23, 0, tzinfo=timezone.utc)
PRODUCER = "anc-local"
KID = "key1"


def iso(seconds):
    return (NOW + timedelta(seconds=seconds)).isoformat()


def request():
    return EffectRequest(
        request_id="one-request", scope="pre_service",
        subject_issuer="https://phiid.example.invalid",
        subject_id="one-test-subject", audience="phicloud-local",
        action="service.execute", resource="service:example",
    )


def risk(req=None, **overrides):
    req = req or request()
    payload = {
        "schema": ANC_SCHEMA, "request_id": req.request_id, "scope": req.scope,
        "posture": "safe", "recommended_action": "allow", "signal_count": 0,
        "weakest_face": "foundation", "weakest_face_score": 0.85,
        "anchor_integrity": 0.9, "observed_at": iso(0),
        "not_after": iso(45), "authority_granted": False,
    }
    return dict(payload, **overrides)


class AuthenticatedAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.secret = secrets.token_bytes(32)  # ephemeral test key, never committed
        self.keys = {(PRODUCER, KID): self.secret}
        self.cache = LocalReplayCache()
        self.req = request()
        self.auth = AuthorityEvidence(**asdict(self.req), not_after=iso(45))
        self.consent = ConsentEvidence(**asdict(self.req), not_after=iso(45))

    def make(self, payload=None):
        return sign_local_advisory(
            risk(self.req) if payload is None else payload,
            request=self.req, producer_id=PRODUCER,
            kid=KID, secret=self.secret, now=NOW,
        )

    def verdict(self, env, **kwargs):
        opts = {
            "request": self.req, "envelope": env,
            "producer_id": PRODUCER, "trusted_keys": self.keys,
            "replay_cache": self.cache, "authority": self.auth,
            "consent": self.consent, "now": NOW,
        }
        opts.update(kwargs)
        return evaluate_authenticated_candidate(**opts)

    def test_one_good_envelope_is_candidate_not_execution_authority(self):
        env = self.make()
        # Exercise JSON representation as a network adapter would, with a
        # strict duplicate-key rejecting decoder.
        data = json.dumps(env).encode("utf-8")
        parsed = parse_envelope_json(data)
        verdict = self.verdict(parsed)
        self.assertEqual(verdict.disposition, "CANDIDATE")
        self.assertFalse(verdict.authoritative)

    def test_replay_denied_even_with_same_valid_mac(self):
        env = self.make()
        self.assertEqual(self.verdict(env).disposition, "CANDIDATE")
        self.assertEqual(self.verdict(env).disposition, "DENY")

    def test_tampered_nested_advisory_and_mac_are_denied(self):
        env = self.make()
        for field, value in (
            ("advisory", dict(env["advisory"], recommended_action="allow", signal_count=2)),
            ("kid", "alternate"),
            ("producer_id", "spoof"),
            ("mac", "0"*64),
            ("nonce", "f"*32),
            ("issued_at", iso(-2)),
            ("audience", "another-audience"),
            ("request_id", "another-request"),
            ("scope", "memory_write"),
        ):
            with self.subTest(field=field):
                tampered = dict(env, **{field: value})
                self.assertEqual(self.verdict(tampered).disposition, "DENY")

    def test_unknown_keys_and_wrong_secret_denied(self):
        env = self.make()
        self.assertEqual(self.verdict(env, trusted_keys={}).disposition, "DENY")
        wrong = {(PRODUCER, KID): secrets.token_bytes(32)}
        self.assertEqual(self.verdict(env, trusted_keys=wrong).disposition, "DENY")

    def test_expiry_and_future_clock_denied(self):
        env = self.make()
        self.assertEqual(self.verdict(env, now=NOW + timedelta(seconds=31)).disposition, "DENY")
        self.assertEqual(self.verdict(env, now=NOW - timedelta(seconds=6)).disposition, "DENY")

    def test_unsigned_forged_allowed_envelope_denied(self):
        payload = risk(self.req)
        self.assertEqual(self.verdict(payload).disposition, "DENY")
        self.assertEqual(self.verdict(None).disposition, "DENY")

    def test_valid_high_risk_signature_results_in_denial(self):
        env = self.make(risk(self.req, posture="hostile", recommended_action="refuse", signal_count=1))
        self.assertEqual(self.verdict(env).disposition, "DENY")

    def test_valid_watch_signature_requires_review(self):
        env = self.make(risk(self.req, posture="watch", recommended_action="warn", signal_count=1))
        self.assertEqual(self.verdict(env).disposition, "REVIEW")

    def test_missing_authority_or_consent_always_denied(self):
        env = self.make()
        self.assertEqual(self.verdict(env, authority=None).disposition, "DENY")
        # New nonce (first valid check consumes a nonce)
        env2 = self.make()
        self.assertEqual(self.verdict(env2, consent=None).disposition, "DENY")

    def test_mismatched_resource_binding_denied(self):
        env = self.make()
        changed = replace(self.req, resource="service:wrong")
        self.assertEqual(
            self.verdict(env, request=changed).disposition, "DENY"
        )

    def test_replay_cache_capacity_fails_closed(self):
        cache = LocalReplayCache(capacity=1)
        self.assertEqual(self.verdict(self.make(), replay_cache=cache).disposition, "CANDIDATE")
        self.assertEqual(self.verdict(self.make(), replay_cache=cache).disposition, "DENY")

    def test_bad_crypto_key_sizes_rejected(self):
        with self.assertRaises(ValueError):
            sign_local_advisory(
                risk(self.req), request=self.req, producer_id=PRODUCER, kid=KID,
                secret=b"short", now=NOW,
            )

    def test_json_duplicate_fields_nonfinite_and_large_rejected(self):
        bad_cases = [
            b'{"nonce":"x","nonce":"y"}',
            b'{"score":NaN}',
            b'{"bad":"x"}' * 1000,
            b'[]',
        ]
        for value in bad_cases:
            with self.subTest(case=value[:30]):
                with self.assertRaises(ValueError):
                    parse_envelope_json(value)

    def test_producer_key_rotation_and_old_key_rejection(self):
        env = self.make()
        self.assertEqual(self.verdict(env).disposition, "CANDIDATE")
        # Revoked key ID cannot be verified. Old MAC does not create a grant.
        self.assertEqual(self.verdict(self.make(), trusted_keys={}).disposition, "DENY")

    def test_anti_replay_is_thread_safe(self):
        from concurrent.futures import ThreadPoolExecutor
        env = self.make()
        with ThreadPoolExecutor(max_workers=8) as pool:
            outcomes = list(pool.map(lambda _: self.verdict(env).disposition, range(16)))
        self.assertEqual(outcomes.count("CANDIDATE"), 1)
        self.assertEqual(outcomes.count("DENY"), 15)


if __name__ == "__main__":
    unittest.main()
