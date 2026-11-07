"""R3 security tests: no synthetic profile or consent can unlock a resource."""

from __future__ import annotations

import json
import time
import unittest
from http.server import ThreadingHTTPServer
from threading import Thread
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from phicloud.authz import (
    AUDIENCE, ISSUER, REQUIRED_SCOPE, AuthorizationDenied,
    AuthorizationUnavailable, LocalTokenIntrospector, create_local_introspector,
    validate_bearer_header, validate_introspection,
)
from phicloud.server import LOOPBACK, make_handler


TOKEN = "opaque-access-token-" + ("x" * 40)
SECRET = "ci-only-introspection-secret-" + ("s" * 24)


def valid_claims(now: int | None = None) -> dict:
    clock = int(time.time()) if now is None else now
    return {
        "active": True,
        "iss": ISSUER,
        "sub": "disposable-test-subject-001",
        "aud": [AUDIENCE],
        "scope": "openid profile " + REQUIRED_SCOPE,
        "exp": clock + 300,
        "nbf": clock - 1,
        "token_type": "Bearer",
    }


class IntrospectionRules(unittest.TestCase):
    def test_one_strict_bearer_header(self):
        self.assertEqual(validate_bearer_header(["Bearer " + TOKEN]), TOKEN)
        for values in [
            None, [], ["Bearer " + TOKEN, "Bearer " + TOKEN],
            ["Basic " + TOKEN], ["bearer " + TOKEN], ["Bearer "],
            ["Bearer " + TOKEN + "\ncorruption"],
            ["Bearer " + ("A" * 4097)],
        ]:
            with self.subTest(values=values):
                with self.assertRaises(AuthorizationDenied):
                    validate_bearer_header(values)

    def test_exact_issuer_audience_scope_expiration_and_access_type(self):
        now = int(time.time())
        self.assertEqual(validate_introspection(valid_claims(now), now=now).sub,
                         "disposable-test-subject-001")
        wrong = [
            None, [], {}, {"active": True},
            {**valid_claims(now), "active": 1},
            {**valid_claims(now), "active": False},
            {**valid_claims(now), "iss": "http://localhost:8080/realms/phiid-dev"},
            {**valid_claims(now), "iss": "https://evil.example"},
            {**valid_claims(now), "sub": ""},
            {**valid_claims(now), "sub": "s" * 256},
            {**valid_claims(now), "aud": "phimail-bff-dev"},
            {**valid_claims(now), "aud": ["phimail-bff-dev"]},
            {**valid_claims(now), "aud": None},
            {**valid_claims(now), "scope": "openid profile"},
            {**valid_claims(now), "scope": "phicloud.profile.read-all"},
            {**valid_claims(now), "scope": None},
            {**valid_claims(now), "exp": now},
            {**valid_claims(now), "exp": True},
            {**valid_claims(now), "exp": str(now + 50)},
            {**valid_claims(now), "nbf": now + 30},
            {**valid_claims(now), "token_type": "refresh_token"},
            {**valid_claims(now), "token_type": None},
        ]
        for item in wrong:
            with self.subTest(item=item):
                with self.assertRaises(AuthorizationDenied):
                    validate_introspection(item, now=now)

    def test_no_shortcuts_when_provider_fails(self):
        def offline(token, secret):
            raise OSError("provider unreachable with sensitive data")
        gate = LocalTokenIntrospector(SECRET, transport=offline)
        with self.assertRaises(AuthorizationUnavailable):
            gate.authorize(TOKEN)

    def test_each_authorization_requires_fresh_introspection(self):
        calls = []
        active = [valid_claims()]
        def transport(token, secret):
            self.assertEqual(secret, SECRET)
            self.assertEqual(token, TOKEN)
            calls.append(1)
            return active[0]
        gate = LocalTokenIntrospector(SECRET, transport=transport)
        first = gate.authorize(TOKEN)
        self.assertEqual(first.scope, REQUIRED_SCOPE)
        self.assertNotIn("disposable-test-subject", json.dumps(first.public_profile()))
        self.assertFalse(first.public_profile()["mailbox_access"])
        self.assertFalse(first.public_profile()["phios_effect_authority"])
        active[0] = {"active": False}
        with self.assertRaises(AuthorizationDenied):
            gate.authorize(TOKEN)
        self.assertEqual(len(calls), 2, "a cached active grant could defeat revocation")

    def test_off_by_default_and_secret_required(self):
        self.assertIsNone(create_local_introspector({}))
        self.assertIsNone(create_local_introspector({
            "PHICLOUD_ENABLE_OAUTH_DEV": "0",
            "PHICLOUD_OAUTH_CLIENT_SECRET": SECRET
        }))
        with self.assertRaises(ValueError):
            create_local_introspector({"PHICLOUD_ENABLE_OAUTH_DEV": "1"})
        with self.assertRaises(ValueError):
            create_local_introspector({
                "PHICLOUD_ENABLE_OAUTH_DEV": "1",
                "PHICLOUD_OAUTH_CLIENT_SECRET": SECRET,
                "PHICLOUD_ENV": "production"
            })


class PrivateRouteTests(unittest.TestCase):
    def setUp(self):
        self.active = valid_claims()
        self.calls = []
        def provider(token, secret):
            self.calls.append(token)
            return self.active
        self.gate = LocalTokenIntrospector(SECRET, transport=provider)
        manifest = {"schema": "phicloud.services.v0.1", "services": [{
            "id": "phiid", "title": "PhiID", "role": "identity",
            "stage": "planned", "repository": None, "endpoint_hint": None
        }]}
        self.manifest = manifest
        self.server = ThreadingHTTPServer((LOOPBACK, 0),
                                          make_handler(manifest, self.gate))
        self.worker = Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)

    def request(self, path, headers=None):
        req = Request(
            f"http://{LOOPBACK}:{self.server.server_port}{path}",
            headers=headers or {}, method="GET",
        )
        try:
            with urlopen(req, timeout=3) as r:
                return r.status, json.load(r)
        except HTTPError as error:
            return error.code, json.load(error)

    def test_public_registry_unchanged(self):
        code, data = self.request("/v1/services")
        self.assertEqual(code, 200)
        self.assertEqual(data["services"], self.manifest["services"])

    def test_missing_and_fake_credentials_never_unlock_private_route(self):
        self.assertEqual(self.request("/v1/private/profile")[0], 401)
        self.assertEqual(self.request("/v1/private/profile?token=" + TOKEN)[0], 404)
        self.assertEqual(self.request("/v1/private/profile",
                                      {"Authorization": "Bearer fake-profile-json"})[0], 401)
        self.assertEqual(len(self.calls), 0)

    def test_real_introspected_token_scoped_to_endpoint(self):
        code, result = self.request("/v1/private/profile",
                                    {"Authorization": "Bearer " + TOKEN})
        self.assertEqual(code, 200)
        self.assertEqual(result["resource"], "local_demo_profile_only")
        self.assertEqual(result["authorized_audience"], AUDIENCE)
        self.assertEqual(result["authorized_scope"], REQUIRED_SCOPE)
        self.assertFalse(result["cloud_storage_access"])
        self.assertFalse(result["phios_effect_authority"])
        self.assertEqual(len(self.calls), 1)

    def test_revocation_is_reflected_in_next_request(self):
        headers = {"Authorization": "Bearer " + TOKEN}
        self.assertEqual(self.request("/v1/private/profile", headers)[0], 200)
        self.active = {"active": False}
        self.assertEqual(self.request("/v1/private/profile", headers)[0], 401)
        self.assertEqual(len(self.calls), 2)

    def test_auth_server_offline_fails_closed(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)
        self.server = ThreadingHTTPServer((LOOPBACK, 0),
            make_handler(self.manifest, LocalTokenIntrospector(
                SECRET, transport=lambda token, secret: (_ for _ in ()).throw(
                    AuthorizationUnavailable("provider_down")
                ))))
        self.worker = Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        code, obj = self.request("/v1/private/profile", {
            "Authorization": "Bearer " + TOKEN
        })
        self.assertEqual(code, 503)
        self.assertEqual(obj["error"], "identity_provider_unavailable")


if __name__ == "__main__":
    unittest.main()
