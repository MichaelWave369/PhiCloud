"""R4 ownership regression: two verified principals never share demo records."""
from __future__ import annotations

import json
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from phicloud.authz import (
    AUDIENCE, DEMO_READ_SCOPE, DEMO_WRITE_SCOPE, ISSUER, REQUIRED_SCOPE,
    AuthorizationDenied, AuthorizationUnavailable, LocalTokenIntrospector,
    validate_introspection,
)
from phicloud.owner_demo import (
    MAX_PER_OWNER, OwnerDemoStore, DemoStoreFull, TTL_SECONDS,
)
from phicloud.server import LOOPBACK, make_handler


SECRET = "not-real-ci-resource-secret-" + "x" * 35
ALICE = "alice-token-" + "A" * 40
BOB = "bob-token-" + "B" * 40
READ_ONLY = "readonly-token-" + "C" * 40
PROFILE_ONLY = "profile-token-" + "D" * 40


def claims(sub: str, scope: str) -> dict:
    return {
        "active": True, "iss": ISSUER, "sub": sub,
        "aud": [AUDIENCE], "scope": scope,
        "exp": int(time.time()) + 300,
        "token_type": "Bearer",
    }


def identity(name: str):
    return SimpleNamespace(issuer=ISSUER, sub=name)


class OwnerStoreTests(unittest.TestCase):
    def test_owner_is_issuer_plus_subject_and_no_owner_input(self):
        state = [100]
        store = OwnerDemoStore(clock=lambda: state[0])
        alice = identity("same-name")
        other_issuer = SimpleNamespace(issuer="https://other.example", sub="same-name")
        bob = identity("bob")
        a = store.create(alice)
        self.assertNotIn("sub", a)
        self.assertNotIn("issuer", a)
        self.assertFalse(a["persistent"])
        self.assertFalse(a["cloud_storage_access"])
        self.assertFalse(a["phios_effect_authority"])
        self.assertEqual(len(store.list_own(alice)), 1)
        self.assertEqual(store.list_own(bob), [])
        self.assertEqual(store.list_own(other_issuer), [])
        self.assertIsNone(store.read_own(bob, a["id"]))
        self.assertIsNone(store.read_own(other_issuer, a["id"]))
        self.assertFalse(store.delete_own(bob, a["id"]))
        self.assertTrue(store.delete_own(alice, a["id"]))
        self.assertIsNone(store.read_own(alice, a["id"]))

    def test_ttl_and_capacity_are_bounded(self):
        now = [1000]
        store = OwnerDemoStore(clock=lambda: now[0])
        for _ in range(MAX_PER_OWNER):
            store.create(identity("alice"))
        with self.assertRaises(DemoStoreFull):
            store.create(identity("alice"))
        self.assertEqual(len(store.list_own(identity("alice"))), MAX_PER_OWNER)
        now[0] += TTL_SECONDS
        self.assertEqual(store.list_own(identity("alice")), [])
        self.assertEqual(len(store.list_own(identity("bob"))), 0)
        store.create(identity("alice"))
        with self.assertRaises(ValueError):
            store.create(SimpleNamespace(issuer=ISSUER, sub=""))

    def test_exact_per_route_scopes_fail_closed(self):
        for scope in [DEMO_READ_SCOPE, DEMO_WRITE_SCOPE]:
            value = claims("alice", scope)
            self.assertEqual(validate_introspection(value, required_scope=scope).scope, scope)
            other = DEMO_WRITE_SCOPE if scope == DEMO_READ_SCOPE else DEMO_READ_SCOPE
            with self.assertRaises(AuthorizationDenied):
                validate_introspection(value, required_scope=other)
        with self.assertRaises(AuthorizationDenied):
            validate_introspection(
                claims("alice", DEMO_READ_SCOPE), required_scope="*"
            )
        with self.assertRaises(AuthorizationDenied):
            validate_introspection(
                claims("alice", REQUIRED_SCOPE), required_scope=DEMO_READ_SCOPE
            )


class OwnerRoutes(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.disabled = set()
        self.offline = False
        def introspect(token: str, secret: str) -> dict:
            self.calls.append(token)
            self.assertEqual(secret, SECRET)
            if self.offline:
                raise AuthorizationUnavailable("provider_down")
            if token in self.disabled:
                return {"active": False}
            scopes = {
                ALICE: "openid " + DEMO_READ_SCOPE + " " + DEMO_WRITE_SCOPE,
                BOB: "openid " + DEMO_READ_SCOPE + " " + DEMO_WRITE_SCOPE,
                READ_ONLY: DEMO_READ_SCOPE,
                PROFILE_ONLY: REQUIRED_SCOPE,
            }
            return claims("bob" if token == BOB else "alice", scopes.get(token, ""))
        self.store = OwnerDemoStore()
        self.server = ThreadingHTTPServer(
            (LOOPBACK, 0), make_handler(
                {"schema": "phicloud.services.v0.1", "services": []},
                LocalTokenIntrospector(SECRET, transport=introspect),
                self.store,
            ),
        )
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)

    def call(self, method, path="/v1/private/demo-records", token=None, action=None,
             headers=None, data=None):
        h = dict(headers or {})
        if token is not None:
            h["Authorization"] = "Bearer " + token
        if action is not None:
            h["X-PhiCloud-Action"] = action
        request = Request(
            f"http://{LOOPBACK}:{self.server.server_port}{path}",
            headers=h, data=data, method=method,
        )
        try:
            with urlopen(request, timeout=3) as reply:
                return reply.status, json.load(reply)
        except HTTPError as error:
            return error.code, json.load(error)

    def create(self, token=ALICE):
        return self.call("POST", token=token, action="create-demo-record")

    def test_two_legitimate_users_are_separated_by_resource_owner(self):
        status, a = self.create(ALICE)
        self.assertEqual(status, 201)
        status, b = self.create(BOB)
        self.assertEqual(status, 201)
        self.assertNotEqual(a["id"], b["id"])
        self.assertEqual(self.call("GET", token=ALICE)[1]["records"][0]["id"], a["id"])
        self.assertEqual(self.call("GET", token=BOB)[1]["records"][0]["id"], b["id"])
        self.assertEqual(self.call("GET", "/v1/private/demo-records/" + a["id"], BOB)[0], 404)
        self.assertEqual(self.call("GET", "/v1/private/demo-records/" + b["id"], ALICE)[0], 404)
        self.assertEqual(self.call("DELETE", "/v1/private/demo-records/" + b["id"],
                                   ALICE, "delete-demo-record")[0], 404)
        self.assertEqual(self.call("GET", "/v1/private/demo-records/" + b["id"], BOB)[0], 200)
        self.assertEqual(self.call("DELETE", "/v1/private/demo-records/" + a["id"],
                                   ALICE, "delete-demo-record")[0], 200)
        self.assertEqual(self.call("GET", "/v1/private/demo-records/" + a["id"],
                                   ALICE)[0], 404)

    def test_write_needs_write_scope_explicit_action_and_no_body(self):
        self.assertEqual(self.call("POST", token=ALICE)[0], 403)
        self.assertEqual(self.call("POST", token=READ_ONLY,
                                   action="create-demo-record")[0], 401)
        self.assertEqual(self.call("POST", token=ALICE,
                                   action="create-demo-record",
                                   headers={"Origin":"https://outside.invalid"})[0], 403)
        self.assertEqual(self.call("POST", token=ALICE,
                                   action="create-demo-record",data=b'{"owner":"bob"}')[0], 413)
        self.assertEqual(self.call("POST", token=ALICE,
                                   action="create-demo-record",
                                   headers={"Sec-Fetch-Site":"cross-site"})[0], 403)
        self.assertEqual(self.store.list_own(identity("alice")), [])

    def test_read_needs_read_scope_and_authentication(self):
        self.assertEqual(self.call("GET")[0], 401)
        self.assertEqual(self.call("GET", token=PROFILE_ONLY)[0], 401)
        self.assertEqual(self.call("GET", token=READ_ONLY)[0], 200)
        self.assertEqual(self.call("GET", token=ALICE,
                                   path="/v1/private/demo-records?owner=bob")[0], 404)
        self.assertEqual(self.call("GET", token=ALICE,
                                   path="/v1/private/demo-records/%2e%2e")[0], 404)

    def test_token_revocation_and_provider_outage_prevent_access(self):
        status, row = self.create()
        self.assertEqual(status, 201)
        self.disabled.add(ALICE)
        self.assertEqual(self.call("GET", token=ALICE)[0], 401)
        self.assertEqual(self.call("DELETE", "/v1/private/demo-records/" + row["id"],
                                   ALICE, "delete-demo-record")[0], 401)
        self.disabled.clear()
        self.offline = True
        self.assertEqual(self.call("GET", token=ALICE)[0], 503)
        self.assertEqual(self.call("POST", token=ALICE, action="create-demo-record")[0], 503)
        self.assertEqual(len(self.store.list_own(identity("alice"))), 1)

    def test_default_disabled_when_no_store_is_passed(self):
        separate = ThreadingHTTPServer((LOOPBACK, 0), make_handler(
            {"schema":"phicloud.services.v0.1","services":[]},
            LocalTokenIntrospector(SECRET, transport=lambda *_: claims(
                "alice", DEMO_READ_SCOPE + " " + DEMO_WRITE_SCOPE))
        ))
        worker = threading.Thread(target=separate.serve_forever, daemon=True)
        worker.start()
        try:
            for method in ["GET","POST","DELETE"]:
                request = Request(
                    f"http://{LOOPBACK}:{separate.server_port}/v1/private/demo-records",
                    method=method
                )
                with self.assertRaises(HTTPError) as err:
                    urlopen(request, timeout=3)
                self.assertEqual(err.exception.code,404)
        finally:
            separate.shutdown()
            separate.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
