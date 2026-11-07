"""R6: private durable synthetic tenant membership and resource ownership checks."""
from __future__ import annotations

import json
import stat
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from phicloud.authz import (
    AUDIENCE, ISSUER, TENANT_READ_SCOPE, TENANT_WRITE_SCOPE,
    AuthorizationUnavailable, LocalTokenIntrospector,
)
from phicloud.server import LOOPBACK, make_handler
from phicloud.tenant_store import (
    AUDIT_TTL, MAX_OWNER_RECORDS, RECORD_TTL, TENANT_SCHEMA,
    LocalTenantCapacity, LocalTenantConfigError, LocalTenantError,
    LocalTenantStore, create_tenant_store,
)

SECRET = "r6-demo-integration-secret-" + "k" * 35
ALICE = "alice-" + "A" * 45
BOB = "bob-" + "B" * 45
READ = "read-" + "C" * 45
WRITE = "write-" + "D" * 45
PROFILE = "profile-" + "E" * 45


def principal(sub):
    return SimpleNamespace(issuer=ISSUER, sub=sub)


def bootstrap():
    return {
        "schema": TENANT_SCHEMA,
        "tenants": [
            {"id": "alpha-team", "members": [
                {"iss": ISSUER, "sub": "alice"},
                {"iss": ISSUER, "sub": "bob"},
            ]},
            {"id": "beta-team", "members": [
                {"iss": ISSUER, "sub": "bob"},
            ]},
        ],
    }


class R6StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="phicloud-r6-")
        self.path = Path(self.directory.name) / "private.sqlite"
        self.clock = [1_000_000]
        self.store = LocalTenantStore(self.path, clock=lambda: self.clock[0])
        self.store.provision_once(bootstrap())

    def tearDown(self):
        if self.store:
            self.store.close()
        self.directory.cleanup()

    def test_persistence_restart_owner_and_membership(self):
        a = self.store.create(principal("alice"), "alpha-team")
        b = self.store.create(principal("bob"), "alpha-team")
        bb = self.store.create(principal("bob"), "beta-team")
        self.assertNotIn("owner", a)
        self.assertNotIn("sub", a)
        self.assertFalse(a["files_present"])
        self.assertTrue(a["persistent_local_only"])
        self.assertNotEqual(a["id"], b["id"])
        self.assertIsNone(self.store.read_own(principal("bob"), "alpha-team", a["id"]))
        self.assertIsNone(self.store.read_own(principal("alice"), "alpha-team", b["id"]))
        with self.assertRaises(LocalTenantError):
            self.store.read_own(principal("alice"), "beta-team", bb["id"])
        self.assertTrue(self.store.delete_own(principal("alice"), "alpha-team", a["id"]))
        self.assertEqual(self.store.list_own(principal("alice"), "alpha-team"), [])
        self.assertEqual(len(self.store.own_audit(principal("alice"), "alpha-team")), 2)
        self.store.close()
        self.store = LocalTenantStore(self.path, clock=lambda: self.clock[0])
        self.assertEqual(self.store.list_own(principal("alice"), "alpha-team"), [])
        self.assertEqual(self.store.list_own(principal("bob"), "alpha-team")[0]["id"], b["id"])
        self.assertEqual(self.store.list_own(principal("bob"), "beta-team")[0]["id"], bb["id"])
        self.assertEqual([a["action"] for a in self.store.own_audit(principal("alice"), "alpha-team")],
                         ["delete", "create"])
        self.assertEqual(self.store.own_audit(principal("bob"), "alpha-team")[0]["action"], "create")
        with self.assertRaises(LocalTenantConfigError):
            self.store.provision_once(bootstrap())

    def test_denied_delete_is_atomic_and_never_logged_as_success(self):
        a = self.store.create(principal("alice"), "alpha-team")
        before = len(self.store.own_audit(principal("bob"), "alpha-team"))
        with self.assertRaises(LocalTenantError):
            self.store.delete_own(principal("bob"), "alpha-team", a["id"])
        self.assertIsNotNone(self.store.read_own(principal("alice"), "alpha-team", a["id"]))
        self.assertEqual(len(self.store.own_audit(principal("bob"), "alpha-team")), before)

    def test_capacity_expiry_and_isolated_audit_retention(self):
        for _ in range(MAX_OWNER_RECORDS):
            self.store.create(principal("alice"), "alpha-team")
        with self.assertRaises(LocalTenantCapacity):
            self.store.create(principal("alice"), "alpha-team")
        self.store.create(principal("bob"), "alpha-team")
        self.clock[0] += RECORD_TTL
        self.assertEqual(self.store.list_own(principal("alice"), "alpha-team"), [])
        self.assertEqual(len(self.store.own_audit(principal("alice"), "alpha-team")),
                         MAX_OWNER_RECORDS)
        self.clock[0] += AUDIT_TTL
        self.assertEqual(self.store.own_audit(principal("alice"), "alpha-team"), [])
        self.store.create(principal("alice"), "alpha-team")

    def test_private_permissions_and_dangling_symlink_fail_closed(self):
        self.assertEqual(self.path.stat().st_mode & 0o077, 0)
        self.assertEqual(Path(self.directory.name).stat().st_mode & 0o077, 0)
        self.store.close()
        self.store = None
        linked = Path(self.directory.name) / "linked.sqlite"
        linked.symlink_to(self.path)
        with self.assertRaises(LocalTenantConfigError):
            LocalTenantStore(linked)
        dangling = Path(self.directory.name) / "dangling.sqlite"
        dangling.symlink_to(Path(self.directory.name) / "notthere.sqlite")
        with self.assertRaises(LocalTenantConfigError):
            LocalTenantStore(dangling)
        self.path.chmod(0o644)
        with self.assertRaises(LocalTenantConfigError):
            LocalTenantStore(self.path)
        self.path.chmod(0o600)
        Path(self.directory.name).chmod(0o755)
        with self.assertRaises(LocalTenantConfigError):
            LocalTenantStore(self.path)
        Path(self.directory.name).chmod(0o700)
        self.store = LocalTenantStore(self.path)

    def test_invalid_operator_provision_fixture_is_rejected(self):
        for fixture in [
            {},
            {"schema": TENANT_SCHEMA, "tenants": []},
            {"schema": TENANT_SCHEMA, "tenants": [
                {"id": "alpha-team", "members": [{"iss": ISSUER, "sub": "alice"}]},
                {"id": "alpha-team", "members": [{"iss": ISSUER, "sub": "bob"}]}
            ]},
            {"schema": TENANT_SCHEMA, "tenants": [
                {"id": "alpha-team", "members": [{"iss": "https://outside.invalid", "sub": "alice"}]}
            ]},
            {"schema": TENANT_SCHEMA, "tenants": [
                {"id": "../escape", "members": [{"iss": ISSUER, "sub": "alice"}]}
            ]},
        ]:
            with self.subTest(fixture=fixture):
                with tempfile.TemporaryDirectory() as directory:
                    store = LocalTenantStore(Path(directory) / "new.sqlite")
                    try:
                        with self.assertRaises((LocalTenantConfigError, LocalTenantError)):
                            store.provision_once(fixture)
                    finally:
                        store.close()

    def test_off_without_both_explicit_flags(self):
        self.assertIsNone(create_tenant_store({}))
        with self.assertRaises(LocalTenantConfigError):
            create_tenant_store({
                "PHICLOUD_ENABLE_TENANT_DEV": "1", "PHICLOUD_TENANT_DB_PATH": str(self.path)
            })
        with self.assertRaises(LocalTenantConfigError):
            create_tenant_store({
                "PHICLOUD_ENABLE_TENANT_DEV": "1", "PHICLOUD_ENABLE_OAUTH_DEV": "1",
                "PHICLOUD_TENANT_DB_PATH": str(self.path), "PHICLOUD_ENV": "production"
            })


class R6HttpTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = LocalTenantStore(Path(self.directory.name) / "demo.sqlite")
        self.store.provision_once(bootstrap())
        self.revoked = set()
        self.offline = False
        self.calls = []
        def provider(token, secret):
            self.assertEqual(secret, SECRET)
            self.calls.append(token)
            if self.offline:
                raise AuthorizationUnavailable("provider_unreachable")
            if token in self.revoked:
                return {"active": False}
            claims = {
                ALICE: ("alice", TENANT_READ_SCOPE + " " + TENANT_WRITE_SCOPE),
                BOB: ("bob", TENANT_READ_SCOPE + " " + TENANT_WRITE_SCOPE),
                READ: ("alice", TENANT_READ_SCOPE),
                WRITE: ("alice", TENANT_WRITE_SCOPE),
                PROFILE: ("alice", "phicloud.profile.read"),
            }
            sub, scope = claims.get(token, ("nobody", ""))
            return {
                "active": True, "iss": ISSUER, "sub": sub,
                "scope": scope, "aud": [AUDIENCE], "token_type": "Bearer",
                "exp": int(time.time()) + 300,
            }
        self.gate = LocalTokenIntrospector(SECRET, transport=provider)
        self.server = ThreadingHTTPServer(
            (LOOPBACK, 0),
            make_handler({"schema": "phicloud.services.v0.1", "services": []},
                         self.gate, None, self.store),
        )
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.root = f"http://{LOOPBACK}:{self.server.server_port}/v1/private/tenants"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=3)
        self.store.close()
        self.directory.cleanup()

    def req(self, method, suffix, token=ALICE, action=None, body=None, headers=None):
        supplied = dict(headers or {})
        if token is not None:
            supplied["Authorization"] = "Bearer " + token
        if action is not None:
            supplied["X-PhiCloud-Action"] = action
        request = Request(self.root + suffix, headers=supplied, method=method,
                          data=body)
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            return error.code, json.load(error)

    def test_equal_scopes_cannot_overcome_subject_and_tenant_policy(self):
        a_status, a = self.req("POST", "/alpha-team/records",
                                action="create-tenant-test-record")
        self.assertEqual(a_status, 201)
        b_status, b = self.req("POST", "/alpha-team/records", BOB,
                                "create-tenant-test-record")
        self.assertEqual(b_status, 201)
        self.assertEqual(self.req("GET", "/alpha-team/records/" + a["id"], BOB)[0],404)
        self.assertEqual(self.req("GET", "/alpha-team/records/" + b["id"], ALICE)[0],404)
        self.assertEqual(self.req("DELETE", "/alpha-team/records/" + a["id"], BOB,
                                  "delete-tenant-test-record")[0],404)
        self.assertEqual(self.req("GET", "/alpha-team/records", ALICE)[1]["records"][0]["id"],a["id"])
        self.assertEqual(self.req("GET", "/alpha-team/records", BOB)[1]["records"][0]["id"],b["id"])
        self.assertEqual(self.req("GET", "/alpha-team/audit", ALICE)[1]["events"][0]["record_id"],a["id"])
        self.assertEqual(self.req("GET", "/alpha-team/audit", BOB)[1]["events"][0]["record_id"],b["id"])
        self.assertEqual(self.req("GET", "/beta-team/records", ALICE)[0],404)
        self.assertEqual(self.req("GET", "/beta-team/records", BOB)[0],200)
        self.assertEqual(self.req("DELETE", "/alpha-team/records/" + a["id"], ALICE,
                                  "delete-tenant-test-record")[0],200)
        self.assertEqual(self.req("GET", "/alpha-team/records/" + a["id"], ALICE)[0],404)

    def test_no_implicit_scope_header_or_payload_authority(self):
        self.assertEqual(self.req("GET", "/alpha-team/records", None)[0],401)
        self.assertEqual(self.req("GET", "/alpha-team/records", PROFILE)[0],401)
        self.assertEqual(self.req("GET", "/alpha-team/records", WRITE)[0],401)
        self.assertEqual(self.req("GET", "/alpha-team/records", READ)[0],200)
        self.assertEqual(self.req("POST", "/alpha-team/records", READ,
                                  "create-tenant-test-record")[0],401)
        self.assertEqual(self.req("POST", "/alpha-team/records")[0],403)
        self.assertEqual(self.req("POST", "/alpha-team/records",
                                  action="create-tenant-test-record",
                                  body=b'{"owner":"bob"}')[0],413)
        self.assertEqual(self.req("POST", "/alpha-team/records",
                                  action="create-tenant-test-record",
                                  headers={"Origin":"https://outside.invalid"})[0],403)
        self.assertEqual(self.req("GET", "/alpha-team/records?owner=bob")[0],404)
        self.assertEqual(self.req("GET", "/alpha-team/records/../audit")[0],404)
        self.assertEqual(self.req("GET", "/alpha-team/records")[1]["records"],[])

    def test_revocation_and_provider_outage_fail_closed_without_erasing_data(self):
        _, record = self.req("POST", "/alpha-team/records",
                             action="create-tenant-test-record")
        self.revoked.add(ALICE)
        self.assertEqual(self.req("GET", "/alpha-team/records/" + record["id"])[0],401)
        self.revoked.clear()
        self.offline = True
        self.assertEqual(self.req("GET", "/alpha-team/records")[0],503)
        self.assertEqual(self.req("DELETE", "/alpha-team/records/" + record["id"],
                                  action="delete-tenant-test-record")[0],503)
        self.offline = False
        self.assertEqual(self.req("GET", "/alpha-team/records/" + record["id"])[0],200)


if __name__ == "__main__":
    unittest.main()
