"""R8 private, offline-only membership revocation and rollback tests."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from phicloud.authz import ISSUER
from phicloud.tenant_store import (
    LocalTenantConfigError, LocalTenantError, LocalTenantStore, TENANT_SCHEMA,
)

SCHEMA = "phicloud.local-tenant-operator-request.v0.1"
OUTPUT = "phicloud.local-tenant-operator-result.v0.1"


def member(name):
    return SimpleNamespace(issuer=ISSUER, sub=name)


def provision():
    return {
        "schema": TENANT_SCHEMA,
        "tenants": [
            {"id": "alpha-team", "members": [
                {"iss": ISSUER, "sub": "alice"},
                {"iss": ISSUER, "sub": "bob"},
            ]},
            {"id": "beta-team", "members": [
                {"iss": ISSUER, "sub": "alice"},
                {"iss": ISSUER, "sub": "bob"},
            ]},
        ],
    }


def request(who="alice", tenant="alpha-team", acknowledge=None):
    return json.dumps({
        "schema": SCHEMA, "tenant": tenant,
        "member": {"iss": ISSUER, "sub": who},
        "acknowledge": acknowledge,
    })


class OperatorRevocationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="phicloud-r8-")
        self.path = Path(self.directory.name) / "private.sqlite"
        self.store = LocalTenantStore(self.path)
        self.store.provision_once(provision())

    def tearDown(self):
        if self.store is not None:
            self.store.close()
        self.directory.cleanup()

    def tool(self, payload, *, apply=False, enabled=True, production=False):
        env = {
            **os.environ,
            "PHICLOUD_TENANT_OPERATOR_DEV": "1" if enabled else "0",
            "PHICLOUD_ENV": "production" if production else "test",
            "NODE_ENV": "test",
        }
        return subprocess.run(
            [sys.executable, "-m", "phicloud.tenant_operator",
             "--db", str(self.path), *(["--apply"] if apply else [])],
            env=env, input=payload, text=True,
            capture_output=True, timeout=8,
        )

    def test_server_lease_blocks_second_server_and_operator(self):
        self.store.create(member("alice"), "alpha-team")
        with self.assertRaisesRegex(LocalTenantConfigError, "in_use"):
            LocalTenantStore(self.path)
        denied = self.tool(request(), enabled=True)
        self.assertEqual(denied.returncode, 2)
        self.assertIn("in_use", denied.stderr)
        self.assertNotIn("alice", denied.stdout + denied.stderr)
        self.assertEqual(len(self.store.list_own(member("alice"), "alpha-team")), 1)
        self.store.close()
        self.store = None
        result = self.tool(request())
        self.assertEqual(result.returncode, 0)
        preview = json.loads(result.stdout)
        self.assertEqual(preview["schema"], OUTPUT)
        self.assertEqual(preview["mode"], "preview")
        self.assertTrue(preview["membership_active"])
        self.assertEqual(preview["existing_markers"], 1)

    def test_durable_revoke_purges_owned_markers_only_for_one_tenant(self):
        own = self.store.create(member("alice"), "alpha-team")
        other = self.store.create(member("bob"), "alpha-team")
        other_tenant = self.store.create(member("alice"), "beta-team")
        self.store.close()
        self.store = None

        preview = self.tool(request())
        self.assertEqual(preview.returncode, 0)
        result = json.loads(preview.stdout)
        self.assertEqual(result["existing_markers"], 1)
        self.assertTrue(result["membership_active"])
        self.assertFalse(result["external_token_revoked"])
        self.assertNotIn("alice", preview.stdout)
        self.assertNotIn(ISSUER, preview.stdout)
        self.assertNotIn("principal_key", preview.stdout)
        self.assertNotIn(own["id"], preview.stdout)

        denied = self.tool(request(acknowledge="REVOKE wrong-team"), apply=True)
        self.assertEqual(denied.returncode, 2)
        denied = self.tool(request(), apply=True)
        self.assertEqual(denied.returncode, 2)
        denied = self.tool(request(acknowledge="REVOKE alpha-team"),
                           apply=True, enabled=False)
        self.assertEqual(denied.returncode, 2)
        denied = self.tool(request(acknowledge="REVOKE alpha-team"),
                           apply=True, production=True)
        self.assertEqual(denied.returncode, 2)

        result = self.tool(request(acknowledge="REVOKE alpha-team"), apply=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        applied = json.loads(result.stdout)
        self.assertEqual(applied["schema"], OUTPUT)
        self.assertEqual(applied["mode"], "apply")
        self.assertTrue(applied["changed"])
        self.assertEqual(applied["removed_markers"], 1)
        self.assertFalse(applied["external_token_revoked"])
        self.assertNotIn("alice", result.stdout + result.stderr)

        self.store = LocalTenantStore(self.path)
        with self.assertRaises(LocalTenantError):
            self.store.list_own(member("alice"), "alpha-team")
        with self.assertRaises(LocalTenantError):
            self.store.create(member("alice"), "alpha-team")
        with self.assertRaises(LocalTenantError):
            self.store.read_own(member("alice"), "alpha-team", own["id"])
        with self.assertRaises(LocalTenantError):
            self.store.delete_own(member("alice"), "alpha-team", own["id"])
        self.assertEqual(self.store.list_own(member("bob"), "alpha-team")[0]["id"],
                         other["id"])
        self.assertEqual(self.store.list_own(member("alice"), "beta-team")[0]["id"],
                         other_tenant["id"])
        with self.assertRaises(LocalTenantConfigError):
            self.store.provision_once(provision())
        tombstone = self.store.preview_member_removal("alpha-team", member("alice"))
        self.assertFalse(tombstone["membership_active"])
        self.assertTrue(tombstone["previously_revoked"])
        self.assertEqual(tombstone["existing_markers"], 0)
        history = self.store._db.execute(
            "SELECT action FROM audit WHERE tenant_id='alpha-team'"
        ).fetchall()
        self.assertEqual(history.count(("create",)), 2,
                         "existing create audit must survive membership removal")
        self.store.close()
        self.store = None

        again = self.tool(request(acknowledge="REVOKE alpha-team"), apply=True)
        self.assertEqual(again.returncode, 0)
        repeated = json.loads(again.stdout)
        self.assertFalse(repeated["changed"])
        self.assertTrue(repeated["previously_revoked"])

    def test_missing_member_is_noop_and_never_enrolls(self):
        self.store.close()
        self.store = None
        res = self.tool(request("outsider", acknowledge="REVOKE alpha-team"),
                        apply=True)
        self.assertEqual(res.returncode, 0)
        output = json.loads(res.stdout)
        self.assertFalse(output["changed"])
        self.assertFalse(output["previously_revoked"])
        self.store = LocalTenantStore(self.path)
        with self.assertRaises(LocalTenantError):
            self.store.list_own(member("outsider"), "alpha-team")

    def test_bad_input_and_duplicate_fields_fail_closed(self):
        self.store.close()
        self.store = None
        for payload in [
            "", "{}", "[]", "not-json", "{" + '"schema":"bad","schema":"bad"}',
            request() + "extra", request() + (" " * 4097),
            request().replace('"alice"', '"alice","role":"admin"'),
            request().replace('"alpha-team"', '"../escape"'),
            request().replace(ISSUER, "https://attacker.invalid"),
        ]:
            with self.subTest(payload=payload[:80]):
                result = self.tool(payload, apply=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")

    def test_failed_atomic_tombstone_does_not_remove_member_or_records(self):
        original = self.store.create(member("alice"), "alpha-team")
        self.store._db.executescript("""
          CREATE TRIGGER forbid_local_revocation
          BEFORE INSERT ON membership_revocations
          BEGIN SELECT RAISE(ABORT, 'injected_transaction_failure'); END;
        """)
        with self.assertRaises(sqlite3.DatabaseError):
            self.store.revoke_member_offline("alpha-team", member("alice"))
        self.assertEqual(
            self.store.list_own(member("alice"), "alpha-team")[0]["id"],
            original["id"])
        self.assertEqual(
            self.store._db.execute(
                "SELECT COUNT(*) FROM membership_revocations").fetchone()[0],
            0)

    def test_revoke_scoped_to_exact_issuer_and_subject(self):
        own = self.store.create(member("bob"), "alpha-team")
        with self.assertRaises(LocalTenantError):
            self.store.revoke_member_offline(
                "alpha-team", SimpleNamespace(
                    issuer="https://attacker.invalid", sub="bob"))
        self.assertEqual(
            self.store.list_own(member("bob"), "alpha-team")[0]["id"], own["id"])


if __name__ == "__main__":
    unittest.main()
