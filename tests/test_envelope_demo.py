"""R11 envelope encryption security and offline rotation regression."""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from phicloud.authz import ISSUER, AUDIENCE, LocalTokenIntrospector
from phicloud.envelope_demo import (
    CANARY, EnvelopeDemoStore, EnvelopeIntegrityError, rotate_wrapping_key,
    create_envelope_demo
)
from phicloud.sealed_demo import read_local_key, provision_local_key
from phicloud.server import LOOPBACK, make_handler
from phicloud.tenant_store import (
    LocalTenantError, LocalTenantConfigError, LocalTenantStore, TENANT_SCHEMA
)

SECRET = "R11-disposable-oidc-client-secret-" + "q" * 40
ALICE = "alice." + "a" * 50
BOB = "bob." + "b" * 50
READ = "read." + "c" * 50
WRITE = "write." + "d" * 50
WRONG_SCOPE = "wrong." + "e" * 50


def actor(sub: str):
    return SimpleNamespace(issuer=ISSUER, sub=sub)


def provision():
    return {
        "schema": TENANT_SCHEMA,
        "tenants": [
            {"id": "alpha-team", "members": [
                {"iss": ISSUER, "sub": "alice"},
                {"iss": ISSUER, "sub": "bob"}]},
            {"id": "beta-team", "members": [
                {"iss": ISSUER, "sub": "bob"}]},
        ],
    }


class EnvelopeStorageTests(unittest.TestCase):
    def setUp(self):
        self.database_dir = tempfile.TemporaryDirectory(prefix="phi-r11-db-")
        self.private_dir = tempfile.TemporaryDirectory(prefix="phi-r11-keys-")
        self.path = Path(self.database_dir.name) / "private.sqlite"
        self.old = Path(self.private_dir.name) / "old.key"
        self.new = Path(self.private_dir.name) / "new.key"
        self.store = LocalTenantStore(self.path)
        self.store.provision_once(provision())
        provision_local_key(self.old, self.path)
        provision_local_key(self.new, self.path)
        self.envelope = EnvelopeDemoStore(self.store, self.old)

    def tearDown(self):
        if self.store is not None:
            self.store.close()
        self.database_dir.cleanup()
        self.private_dir.cleanup()

    def test_per_record_unique_data_key_and_encrypted_payload(self):
        first = self.envelope.create(actor("alice"), "alpha-team")
        second = self.envelope.create(actor("alice"), "alpha-team")
        rows = self.store._db.execute(
            "SELECT id,payload_nonce,payload_ciphertext,wrap_nonce,wrapped_dek"
            " FROM envelope_markers ORDER BY id").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0][3], rows[1][3])
        self.assertNotEqual(rows[0][4], rows[1][4])
        for row in rows:
            self.assertEqual(len(row[1]), 12)
            self.assertEqual(len(row[3]), 12)
            self.assertEqual(len(row[4]), 48)
            self.assertNotIn(CANARY, row[2])
            self.assertNotIn(read_local_key(self.old, self.path), row[4])
        self.assertNotIn(CANARY, self.path.read_bytes())
        self.assertNotIn(read_local_key(self.old, self.path), self.path.read_bytes())
        self.assertTrue(self.envelope.read_own(
            actor("alice"), "alpha-team", first["id"])["wrapped_data_key"])
        self.assertFalse(self.envelope.read_own(
            actor("alice"), "alpha-team", second["id"])["plaintext_returned"])
        self.assertNotIn("ciphertext", json.dumps(self.envelope.list_own(
            actor("alice"), "alpha-team")))

    def test_valid_tokens_still_need_member_and_record_owner(self):
        alice = self.envelope.create(actor("alice"), "alpha-team")
        bob = self.envelope.create(actor("bob"), "alpha-team")
        self.assertIsNone(self.envelope.read_own(
            actor("bob"), "alpha-team", alice["id"]))
        self.assertIsNone(self.envelope.read_own(
            actor("alice"), "alpha-team", bob["id"]))
        with self.assertRaises(LocalTenantError):
            self.envelope.delete_own(actor("bob"), "alpha-team", alice["id"])
        with self.assertRaises(LocalTenantError):
            self.envelope.create(actor("alice"), "beta-team")
        self.assertEqual(self.envelope.read_own(
            actor("alice"), "alpha-team", alice["id"])["id"], alice["id"])

    def test_tampering_payload_wrap_and_owner_aad_fails_closed(self):
        one = self.envelope.create(actor("alice"), "alpha-team")
        row = self.store._db.execute(
            "SELECT payload_ciphertext,wrapped_dek FROM envelope_markers WHERE id=?",
            (one["id"],)).fetchone()
        self.store._db.execute(
            "UPDATE envelope_markers SET wrapped_dek=? WHERE id=?",
            (row[1][:-1] + bytes([row[1][-1] ^ 1]), one["id"]))
        with self.assertRaises(EnvelopeIntegrityError):
            self.envelope.read_own(actor("alice"), "alpha-team", one["id"])
        self.store._db.execute(
            "UPDATE envelope_markers SET wrapped_dek=?,payload_ciphertext=? WHERE id=?",
            (row[1], row[0][:-1] + bytes([row[0][-1] ^ 1]), one["id"]))
        with self.assertRaises(EnvelopeIntegrityError):
            self.envelope.list_own(actor("alice"), "alpha-team")
        self.store._db.execute(
            "UPDATE envelope_markers SET payload_ciphertext=?,owner_key=? WHERE id=?",
            (row[0], self.store._owner_key(actor("bob")), one["id"]))
        with self.assertRaises(EnvelopeIntegrityError):
            self.envelope.read_own(actor("bob"), "alpha-team", one["id"])

    def test_atomic_rewrap_keeps_payload_ciphertext_unchanged(self):
        alice = self.envelope.create(actor("alice"), "alpha-team")
        bob = self.envelope.create(actor("bob"), "alpha-team")
        before = self.store._db.execute(
            "SELECT id,payload_nonce,payload_ciphertext,wrap_nonce,wrapped_dek"
            " FROM envelope_markers ORDER BY id").fetchall()
        result = rotate_wrapping_key(self.store, self.old, self.new)
        self.assertEqual(result["rewrapped_markers"], 2)
        self.assertFalse(result["payload_reencrypted"])
        after = self.store._db.execute(
            "SELECT id,payload_nonce,payload_ciphertext,wrap_nonce,wrapped_dek"
            " FROM envelope_markers ORDER BY id").fetchall()
        for old, new in zip(before, after):
            self.assertEqual(old[:3], new[:3], "payload was unexpectedly re-encrypted")
            self.assertNotEqual(old[3], new[3])
            self.assertNotEqual(old[4], new[4])
        with self.assertRaisesRegex(LocalTenantConfigError, "active_key_mismatch"):
            EnvelopeDemoStore(self.store, self.old)
        refreshed = EnvelopeDemoStore(self.store, self.new)
        self.assertIsNotNone(refreshed.read_own(actor("alice"), "alpha-team", alice["id"]))
        self.assertIsNotNone(refreshed.read_own(actor("bob"), "alpha-team", bob["id"]))
        self.store.close()
        self.store = LocalTenantStore(self.path)
        self.envelope = EnvelopeDemoStore(self.store, self.new)
        self.assertEqual(self.envelope.read_own(
            actor("alice"), "alpha-team", alice["id"])["id"], alice["id"])
        with self.assertRaises(LocalTenantConfigError):
            rotate_wrapping_key(self.store, self.old, self.new)

    def test_failed_wrap_update_is_atomic_and_old_key_stays_active(self):
        one = self.envelope.create(actor("alice"), "alpha-team")
        before = self.store._db.execute(
            "SELECT wrapped_dek FROM envelope_markers WHERE id=?",
            (one["id"],)).fetchone()[0]
        self.store._db.executescript("""
            CREATE TRIGGER fail_rewrap_update
            BEFORE UPDATE OF wrapped_dek ON envelope_markers
            BEGIN SELECT RAISE(ABORT, 'injected_update_failure'); END;
        """)
        with self.assertRaises(sqlite3.DatabaseError):
            rotate_wrapping_key(self.store, self.old, self.new)
        self.assertEqual(self.store._db.execute(
            "SELECT wrapped_dek FROM envelope_markers WHERE id=?",
            (one["id"],)).fetchone()[0], before)
        self.assertIsNotNone(EnvelopeDemoStore(
            self.store, self.old).read_own(actor("alice"), "alpha-team", one["id"]))
        with self.assertRaises(LocalTenantConfigError):
            EnvelopeDemoStore(self.store, self.new)

    def test_revocation_purges_wrapped_keys_for_member_but_not_others(self):
        first = self.envelope.create(actor("alice"), "alpha-team")
        other = self.envelope.create(actor("bob"), "alpha-team")
        beta = self.envelope.create(actor("bob"), "beta-team")
        self.store.revoke_member_offline("alpha-team", actor("bob"))
        self.assertIsNone(self.envelope.read_own(
            actor("alice"), "alpha-team", other["id"]))
        self.assertIsNotNone(self.envelope.read_own(
            actor("alice"), "alpha-team", first["id"]))
        self.assertEqual(self.envelope.read_own(
            actor("bob"), "beta-team", beta["id"])["id"], beta["id"])
        self.assertEqual(self.store._db.execute(
            "SELECT COUNT(*) FROM envelope_markers WHERE id=?", (other["id"],)
        ).fetchone()[0], 0)
        with self.assertRaises(LocalTenantError):
            self.envelope.create(actor("bob"), "alpha-team")

    def test_explicit_opt_in_and_key_files_remain_private(self):
        self.assertIsNone(create_envelope_demo(self.store, {}))
        with self.assertRaises(LocalTenantConfigError):
            create_envelope_demo(self.store, {
                "PHICLOUD_ENABLE_ENVELOPE_DEV": "1",
                "PHICLOUD_ENV": "production",
                "PHICLOUD_ENVELOPE_KEK_PATH": str(self.old)
            })
        with self.assertRaises(LocalTenantConfigError):
            create_envelope_demo(self.store, {"PHICLOUD_ENABLE_ENVELOPE_DEV": "1"})
        self.assertEqual(self.old.stat().st_mode & 0o077, 0)
        self.assertEqual(self.new.stat().st_mode & 0o077, 0)
        self.old.chmod(0o644)
        with self.assertRaises(LocalTenantConfigError):
            EnvelopeDemoStore(self.store, self.old)
        self.old.chmod(0o600)
        with self.assertRaises(LocalTenantConfigError):
            rotate_wrapping_key(self.store, self.old, self.old)

    def test_offline_cli_refuses_running_server_and_confirmation_errors(self):
        self.envelope.create(actor("alice"), "alpha-team")
        args = [sys.executable, "-m", "phicloud.envelope_operator",
                "--db", str(self.path), "--old-key", str(self.old),
                "--new-key", str(self.new),
                "--confirm", "REWRAP SYNTHETIC ENVELOPES"]
        env = {**os.environ, "PHICLOUD_ENVELOPE_OPERATOR_DEV": "1",
               "NODE_ENV": "test", "PHICLOUD_ENV": "test"}
        denied = subprocess.run(args, capture_output=True, text=True, env=env, timeout=8)
        self.assertEqual(denied.returncode, 2, denied.stderr)
        self.assertNotIn(str(self.old), denied.stderr)
        self.assertNotIn(str(self.new), denied.stderr)
        self.store.close()
        self.store = None
        bad = subprocess.run(args[:-1] + ["wrong"], capture_output=True, text=True,
                             env=env, timeout=8)
        self.assertEqual(bad.returncode, 2)
        executed = subprocess.run(args, capture_output=True, text=True,
                                  env=env, timeout=8)
        self.assertEqual(executed.returncode, 0, executed.stderr)
        self.assertIn("rewrapped_markers=1", executed.stdout)
        self.assertNotIn(str(self.old), executed.stdout)
        self.store = LocalTenantStore(self.path)
        self.envelope = EnvelopeDemoStore(self.store, self.new)


class EnvelopeHttpTests(unittest.TestCase):
    def setUp(self):
        self.database_dir = tempfile.TemporaryDirectory()
        self.private_dir = tempfile.TemporaryDirectory()
        self.store = LocalTenantStore(Path(self.database_dir.name) / "test.sqlite")
        self.store.provision_once(provision())
        self.key = Path(self.private_dir.name) / "key.key"
        provision_local_key(self.key, self.store.path)
        self.envelope = EnvelopeDemoStore(self.store, self.key)
        self.revoked = set()
        self.offline = False

        def introspect(token, secret):
            self.assertEqual(secret, SECRET)
            if self.offline:
                raise OSError("keycloak_unreachable")
            if token in self.revoked:
                return {"active": False}
            mapping = {
                ALICE: ("alice", "phicloud.envelope.read phicloud.envelope.write"),
                BOB: ("bob", "phicloud.envelope.read phicloud.envelope.write"),
                READ: ("alice", "phicloud.envelope.read"),
                WRITE: ("alice", "phicloud.envelope.write"),
                WRONG_SCOPE: ("alice", "phicloud.sealed.read")
            }
            sub, scopes = mapping.get(token, ("outsider", ""))
            return {
                "active": True, "iss": ISSUER, "sub": sub, "scope": scopes,
                "aud": [AUDIENCE], "token_type": "Bearer",
                "exp": int(time.time()) + 300,
            }
        gate = LocalTokenIntrospector(SECRET, transport=introspect)
        self.server = ThreadingHTTPServer((LOOPBACK, 0), make_handler(
            {"schema":"phicloud.services.v0.1", "services":[]},
            gate, None, self.store, None, self.envelope
        ))
        self.worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.worker.start()
        self.base = f"http://{LOOPBACK}:{self.server.server_port}/v1/private/tenants"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.store.close()
        self.database_dir.cleanup()
        self.private_dir.cleanup()

    def req(self, method, token=ALICE, tenant="alpha-team", record=None,
            action=None, body=None, headers=None):
        target = f"{self.base}/{tenant}/envelope-markers"
        if record is not None:
            target += "/" + record
        h = dict(headers or {})
        if token is not None:
            h["Authorization"] = "Bearer " + token
        if action is not None:
            h["X-PhiCloud-Action"] = action
        request = Request(target, headers=h, data=body, method=method)
        try:
            with urlopen(request, timeout=3) as reply:
                return reply.status, json.load(reply)
        except HTTPError as exc:
            return exc.code, json.load(exc)

    def test_scope_ownership_actions_and_no_body(self):
        code, a = self.req("POST", action="create-envelope-test-marker")
        self.assertEqual(code, 201)
        code, b = self.req("POST", token=BOB, action="create-envelope-test-marker")
        self.assertEqual(code, 201)
        self.assertEqual(self.req("GET", token=BOB, record=a["id"])[0], 404)
        self.assertEqual(self.req("GET", record=b["id"])[0], 404)
        self.assertEqual(self.req("DELETE", token=BOB, record=a["id"],
                                  action="delete-envelope-test-marker")[0], 404)
        self.assertEqual(self.req("GET", record=a["id"])[0], 200)
        self.assertEqual(self.req("GET", token=WRITE)[0], 401)
        self.assertEqual(self.req("POST", token=READ,
                                  action="create-envelope-test-marker")[0], 401)
        self.assertEqual(self.req("GET", token=WRONG_SCOPE)[0], 401)
        self.assertEqual(self.req("GET", tenant="beta-team")[0], 404)
        self.assertEqual(self.req("POST", action="create-envelope-test-marker",
                                  body=b'{"owner":"bob"}')[0], 413)
        self.assertEqual(self.req("POST", action="create-envelope-test-marker",
                                  headers={"Origin":"https://outside.invalid"})[0], 403)
        self.assertEqual(self.req("POST", action="create-envelope-test-marker",
                                  headers={"Sec-Fetch-Site":"cross-site"})[0], 403)

    def test_revoked_token_provider_outage_and_ciphertext_corruption(self):
        code, a = self.req("POST", action="create-envelope-test-marker")
        self.assertEqual(code, 201)
        self.revoked.add(ALICE)
        self.assertEqual(self.req("GET", record=a["id"])[0], 401)
        self.revoked.clear()
        self.offline = True
        self.assertEqual(self.req("GET", record=a["id"])[0], 503)
        self.offline = False
        self.store._db.execute(
            "UPDATE envelope_markers SET wrapped_dek=X'00' WHERE id=?", (a["id"],)
        )
        self.assertEqual(self.req("GET", record=a["id"])[0], 503)


if __name__ == "__main__":
    unittest.main()
