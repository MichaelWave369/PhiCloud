"""R9 separate witness: backup rollback, crash window, and fail-closed repair."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from phicloud.authz import ISSUER
from phicloud.tenant_store import (
    LocalTenantConfigError, LocalTenantError, LocalTenantStore, TENANT_SCHEMA,
)
from phicloud.tenant_fence import RevocationWitness, WitnessError

OPERATOR_SCHEMA = "phicloud.tenant-recovery-operator/0.1"
OUTPUT_SCHEMA = "phicloud.tenant-recovery-result/0.1"


def actor(subject):
    return SimpleNamespace(issuer=ISSUER, sub=subject)


def fixture():
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


class RecoveryWitnessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="phi-r9-db-")
        self.anchor_dir = tempfile.TemporaryDirectory(prefix="phi-r9-fence-")
        self.db_path = Path(self.directory.name) / "tenant.sqlite"
        self.witness_path = Path(self.anchor_dir.name) / "witness.jsonl"
        self.db = LocalTenantStore(self.db_path)
        self.db.provision_once(fixture())

    def tearDown(self):
        if self.db is not None:
            self.db.close()
        self.directory.cleanup()
        self.anchor_dir.cleanup()

    def reopen(self, *, recovery_mode=False):
        self.db = LocalTenantStore(
            self.db_path, fence_path=self.witness_path,
            recovery_mode=recovery_mode)
        return self.db

    def enroll(self):
        result = self.db.enroll_recovery_fence(self.witness_path)
        self.assertEqual(result["enrolled"], True)
        self.assertEqual(self.witness_path.stat().st_mode & 0o077, 0)
        self.assertEqual(len(self.db._fence.records), 0)

    def snapshot(self):
        # Copy only *SQLite* while no connection holds it: the witness is
        # intentionally stored independently and is never restored with DB.
        self.db.close()
        self.db = None
        snapshot = Path(self.directory.name) / "snapshot.sqlite"
        shutil.copy2(self.db_path, snapshot)
        return snapshot

    def test_old_sqlite_restore_cannot_regrant_deleted_membership(self):
        self.db.create(actor("alice"), "alpha-team")
        bob_record = self.db.create(actor("bob"), "alpha-team")
        beta_record = self.db.create(actor("alice"), "beta-team")
        self.enroll()
        snapshot = self.snapshot()
        self.reopen()
        result = self.db.revoke_member_offline("alpha-team", actor("alice"))
        self.assertTrue(result["changed"])
        self.assertEqual(result["removed_markers"], 1)
        self.db.close()
        self.db = None

        shutil.copy2(snapshot, self.db_path)
        with self.assertRaisesRegex(LocalTenantConfigError,
                                    "stale_or_mismatched_sqlite_revocations"):
            self.reopen()
        self.assertIsNone(self.db, "failed startup cannot become a usable server")

        self.reopen(recovery_mode=True)
        repaired = self.db.reconcile_recovery_fence()
        self.assertEqual(repaired["reconciled_revocations"], 1)
        self.assertFalse(repaired["access_regranted"])
        self.db.close()
        self.db = None

        self.reopen()
        with self.assertRaises(LocalTenantError):
            self.db.create(actor("alice"), "alpha-team")
        with self.assertRaises(LocalTenantError):
            self.db.list_own(actor("alice"), "alpha-team")
        self.assertEqual(self.db.list_own(actor("bob"), "alpha-team")[0]["id"],
                         bob_record["id"])
        self.assertEqual(self.db.list_own(actor("alice"), "beta-team")[0]["id"],
                         beta_record["id"])
        count = self.db._db.execute("SELECT COUNT(*) FROM recovery_events").fetchone()[0]
        self.assertEqual(count, 1)
        self.assertEqual(self.db.reconcile_recovery_fence if self.db._recovery_mode
                         else None, None)
        self.db.close()
        self.db = None

        self.reopen(recovery_mode=True)
        again = self.db.reconcile_recovery_fence()
        self.assertEqual(again["reconciled_revocations"], 0)
        self.assertEqual(self.db._db.execute(
            "SELECT COUNT(*) FROM recovery_events").fetchone()[0], 1)

    def test_existing_r8_tombstones_are_carried_into_first_witness(self):
        self.db.revoke_member_offline("alpha-team", actor("alice"))
        result = self.db.enroll_recovery_fence(self.witness_path)
        self.assertEqual(result["existing_revocations"], 1)
        self.db.close()
        self.db = None
        self.reopen()
        self.assertTrue(self.db.preview_member_removal(
            "alpha-team", actor("alice"))["previously_revoked"])
        self.assertFalse(self.db.preview_member_removal(
            "alpha-team", actor("alice"))["membership_active"])
        with self.assertRaises(LocalTenantConfigError):
            self.db.enroll_recovery_fence(self.witness_path)

    def test_missing_modified_or_insecure_witness_fails_closed(self):
        self.enroll()
        self.db.close()
        self.db = None
        with self.assertRaisesRegex(LocalTenantConfigError, "requires_independent_fence"):
            self.db = LocalTenantStore(self.db_path)
        original = self.witness_path.read_bytes()
        self.witness_path.unlink()
        with self.assertRaises(LocalTenantConfigError):
            self.reopen()
        self.witness_path.write_bytes(original)
        self.witness_path.chmod(0o600)
        self.witness_path.write_bytes(original[:-1])
        with self.assertRaises(LocalTenantConfigError):
            self.reopen()
        self.witness_path.write_bytes(original)
        self.witness_path.chmod(0o644)
        with self.assertRaises(LocalTenantConfigError):
            self.reopen()
        self.witness_path.chmod(0o600)
        self.reopen()

    def test_operator_reconcile_never_deletes_unwitnessed_db_tombstone(self):
        self.enroll()
        with self.db._lock:
            self.db._db.execute(
                "INSERT INTO membership_revocations"
                " (tenant_id,principal_key,revoked_at,removed_markers)"
                " VALUES(?,?,?,?)",
                ("alpha-team", self.db._owner_key(actor("bob")), 1234, 0))
        self.db.close()
        self.db = None
        with self.assertRaises(LocalTenantConfigError):
            self.reopen()
        self.reopen(recovery_mode=True)
        with self.assertRaisesRegex(LocalTenantConfigError,
                                    "unwitnessed_sqlite_revocation"):
            self.db.reconcile_recovery_fence()
        self.assertEqual(self.db._db.execute(
            "SELECT COUNT(*) FROM memberships").fetchone()[0], 4)

    def test_commit_failure_after_fsynced_witness_stays_fail_closed(self):
        self.db.create(actor("alice"), "alpha-team")
        self.enroll()
        self.db._db.executescript("""
            CREATE TRIGGER inject_revoke_failure
            BEFORE INSERT ON membership_revocations
            BEGIN SELECT RAISE(ABORT, 'simulated_sqlite_write_failure'); END;
        """)
        with self.assertRaises(sqlite3.DatabaseError):
            self.db.revoke_member_offline("alpha-team", actor("alice"))
        self.assertEqual(self.db._db.execute(
            "SELECT COUNT(*) FROM memberships WHERE tenant_id='alpha-team'"
        ).fetchone()[0], 2)
        self.db.close()
        self.db = None
        with self.assertRaises(LocalTenantConfigError):
            self.reopen()

        self.reopen(recovery_mode=True)
        self.db._db.execute("DROP TRIGGER inject_revoke_failure")
        repaired = self.db.reconcile_recovery_fence()
        self.assertEqual(repaired["reconciled_revocations"], 1)
        self.db.close()
        self.db = None
        self.reopen()
        with self.assertRaises(LocalTenantError):
            self.db.create(actor("alice"), "alpha-team")

    def test_witness_cannot_live_in_sqlite_backup_directory_or_be_reenrolled(self):
        same_dir = Path(self.directory.name) / "witness.jsonl"
        with self.assertRaisesRegex(LocalTenantConfigError,
                                    "outside_database_backup_directory"):
            self.db.enroll_recovery_fence(same_dir)
        # An invalid destination is a preflight error, not a crash window.
        # Keep the DB usable. Actual interrupted enrollment after DB binding
        # will still fail closed until investigated.
        self.assertFalse(self.db._db.execute(
            "SELECT 1 FROM metadata WHERE key='recovery_fence_id'").fetchone())
        self.enroll()
        with self.assertRaisesRegex(LocalTenantConfigError,
                                    "already_enrolled"):
            self.db.enroll_recovery_fence(self.witness_path)

    def test_unsafe_witness_symlink_and_duplicate_entries_denied(self):
        self.enroll()
        self.db.close()
        self.db = None
        original = self.witness_path.read_bytes()
        self.witness_path.unlink()
        target = Path(self.anchor_dir.name) / "actual.jsonl"
        target.write_bytes(original)
        target.chmod(0o600)
        self.witness_path.symlink_to(target)
        with self.assertRaises(LocalTenantConfigError):
            self.reopen()
        self.witness_path.unlink()
        self.witness_path.write_bytes(original)
        self.witness_path.chmod(0o600)
        item = {"type": "revoke", "tenant": "alpha-team", "key": "a" * 64, "at": 42}
        line = (json.dumps(item) + "\n").encode()
        with self.witness_path.open("ab") as writer:
            writer.write(line + line)
        with self.assertRaises(LocalTenantConfigError):
            self.reopen()

    def test_config_requires_opt_in_and_database_binding(self):
        self.enroll()
        self.db.close()
        self.db = None
        from phicloud.tenant_store import create_tenant_store
        env = {
            "PHICLOUD_ENABLE_TENANT_DEV": "1",
            "PHICLOUD_ENABLE_OAUTH_DEV": "1",
            "PHICLOUD_TENANT_DB_PATH": str(self.db_path),
            "PHICLOUD_TENANT_FENCE_PATH": str(self.witness_path),
        }
        with self.assertRaises(LocalTenantConfigError):
            create_tenant_store(env)
        env["PHICLOUD_ENABLE_FENCE_DEV"] = "1"
        self.db = create_tenant_store(env)
        self.assertIsNotNone(self.db._fence)

    def test_cli_enroll_and_reconcile_requires_exact_confirmation(self):
        self.db.close()
        self.db = None

        def invoke(mode, confirm, enabled="1"):
            payload = json.dumps({
                "schema": OPERATOR_SCHEMA, "confirmation": confirm})
            env = {**os.environ, "PHICLOUD_TENANT_RECOVERY_DEV": enabled,
                   "NODE_ENV": "test", "PHICLOUD_ENV": "test"}
            return subprocess.run(
                [sys.executable, "-m", "phicloud.tenant_recovery",
                 "--db", str(self.db_path), "--witness", str(self.witness_path),
                 "--" + mode],
                input=payload, text=True, capture_output=True, env=env, timeout=7)
        for result in (
            invoke("enroll", "ENROLL INDEPENDENT WITNESS", "0"),
            invoke("enroll", "wrong"),
            invoke("enroll", "ENROLL INDEPENDENT WITNESS ")):
            self.assertEqual(result.returncode, 2)
        enrolled = invoke("enroll", "ENROLL INDEPENDENT WITNESS")
        self.assertEqual(enrolled.returncode, 0, enrolled.stderr)
        response = json.loads(enrolled.stdout)
        self.assertEqual(response["schema"], OUTPUT_SCHEMA)
        self.assertEqual(response["mode"], "enroll")
        self.assertTrue(response["enrolled"])
        self.assertNotIn("alice", enrolled.stdout)
        self.assertNotIn(ISSUER, enrolled.stdout)
        self.db = LocalTenantStore(self.db_path, fence_path=self.witness_path)
        self.db.revoke_member_offline("alpha-team", actor("alice"))
        self.db.close()
        self.db = None
        result = invoke("reconcile", "RECONCILE REVOKE ONLY")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["reconciled_revocations"], 0)


if __name__ == "__main__":
    unittest.main()
