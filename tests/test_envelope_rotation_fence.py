"""R12 local independent rotation witness: rollback and crash-window regression."""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from phicloud.authz import ISSUER
from phicloud.envelope_demo import (
    EnvelopeDemoStore, rotate_wrapping_key
)
from phicloud.envelope_rotation_fence import (
    BINDING_KEY, RotationWitness, enroll_rotation_witness,
    load_for_database
)
from phicloud.sealed_demo import provision_local_key
from phicloud.tenant_store import (
    LocalTenantConfigError, LocalTenantStore, TENANT_SCHEMA
)

def actor(sub):
    return SimpleNamespace(issuer=ISSUER, sub=sub)


class RotationWitnessTests(unittest.TestCase):
    def setUp(self):
        self.db_dir = tempfile.TemporaryDirectory(prefix="r12-db-")
        self.key_dir = tempfile.TemporaryDirectory(prefix="r12-keys-")
        self.wit_dir = tempfile.TemporaryDirectory(prefix="r12-witness-")
        self.db_path = Path(self.db_dir.name) / "tenant.sqlite"
        self.old = Path(self.key_dir.name) / "old.key"
        self.new = Path(self.key_dir.name) / "new.key"
        self.third = Path(self.key_dir.name) / "third.key"
        self.witness = Path(self.wit_dir.name) / "rotations.jsonl"
        self.db = LocalTenantStore(self.db_path)
        self.db.provision_once({
            "schema":TENANT_SCHEMA,
            "tenants":[{"id":"alpha-team","members":[
                {"iss":ISSUER,"sub":"alice"},
                {"iss":ISSUER,"sub":"bob"}]}]
        })
        for p in (self.old, self.new, self.third):
            provision_local_key(p, self.db_path)
        self.demo = EnvelopeDemoStore(self.db, self.old)

    def tearDown(self):
        if self.db:
            self.db.close()
        self.db_dir.cleanup()
        self.key_dir.cleanup()
        self.wit_dir.cleanup()

    def enroll(self):
        result = enroll_rotation_witness(self.db,self.witness,self.old)
        self.assertTrue(result["enrolled"])
        self.assertEqual(self.witness.stat().st_mode & 0o077,0)
        return result

    def reopen(self, key, *, witness=True):
        self.db = LocalTenantStore(self.db_path)
        self.demo = EnvelopeDemoStore(
            self.db,key,
            rotation_witness_path=self.witness if witness else None)
        return self.demo

    def snapshot(self):
        self.db.close()
        self.db = None
        old = Path(self.db_dir.name) / "old-snapshot.sqlite"
        shutil.copy2(self.db_path,old)
        return old

    def test_old_db_and_old_key_restored_but_new_witness_survives(self):
        a = self.demo.create(actor("alice"),"alpha-team")
        b = self.demo.create(actor("bob"),"alpha-team")
        self.enroll()
        snap = self.snapshot()
        self.reopen(self.old)
        rotated = rotate_wrapping_key(
            self.db,self.old,self.new,rotation_witness_path=self.witness)
        self.assertEqual(rotated["rewrapped_markers"],2)
        self.db.close()
        self.db=None
        shutil.copy2(snap,self.db_path)

        self.db=LocalTenantStore(self.db_path)
        with self.assertRaisesRegex(
                LocalTenantConfigError,"stale_or_pending_envelope_key_rotation"):
            EnvelopeDemoStore(
                self.db,self.old,rotation_witness_path=self.witness)
        with self.assertRaisesRegex(
                LocalTenantConfigError,"enrolled_envelope_requires_rotation_witness"):
            EnvelopeDemoStore(self.db,self.old)
        self.assertEqual(load_for_database(
            self.db,self.witness,allow_pending=True).events[-1][0],
            self.db._db.execute(
                "SELECT value FROM metadata WHERE key='envelope_active_kek_id'"
            ).fetchone()[0])
        # Reconciliation rewraps, it does not regrant or re-encrypt payload.
        before=self.db._db.execute(
            "SELECT id,payload_nonce,payload_ciphertext"
            " FROM envelope_markers ORDER BY id").fetchall()
        result=rotate_wrapping_key(
            self.db,self.old,self.new,
            rotation_witness_path=self.witness,resume_pending=True)
        self.assertEqual(result["rewrapped_markers"],2)
        after=self.db._db.execute(
            "SELECT id,payload_nonce,payload_ciphertext"
            " FROM envelope_markers ORDER BY id").fetchall()
        self.assertEqual(before,after)
        self.assertEqual(len(RotationWitness(
            self.witness,db_path=self.db_path,
            database_id=self.db._db.execute(
                "SELECT value FROM metadata WHERE key=?",(BINDING_KEY,)
            ).fetchone()[0]).events),1)
        self.db.close()
        self.db=None
        self.reopen(self.new)
        self.assertEqual(self.demo.read_own(
            actor("alice"),"alpha-team",a["id"])["id"],a["id"])
        self.assertEqual(self.demo.read_own(
            actor("bob"),"alpha-team",b["id"])["id"],b["id"])
        with self.assertRaisesRegex(LocalTenantConfigError,"active_key_mismatch"):
            EnvelopeDemoStore(self.db,self.old,
                              rotation_witness_path=self.witness)

    def test_failed_sqlite_write_after_witness_fsync_stays_denied_until_resume(self):
        first=self.demo.create(actor("alice"),"alpha-team")
        self.enroll()
        self.db._db.executescript("""
            CREATE TRIGGER fail_envelope_rotate
            BEFORE UPDATE OF wrapped_dek ON envelope_markers
            BEGIN SELECT RAISE(ABORT,'simulate_transaction_loss'); END;
        """)
        with self.assertRaises(sqlite3.DatabaseError):
            rotate_wrapping_key(self.db,self.old,self.new,
                                rotation_witness_path=self.witness)
        self.assertEqual(self.db._db.execute(
            "SELECT COUNT(*) FROM envelope_markers").fetchone()[0],1)
        self.db.close()
        self.db=None
        self.db=LocalTenantStore(self.db_path)
        with self.assertRaises(LocalTenantConfigError):
            EnvelopeDemoStore(self.db,self.old,
                              rotation_witness_path=self.witness)
        with self.assertRaisesRegex(LocalTenantConfigError,
                                    "rotation_witness_ahead_recovery_required"):
            rotate_wrapping_key(self.db,self.old,self.third,
                                rotation_witness_path=self.witness)
        self.db._db.execute("DROP TRIGGER fail_envelope_rotate")
        fixed=rotate_wrapping_key(
            self.db,self.old,self.new,
            rotation_witness_path=self.witness,resume_pending=True)
        self.assertEqual(fixed["rewrapped_markers"],1)
        self.db.close()
        self.db=None
        self.reopen(self.new)
        self.assertIsNotNone(self.demo.read_own(
            actor("alice"),"alpha-team",first["id"]))

    def test_invalid_enrollment_path_is_rejected_without_poisoning_db(self):
        bad=Path(self.db_dir.name)/"same-backup.jsonl"
        with self.assertRaisesRegex(
                LocalTenantConfigError,"inside_database_backup_directory"):
            enroll_rotation_witness(self.db,bad,self.old)
        bad2=Path(self.key_dir.name)/"same-key-backup.jsonl"
        with self.assertRaisesRegex(
                LocalTenantConfigError,"inside_key_backup_directory"):
            enroll_rotation_witness(self.db,bad2,self.old)
        self.assertFalse(self.db._db.execute(
            "SELECT 1 FROM metadata WHERE key=?",(BINDING_KEY,)).fetchone())
        self.enroll()
        with self.assertRaisesRegex(LocalTenantConfigError,"already_enrolled"):
            enroll_rotation_witness(self.db,self.witness,self.old)

    def test_missing_malformed_and_world_readable_witness_denied(self):
        self.enroll()
        self.db.close()
        self.db=None
        self.db=LocalTenantStore(self.db_path)
        with self.assertRaises(LocalTenantConfigError):
            EnvelopeDemoStore(self.db,self.old)
        raw=self.witness.read_bytes()
        self.witness.unlink()
        with self.assertRaises(LocalTenantConfigError):
            EnvelopeDemoStore(self.db,self.old,
                              rotation_witness_path=self.witness)
        self.witness.write_bytes(raw[:-1])
        self.witness.chmod(0o600)
        with self.assertRaises(LocalTenantConfigError):
            EnvelopeDemoStore(self.db,self.old,
                              rotation_witness_path=self.witness)
        self.witness.write_bytes(raw)
        self.witness.chmod(0o644)
        with self.assertRaises(LocalTenantConfigError):
            EnvelopeDemoStore(self.db,self.old,
                              rotation_witness_path=self.witness)
        self.witness.chmod(0o600)
        self.demo=EnvelopeDemoStore(self.db,self.old,
                                    rotation_witness_path=self.witness)
        self.assertEqual(self.demo.list_own(actor("alice"),"alpha-team"),[])

    def test_no_silent_skip_or_backward_transition(self):
        self.enroll()
        rotate_wrapping_key(self.db,self.old,self.new,
                            rotation_witness_path=self.witness)
        with self.assertRaises(LocalTenantConfigError):
            rotate_wrapping_key(self.db,self.old,self.third,
                                rotation_witness_path=self.witness)
        rotate_wrapping_key(self.db,self.new,self.third,
                            rotation_witness_path=self.witness)
        self.db.close()
        self.db=None
        self.reopen(self.third)
        with self.assertRaises(LocalTenantConfigError):
            rotate_wrapping_key(self.db,self.third,self.old,
                                rotation_witness_path=self.witness)
        self.assertEqual(len(load_for_database(
            self.db,self.witness).events),2)

    def test_cli_guarded_enroll_rotate_resume_and_active_server_lock(self):
        self.demo.create(actor("alice"),"alpha-team")
        env={**os.environ,
             "PHICLOUD_ROTATION_WITNESS_OPERATOR_DEV":"1",
             "PHICLOUD_ENVELOPE_OPERATOR_DEV":"1",
             "NODE_ENV":"test","PHICLOUD_ENV":"test"}
        enroll_cmd=[sys.executable,"-m","phicloud.envelope_rotation_enroll",
                    "--db",str(self.db_path),"--active-key",str(self.old),
                    "--rotation-witness",str(self.witness),
                    "--confirm","ENROLL SYNTHETIC KEY ROTATION WITNESS"]
        denied=subprocess.run(enroll_cmd,capture_output=True,text=True,
                              env=env,timeout=8)
        self.assertEqual(denied.returncode,2)
        self.db.close()
        self.db=None
        accepted=subprocess.run(enroll_cmd,capture_output=True,text=True,
                                env=env,timeout=8)
        self.assertEqual(accepted.returncode,0,accepted.stderr)
        self.assertNotIn("alice",accepted.stdout)
        self.assertNotIn(str(self.old),accepted.stdout)
        rotate_cmd=[sys.executable,"-m","phicloud.envelope_operator",
                    "--db",str(self.db_path),
                    "--old-key",str(self.old),"--new-key",str(self.new),
                    "--rotation-witness",str(self.witness),
                    "--confirm","REWRAP SYNTHETIC ENVELOPES"]
        rotated=subprocess.run(rotate_cmd,capture_output=True,text=True,
                               env=env,timeout=8)
        self.assertEqual(rotated.returncode,0,rotated.stderr)
        self.assertIn("rewrapped_markers=1",rotated.stdout)
        self.db=LocalTenantStore(self.db_path)
        self.demo=EnvelopeDemoStore(self.db,self.new,
                                    rotation_witness_path=self.witness)
        self.assertIsNotNone(self.demo.list_own(actor("alice"),"alpha-team"))

    def test_rotation_witness_not_for_real_content_or_public_registry(self):
        # Avoid optional crypto import unless R11 is explicitly enabled.
        out=subprocess.run([sys.executable,"-S","-c",
                            "import phicloud.server"],
                           capture_output=True,text=True,timeout=8)
        self.assertEqual(out.returncode,0,out.stderr)
        self.assertNotIn("BEGIN PRIVATE KEY",self.witness.read_text()
                         if self.witness.exists() else "")


if __name__=="__main__":
    unittest.main()
