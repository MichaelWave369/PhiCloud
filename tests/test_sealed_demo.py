"""R10 encrypted canary: no real files, scoped owner-bound AES-GCM integrity."""
from __future__ import annotations

import os
import sqlite3
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen
import json

from phicloud.authz import ISSUER, AUDIENCE, LocalTokenIntrospector
from phicloud.sealed_demo import (
    SYNTHETIC_VALUE, SealedDataUnavailable, SealedDemoStore,
    create_sealed_demo, provision_local_key, read_local_key,
)
from phicloud.server import LOOPBACK, make_handler
from phicloud.tenant_store import (
    LocalTenantConfigError, LocalTenantError, LocalTenantStore, TENANT_SCHEMA
)

SECRET = "r10-only-local-fake-client-secret-" + "s" * 40
ALICE = "alice-" + "A" * 40
BOB = "bob-" + "B" * 40
READ = "read-" + "C" * 40
WRITE = "write-" + "D" * 40
PROFILE = "profile-" + "E" * 40


def who(subject):
    return SimpleNamespace(issuer=ISSUER, sub=subject)


def fixture():
    return {"schema": TENANT_SCHEMA, "tenants": [
        {"id": "alpha-team", "members": [
            {"iss": ISSUER, "sub": "alice"},
            {"iss": ISSUER, "sub": "bob"}]},
        {"id": "beta-team", "members": [
            {"iss": ISSUER, "sub": "bob"}]},
    ]}


class SealedStoreTests(unittest.TestCase):
    def setUp(self):
        self.db_dir = tempfile.TemporaryDirectory(prefix="r10-data-")
        self.key_dir = tempfile.TemporaryDirectory(prefix="r10-key-")
        self.path = Path(self.db_dir.name) / "tenant.sqlite"
        self.key_path = Path(self.key_dir.name) / "sealed.key"
        self.tenant_store = LocalTenantStore(self.path)
        self.tenant_store.provision_once(fixture())
        provision_local_key(self.key_path, self.path)
        self.sealed = SealedDemoStore(self.tenant_store, self.key_path)

    def tearDown(self):
        if self.tenant_store:
            self.tenant_store.close()
        self.db_dir.cleanup()
        self.key_dir.cleanup()

    def test_independent_key_is_private_and_no_plaintext_in_database(self):
        self.assertEqual(self.key_path.stat().st_mode & 0o077, 0)
        self.assertEqual(len(read_local_key(self.key_path, self.path)), 32)
        created = self.sealed.create(who("alice"), "alpha-team")
        self.assertTrue(created["encrypted_at_rest"])
        self.assertNotIn("plaintext", str(created).replace("plaintext_returned", ""))
        row = self.tenant_store._db.execute(
            "SELECT nonce,ciphertext FROM sealed_markers WHERE id=?",
            (created["id"],)
        ).fetchone()
        self.assertEqual(len(row[0]), 12)
        self.assertNotIn(SYNTHETIC_VALUE, row[1])
        self.assertNotIn(read_local_key(self.key_path, self.path), self.path.read_bytes())
        shown = self.sealed.read_own(who("alice"), "alpha-team", created["id"])
        self.assertTrue(shown["authenticated_integrity"])
        self.assertFalse(shown["plaintext_returned"])
        self.assertFalse(shown["user_content_allowed"])

    def test_cross_user_and_cross_tenant_denied_even_with_known_id(self):
        a = self.sealed.create(who("alice"), "alpha-team")
        b = self.sealed.create(who("bob"), "alpha-team")
        self.assertIsNone(self.sealed.read_own(who("bob"), "alpha-team", a["id"]))
        self.assertIsNone(self.sealed.read_own(who("alice"), "alpha-team", b["id"]))
        with self.assertRaises(LocalTenantError):
            self.sealed.read_own(who("alice"), "beta-team", a["id"])
        with self.assertRaises(LocalTenantError):
            self.sealed.delete_own(who("bob"), "alpha-team", a["id"])
        self.assertEqual(
            [r["id"] for r in self.sealed.list_own(who("alice"), "alpha-team")],
            [a["id"]]
        )

    def test_ciphertext_nonce_owner_and_aad_tampering_fail_closed(self):
        a = self.sealed.create(who("alice"), "alpha-team")
        row = self.tenant_store._db.execute(
            "SELECT ciphertext FROM sealed_markers WHERE id=?", (a["id"],)
        ).fetchone()[0]
        tampered = row[:-1] + bytes([row[-1] ^ 1])
        self.tenant_store._db.execute(
            "UPDATE sealed_markers SET ciphertext=? WHERE id=?", (tampered,a["id"])
        )
        with self.assertRaises(SealedDataUnavailable):
            self.sealed.read_own(who("alice"), "alpha-team", a["id"])
        with self.assertRaises(SealedDataUnavailable):
            self.sealed.list_own(who("alice"), "alpha-team")
        with self.assertRaises(SealedDataUnavailable):
            self.sealed.delete_own(who("alice"), "alpha-team", a["id"])
        self.tenant_store._db.execute(
            "UPDATE sealed_markers SET ciphertext=? WHERE id=?", (row,a["id"])
        )
        self.tenant_store._db.execute(
            "UPDATE sealed_markers SET tenant_id='beta-team',owner_key=? WHERE id=?",
            (self.tenant_store._owner_key(who("bob")), a["id"])
        )
        with self.assertRaises(SealedDataUnavailable):
            self.sealed.read_own(who("bob"), "beta-team", a["id"])

    def test_restart_and_wrong_key_fail_closed(self):
        a = self.sealed.create(who("alice"), "alpha-team")
        self.tenant_store.close()
        self.tenant_store = LocalTenantStore(self.path)
        self.sealed = SealedDemoStore(self.tenant_store,self.key_path)
        self.assertEqual(
            self.sealed.read_own(who("alice"), "alpha-team", a["id"])["id"], a["id"]
        )
        self.key_path.unlink()
        with self.assertRaises(LocalTenantConfigError):
            SealedDemoStore(self.tenant_store, self.key_path)
        provision_local_key(self.key_path,self.path)
        with self.assertRaisesRegex(LocalTenantConfigError,"key_mismatch"):
            SealedDemoStore(self.tenant_store, self.key_path)

    def test_private_key_path_and_reuse_rejected(self):
        with self.assertRaises(LocalTenantConfigError):
            provision_local_key(self.key_path,self.path)
        with self.assertRaises(LocalTenantConfigError):
            provision_local_key(Path(self.db_dir.name)/"shared.key",self.path)
        self.key_path.chmod(0o644)
        with self.assertRaises(LocalTenantConfigError):
            read_local_key(self.key_path,self.path)
        self.key_path.chmod(0o600)
        dangling=Path(self.key_dir.name)/"dangling.key"
        dangling.symlink_to(Path(self.key_dir.name)/"nonexistent.key")
        with self.assertRaises(LocalTenantConfigError):
            read_local_key(dangling,self.path)

    def test_revocation_purges_ciphertext_without_enabled_demo_key(self):
        a=self.sealed.create(who("alice"),"alpha-team")
        b=self.sealed.create(who("bob"),"alpha-team")
        self.tenant_store.revoke_member_offline("alpha-team",who("alice"))
        self.assertEqual(
            self.tenant_store._db.execute(
                "SELECT COUNT(*) FROM sealed_markers WHERE id=?", (a["id"],)
            ).fetchone()[0],0
        )
        self.assertEqual(
            self.tenant_store._db.execute(
                "SELECT COUNT(*) FROM sealed_markers WHERE id=?", (b["id"],)
            ).fetchone()[0],1
        )
        with self.assertRaises(LocalTenantError):
            self.sealed.create(who("alice"),"alpha-team")

    def test_off_by_default_and_production_denied(self):
        self.assertIsNone(create_sealed_demo(self.tenant_store,{}))
        with self.assertRaises(LocalTenantConfigError):
            create_sealed_demo(None,{"PHICLOUD_ENABLE_SEALED_DEV":"1"})
        with self.assertRaises(LocalTenantConfigError):
            create_sealed_demo(self.tenant_store,{
                "PHICLOUD_ENABLE_SEALED_DEV":"1",
                "PHICLOUD_SEALED_KEY_PATH":str(self.key_path),
                "PHICLOUD_ENV":"production",
            })


class SealedHttpTests(unittest.TestCase):
    def setUp(self):
        self.db_dir = tempfile.TemporaryDirectory()
        self.key_dir = tempfile.TemporaryDirectory()
        self.store=LocalTenantStore(Path(self.db_dir.name)/"test.sqlite")
        self.store.provision_once(fixture())
        self.key=Path(self.key_dir.name)/"sealed.key"
        provision_local_key(self.key,self.store.path)
        self.sealed=SealedDemoStore(self.store,self.key)
        self.revoked=set()
        self.offline=False

        def introspect(token,secret):
            self.assertEqual(secret,SECRET)
            if self.offline:
                raise OSError("provider down")
            if token in self.revoked:
                return {"active":False}
            token_map={
                ALICE:("alice","phicloud.sealed.read phicloud.sealed.write"),
                BOB:("bob","phicloud.sealed.read phicloud.sealed.write"),
                READ:("alice","phicloud.sealed.read"),
                WRITE:("alice","phicloud.sealed.write"),
                PROFILE:("alice","phicloud.tenant.read"),
            }
            owner,scopes=token_map.get(token,("outsider",""))
            return {"active":True,"iss":ISSUER,"sub":owner,
                    "scope":scopes,"aud":[AUDIENCE],"token_type":"Bearer",
                    "exp":int(time.time())+300}
        gate=LocalTokenIntrospector(SECRET,transport=introspect)
        self.server=ThreadingHTTPServer(
            (LOOPBACK,0),make_handler(
                {"schema":"phicloud.services.v0.1","services":[]},
                gate,None,self.store,self.sealed
            )
        )
        self.worker=threading.Thread(target=self.server.serve_forever,daemon=True)
        self.worker.start()
        self.base=f"http://{LOOPBACK}:{self.server.server_port}/v1/private/tenants"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.store.close()
        self.db_dir.cleanup()
        self.key_dir.cleanup()

    def call(self,method,tenant="alpha-team",token=ALICE,marker=None,action=None,
             body=None,extra=None):
        url=self.base+"/"+tenant+"/sealed-markers"
        if marker is not None:
            url+="/"+marker
        headers=dict(extra or {})
        if token is not None:
            headers["Authorization"]="Bearer "+token
        if action:
            headers["X-PhiCloud-Action"]=action
        req=Request(url,method=method,headers=headers,data=body)
        try:
            with urlopen(req,timeout=3) as resp:
                return resp.status,json.load(resp)
        except HTTPError as error:
            return error.code,json.load(error)

    def test_two_valid_users_and_precise_scopes(self):
        code,a=self.call("POST",action="create-sealed-test-marker")
        self.assertEqual(code,201)
        code,b=self.call("POST",token=BOB,action="create-sealed-test-marker")
        self.assertEqual(code,201)
        self.assertEqual(self.call("GET",token=BOB,marker=a["id"])[0],404)
        self.assertEqual(self.call("GET",marker=b["id"])[0],404)
        self.assertEqual(self.call("DELETE",token=BOB,marker=a["id"],
                                   action="delete-sealed-test-marker")[0],404)
        self.assertEqual(self.call("GET",marker=a["id"])[0],200)
        self.assertEqual(self.call("GET",token=WRITE)[0],401)
        self.assertEqual(self.call("POST",token=READ,
                                   action="create-sealed-test-marker")[0],401)
        self.assertEqual(self.call("GET",token=PROFILE)[0],401)
        self.assertEqual(self.call("GET",tenant="beta-team")[0],404)
        self.assertEqual(self.call("POST",action="create-sealed-test-marker",
                                   extra={"Origin":"https://attacker.invalid"})[0],403)
        self.assertEqual(self.call("POST",action="create-sealed-test-marker",
                                   body=b'{"owner":"bob"}')[0],413)

    def test_revocation_and_corruption_do_not_decrypt(self):
        code,a=self.call("POST",action="create-sealed-test-marker")
        self.assertEqual(code,201)
        self.revoked.add(ALICE)
        self.assertEqual(self.call("GET",marker=a["id"])[0],401)
        self.revoked.clear()
        self.offline=True
        self.assertEqual(self.call("GET",marker=a["id"])[0],503)
        self.offline=False
        self.store._db.execute(
            "UPDATE sealed_markers SET ciphertext=X'00' WHERE id=?", (a["id"],)
        )
        self.assertEqual(self.call("GET",marker=a["id"])[0],503)


if __name__=="__main__":
    unittest.main()
