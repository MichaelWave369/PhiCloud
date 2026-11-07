"""PhiCloud R10: AES-256-GCM encrypted SYNTHETIC markers (local dev ONLY).

No caller-supplied plaintext, files, accounts, tokens, mail content or real data.
Each fixed synthetic marker is bound by authenticated associated data (AAD)
to its verified issuer/subject pseudonymous owner key, tenant and record ID.
An independent operator-provisioned key file is NEVER stored in SQLite.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
from pathlib import Path

from .tenant_store import LocalTenantConfigError, LocalTenantError, LocalTenantCapacity

SCHEMA = "phicloud.local-sealed-marker/0.1"
KEY_SCHEMA = "phicloud.local-sealed-key/0.1"
SYNTHETIC_VALUE = b"PHICLOUD_R10_SYNTHETIC_CANARY_NOT_USER_CONTENT_V1"
TTL = 10 * 60
MAX_PER_OWNER = 4
MAX_GLOBAL = 64


class SealedDataUnavailable(Exception):
    """Ciphertext tamper, missing key, or storage failure. Deny, never leak."""


def _private_stat(path: Path, *, directory=False):
    if not path.is_absolute() or sys.platform == "win32":
        raise LocalTenantConfigError("posix_absolute_key_path_required")
    try:
        st = path.lstat()
    except OSError as exc:
        raise LocalTenantConfigError("missing_private_encryption_key") from exc
    if st.st_mode & 0o077 or stat.S_ISLNK(st.st_mode):
        raise LocalTenantConfigError("unsafe_encryption_key_permissions")
    if directory and not stat.S_ISDIR(st.st_mode):
        raise LocalTenantConfigError("private_key_directory_required")
    if not directory and (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1):
        raise LocalTenantConfigError("private_regular_key_required")
    return st


def validate_key_destination(path: str | Path, db_path: str | Path):
    """Private, separate key directory; never place keys in SQLite backups."""
    path = Path(path)
    db = Path(db_path)
    if not path.is_absolute() or path.suffix != ".key":
        raise LocalTenantConfigError("absolute_dot_key_path_required")
    _private_stat(path.parent, directory=True)
    if path.parent.resolve() == db.parent.resolve():
        raise LocalTenantConfigError("independent_key_directory_required")
    return path


def provision_local_key(path: str | Path, db_path: str | Path) -> None:
    target = validate_key_destination(path, db_path)
    # Exclusive create plus O_NOFOLLOW; never overwrite a key and orphan data.
    old_mask = os.umask(0o077)
    try:
        fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError as exc:
        raise LocalTenantConfigError("local_key_already_exists") from exc
    finally:
        os.umask(old_mask)
    try:
        material = os.urandom(32)
        written = os.write(fd, material)
        if written != 32:
            raise LocalTenantConfigError("local_key_write_failed")
        os.fsync(fd)
    finally:
        os.close(fd)
    dir_fd = os.open(str(target.parent), os.O_RDONLY |
                     getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def read_local_key(path: str | Path, db_path: str | Path) -> bytes:
    target = validate_key_destination(path, db_path)
    _private_stat(target)
    fd = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or
                st.st_mode & 0o077 or st.st_size != 32):
            raise LocalTenantConfigError("invalid_private_encryption_key")
        material = os.read(fd, 33)
        if len(material) != 32:
            raise LocalTenantConfigError("invalid_private_encryption_key")
        return material
    finally:
        os.close(fd)


class SealedDemoStore:
    def __init__(self, tenant_store, key_path: str | Path):
        # The default R0 public registry and R6 tenant store remain stdlib
        # only. Load the pinned optional crypto dependency when R10 is on.
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._store = tenant_store
        key = read_local_key(key_path, tenant_store.path)
        self._aead = AESGCM(key)
        # This is a NON-SECRET fingerprint of a random 256-bit key, used only
        # for mismatch detection, not as authority or a decryption capability.
        fingerprint = hashlib.sha256(b"PhiCloud-R10-key-id\0" + key).hexdigest()
        with tenant_store._lock:
            db = tenant_store._db
            db.executescript("""
                CREATE TABLE IF NOT EXISTS sealed_markers (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL,
                    owner_key TEXT NOT NULL,
                    nonce BLOB NOT NULL,
                    ciphertext BLOB NOT NULL,
                    created INTEGER NOT NULL,
                    expires INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS sealed_markers_by_owner
                  ON sealed_markers(tenant_id,owner_key,expires);
            """)
            existing = db.execute(
                "SELECT value FROM metadata WHERE key='sealed_marker_key_id'"
            ).fetchone()
            if existing is None:
                count = db.execute("SELECT COUNT(*) FROM sealed_markers").fetchone()[0]
                if count:
                    raise LocalTenantConfigError("sealed_rows_without_key_binding")
                db.execute(
                    "INSERT INTO metadata(key,value) VALUES('sealed_marker_key_id',?)",
                    (fingerprint,))
            elif existing[0] != fingerprint:
                raise LocalTenantConfigError("sealed_marker_key_mismatch")

    @staticmethod
    def _aad(tenant, owner, marker_id, created, expires) -> bytes:
        return json.dumps(
            [SCHEMA, tenant, owner, marker_id, created, expires],
            ensure_ascii=True, separators=(",", ":")
        ).encode("ascii")

    def _identity(self, principal, tenant):
        tenant = self._store._tenant_id(tenant)
        owner = self._store._owner_key(principal)
        return tenant, owner

    def _verify(self, row):
        marker_id, tenant, owner, nonce, ciphertext, created, expires = row
        if (type(nonce) is not bytes or len(nonce) != 12
                or type(ciphertext) is not bytes or len(ciphertext) > 1024
                or len(ciphertext) < 16):
            raise SealedDataUnavailable("corrupt_encrypted_marker")
        from cryptography.exceptions import InvalidTag

        try:
            plaintext = self._aead.decrypt(
                nonce, ciphertext, self._aad(tenant, owner, marker_id, created, expires)
            )
        except (InvalidTag, ValueError) as exc:
            raise SealedDataUnavailable("encrypted_marker_integrity_failed") from exc
        if plaintext != SYNTHETIC_VALUE:
            raise SealedDataUnavailable("unrecognized_synthetic_marker")

    @staticmethod
    def _view(row):
        marker_id, tenant, _owner, _nonce, _ciphertext, created, expires = row
        return {
            "schema": SCHEMA, "id": marker_id, "tenant": tenant,
            "kind": "encrypted_synthetic_canary_only",
            "encrypted_at_rest": True, "authenticated_integrity": True,
            "created_at_epoch": created, "expires_at_epoch": expires,
            "plaintext_returned": False, "user_content_allowed": False,
            "real_files": False, "cloud_storage_access": False,
            "mailbox_access": False, "phios_effect_authority": False,
        }

    def _prune(self, now):
        self._store._db.execute(
            "DELETE FROM sealed_markers WHERE expires<=?", (now,))

    def create(self, principal, tenant):
        tenant, owner = self._identity(principal, tenant)
        with self._store._lock:
            db = self._store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                self._store._require_member(tenant, owner)
                now = self._store._now()
                self._prune(now)
                own = db.execute(
                    "SELECT COUNT(*) FROM sealed_markers"
                    " WHERE tenant_id=? AND owner_key=?", (tenant, owner)
                ).fetchone()[0]
                total = db.execute("SELECT COUNT(*) FROM sealed_markers").fetchone()[0]
                if own >= MAX_PER_OWNER or total >= MAX_GLOBAL:
                    raise LocalTenantCapacity("sealed_marker_capacity")
                marker_id = secrets.token_urlsafe(24)
                created, expires = now, now + TTL
                nonce = os.urandom(12)
                ciphertext = self._aead.encrypt(
                    nonce, SYNTHETIC_VALUE,
                    self._aad(tenant, owner, marker_id, created, expires)
                )
                db.execute(
                    "INSERT INTO sealed_markers"
                    " (id,tenant_id,owner_key,nonce,ciphertext,created,expires)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (marker_id, tenant, owner, nonce, ciphertext, created, expires)
                )
                db.execute("COMMIT")
                return {
                    "schema": SCHEMA, "id": marker_id, "tenant": tenant,
                    "encrypted_at_rest": True, "plaintext_returned": False,
                    "user_content_allowed": False, "persistent_local_only": True,
                }
            except Exception:
                db.execute("ROLLBACK")
                raise

    def _read_rows(self, tenant, owner, marker_id=None):
        if marker_id is None:
            return self._store._db.execute(
                "SELECT id,tenant_id,owner_key,nonce,ciphertext,created,expires"
                " FROM sealed_markers WHERE tenant_id=? AND owner_key=? AND expires>?"
                " ORDER BY id LIMIT ?", (tenant, owner, self._store._now(), MAX_PER_OWNER)
            ).fetchall()
        if not isinstance(marker_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", marker_id):
            return []
        return self._store._db.execute(
            "SELECT id,tenant_id,owner_key,nonce,ciphertext,created,expires"
            " FROM sealed_markers WHERE tenant_id=? AND owner_key=?"
            " AND id=? AND expires>?",
            (tenant, owner, marker_id, self._store._now())
        ).fetchall()

    def list_own(self, principal, tenant):
        tenant, owner = self._identity(principal, tenant)
        with self._store._lock:
            self._store._require_member(tenant, owner)
            rows = self._read_rows(tenant, owner)
            for row in rows:
                self._verify(row)
            return [self._view(row) for row in rows]

    def read_own(self, principal, tenant, marker_id):
        tenant, owner = self._identity(principal, tenant)
        with self._store._lock:
            self._store._require_member(tenant, owner)
            rows = self._read_rows(tenant, owner, marker_id)
            if not rows:
                return None
            self._verify(rows[0])
            return self._view(rows[0])

    def delete_own(self, principal, tenant, marker_id):
        tenant, owner = self._identity(principal, tenant)
        with self._store._lock:
            db = self._store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                self._store._require_member(tenant, owner)
                rows = self._read_rows(tenant, owner, marker_id)
                if not rows:
                    raise LocalTenantError("unknown_resource")
                self._verify(rows[0])
                db.execute(
                    "DELETE FROM sealed_markers WHERE id=? AND tenant_id=? AND owner_key=?",
                    (marker_id, tenant, owner)
                )
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise


def create_sealed_demo(store, env=None):
    settings = os.environ if env is None else env
    if settings.get("PHICLOUD_ENABLE_SEALED_DEV") != "1":
        return None
    if store is None or settings.get("PHICLOUD_ENV") == "production" or settings.get("NODE_ENV") == "production":
        raise LocalTenantConfigError("sealed_dev_requires_nonproduction_tenant_store")
    key_path = settings.get("PHICLOUD_SEALED_KEY_PATH")
    if not key_path:
        raise LocalTenantConfigError("independent_private_key_path_required")
    return SealedDemoStore(store, key_path)
