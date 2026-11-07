"""R11 local envelope encryption of *fixed synthetic* markers, never user files.

Each synthetic marker gets a random per-record 256-bit DEK, which encrypts
one non-personal canary via AES-256-GCM. An independently provisioned KEK
wraps that DEK using another AES-256-GCM invocation. Both encryptions bind
tenant, introspection-verified owner pseudonym, record ID, and lifetime as
authenticated associated data.

This is NOT customer encryption, key escrow, KMS, recovery or production data.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from pathlib import Path

from .sealed_demo import read_local_key
from .tenant_store import LocalTenantConfigError, LocalTenantError, LocalTenantCapacity

SCHEMA = "phicloud.local-envelope-canary/0.1"
CANARY = b"PHICLOUD_R11_FIXED_SYNTHETIC_CANARY_NOT_USER_CONTENT_V1"
TTL = 600
MAX_OWNER = 4
MAX_TOTAL = 64
_ID_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$")


class EnvelopeIntegrityError(Exception):
    """Malformed, mismatched or corrupted wrapping or payload; fail closed."""


def _aesgcm():
    # Do not force public R0 registry users to install cryptography.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
    return AESGCM, InvalidTag


def _key_id(key: bytes) -> str:
    # Random-key equality fingerprint only. Never a token or credential.
    return hashlib.sha256(b"PhiCloud-R11-KEK-ID/1\0" + key).hexdigest()


def _aad(purpose: str, tenant: str, owner: str,
         marker_id: str, created: int, expires: int) -> bytes:
    return json.dumps([SCHEMA, purpose, tenant, owner, marker_id, created, expires],
                      ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _read_and_verify(row, kek: bytes) -> bytes:
    marker_id, tenant, owner, payload_nonce, encrypted_payload, wrap_nonce, wrapped_dek, created, expires = row
    fields = (payload_nonce, encrypted_payload, wrap_nonce, wrapped_dek)
    if (any(type(v) is not bytes for v in fields)
            or len(payload_nonce) != 12 or len(wrap_nonce) != 12
            or not 16 <= len(encrypted_payload) <= 512
            or len(wrapped_dek) != 48
            or not isinstance(marker_id, str) or not _ID_RE.fullmatch(marker_id)):
        raise EnvelopeIntegrityError("malformed_envelope_row")
    AESGCM, InvalidTag = _aesgcm()
    try:
        dek = AESGCM(kek).decrypt(
            wrap_nonce, wrapped_dek,
            _aad("wrap", tenant, owner, marker_id, created, expires))
        if len(dek) != 32:
            raise EnvelopeIntegrityError("unexpected_data_key_size")
        plaintext = AESGCM(dek).decrypt(
            payload_nonce, encrypted_payload,
            _aad("payload", tenant, owner, marker_id, created, expires))
    except (InvalidTag, ValueError) as exc:
        raise EnvelopeIntegrityError("envelope_integrity_denied") from exc
    if plaintext != CANARY:
        raise EnvelopeIntegrityError("unexpected_synthetic_value")
    return dek


class EnvelopeDemoStore:
    """Independent bounded table; never upgrade R10 markers in place."""

    def __init__(self, tenant_store, key_path: str | Path):
        self._store = tenant_store
        self._kek = read_local_key(key_path, tenant_store.path)
        self.key_id = _key_id(self._kek)
        with tenant_store._lock:
            db = tenant_store._db
            db.executescript("""
                CREATE TABLE IF NOT EXISTS envelope_markers (
                    id TEXT PRIMARY KEY NOT NULL,
                    tenant_id TEXT NOT NULL,
                    owner_key TEXT NOT NULL,
                    payload_nonce BLOB NOT NULL,
                    payload_ciphertext BLOB NOT NULL,
                    wrap_nonce BLOB NOT NULL,
                    wrapped_dek BLOB NOT NULL,
                    created INTEGER NOT NULL,
                    expires INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS envelopes_by_owner
                  ON envelope_markers(tenant_id,owner_key,expires);
            """)
            row = db.execute(
                "SELECT value FROM metadata WHERE key='envelope_active_kek_id'"
            ).fetchone()
            if row is None:
                if db.execute("SELECT 1 FROM envelope_markers LIMIT 1").fetchone():
                    raise LocalTenantConfigError("envelopes_without_key_binding")
                db.execute(
                    "INSERT INTO metadata(key,value)"
                    " VALUES('envelope_active_kek_id',?)", (self.key_id,))
            elif row[0] != self.key_id:
                raise LocalTenantConfigError("envelope_active_key_mismatch")

    def _actor(self, principal, tenant):
        return (self._store._tenant_id(tenant),
                self._store._owner_key(principal))

    @staticmethod
    def _view(row):
        return {
            "schema": SCHEMA, "id": row[0], "tenant": row[1],
            "kind": "envelope_encrypted_synthetic_canary",
            "per_record_data_key": True,
            "wrapped_data_key": True,
            "plaintext_returned": False,
            "user_content_allowed": False,
            "real_files": False, "cloud_storage_access": False,
            "mailbox_access": False, "phios_effect_authority": False,
        }

    @staticmethod
    def _select():
        return ("SELECT id,tenant_id,owner_key,payload_nonce,payload_ciphertext,"
                "wrap_nonce,wrapped_dek,created,expires FROM envelope_markers")

    def _rows(self, tenant, owner, marker_id=None):
        db = self._store._db
        if marker_id is None:
            return db.execute(
                self._select() + " WHERE tenant_id=? AND owner_key=?"
                " AND expires>? ORDER BY id LIMIT ?",
                (tenant, owner, self._store._now(), MAX_OWNER)
            ).fetchall()
        if not isinstance(marker_id, str) or not _ID_RE.fullmatch(marker_id):
            return []
        return db.execute(
            self._select() +
            " WHERE tenant_id=? AND owner_key=? AND id=? AND expires>?",
            (tenant, owner, marker_id, self._store._now())
        ).fetchall()

    def create(self, principal, tenant):
        tenant, owner = self._actor(principal, tenant)
        AESGCM, _ = _aesgcm()
        with self._store._lock:
            db = self._store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                self._store._require_member(tenant, owner)
                now = self._store._now()
                db.execute("DELETE FROM envelope_markers WHERE expires<=?", (now,))
                own = db.execute(
                    "SELECT COUNT(*) FROM envelope_markers"
                    " WHERE tenant_id=? AND owner_key=?", (tenant, owner)
                ).fetchone()[0]
                total = db.execute(
                    "SELECT COUNT(*) FROM envelope_markers"
                ).fetchone()[0]
                if own >= MAX_OWNER or total >= MAX_TOTAL:
                    raise LocalTenantCapacity("envelope_marker_capacity")
                marker_id = secrets.token_urlsafe(24)
                expires = now + TTL
                dek = os.urandom(32)
                payload_nonce, wrap_nonce = os.urandom(12), os.urandom(12)
                ciphertext = AESGCM(dek).encrypt(
                    payload_nonce, CANARY,
                    _aad("payload", tenant, owner, marker_id, now, expires))
                wrapped = AESGCM(self._kek).encrypt(
                    wrap_nonce, dek,
                    _aad("wrap", tenant, owner, marker_id, now, expires))
                db.execute(
                    "INSERT INTO envelope_markers"
                    " (id,tenant_id,owner_key,payload_nonce,payload_ciphertext,"
                    " wrap_nonce,wrapped_dek,created,expires)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (marker_id, tenant, owner, payload_nonce, ciphertext,
                     wrap_nonce, wrapped, now, expires))
                db.execute("COMMIT")
                return {
                    "schema": SCHEMA, "id": marker_id, "tenant": tenant,
                    "per_record_data_key": True, "wrapped_data_key": True,
                    "plaintext_returned": False, "user_content_allowed": False
                }
            except Exception:
                db.execute("ROLLBACK")
                raise

    def list_own(self, principal, tenant):
        tenant, owner = self._actor(principal, tenant)
        with self._store._lock:
            self._store._require_member(tenant, owner)
            rows = self._rows(tenant, owner)
            for row in rows:
                _read_and_verify(row, self._kek)
            return [self._view(row) for row in rows]

    def read_own(self, principal, tenant, marker_id):
        tenant, owner = self._actor(principal, tenant)
        with self._store._lock:
            self._store._require_member(tenant, owner)
            rows = self._rows(tenant, owner, marker_id)
            if not rows:
                return None
            _read_and_verify(rows[0], self._kek)
            return self._view(rows[0])

    def delete_own(self, principal, tenant, marker_id):
        tenant, owner = self._actor(principal, tenant)
        with self._store._lock:
            db = self._store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                self._store._require_member(tenant, owner)
                rows = self._rows(tenant, owner, marker_id)
                if not rows:
                    raise LocalTenantError("unknown_resource")
                _read_and_verify(rows[0], self._kek)
                db.execute(
                    "DELETE FROM envelope_markers"
                    " WHERE id=? AND tenant_id=? AND owner_key=?",
                    (marker_id, tenant, owner))
                db.execute("COMMIT")
            except Exception:
                db.execute("ROLLBACK")
                raise


def rotate_wrapping_key(tenant_store, old_path: str | Path,
                        new_path: str | Path) -> dict:
    """Offline atomic KEK rotation: payload ciphertext remains byte-identical.

    Both old/new key files must already exist OUTSIDE the SQLite backup dir.
    A database exclusive lease must be held by the offline operator. Never
    unlink the old file here, since a failed transaction needs it for recovery.
    """
    old_path, new_path = Path(old_path), Path(new_path)
    if old_path == new_path or old_path.resolve() == new_path.resolve():
        raise LocalTenantConfigError("distinct_wrapping_keys_required")
    old_key = read_local_key(old_path, tenant_store.path)
    new_key = read_local_key(new_path, tenant_store.path)
    old_id, new_id = _key_id(old_key), _key_id(new_key)
    if old_id == new_id:
        raise LocalTenantConfigError("new_wrapping_key_must_differ")
    AESGCM, _ = _aesgcm()
    with tenant_store._lock:
        db = tenant_store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            active = db.execute(
                "SELECT value FROM metadata WHERE key='envelope_active_kek_id'"
            ).fetchone()
            if active is None or active[0] != old_id:
                raise LocalTenantConfigError("old_wrapping_key_not_active")
            rows = db.execute(EnvelopeDemoStore._select()).fetchall()
            count = 0
            for row in rows:
                dek = _read_and_verify(row, old_key)
                marker_id, tenant, owner, _, _, _, _, created, expires = row
                new_nonce = os.urandom(12)
                new_wrapped = AESGCM(new_key).encrypt(
                    new_nonce, dek,
                    _aad("wrap", tenant, owner, marker_id, created, expires))
                db.execute(
                    "UPDATE envelope_markers SET wrap_nonce=?,wrapped_dek=?"
                    " WHERE id=?", (new_nonce, new_wrapped, marker_id))
                count += 1
            db.execute(
                "UPDATE metadata SET value=? WHERE key='envelope_active_kek_id'",
                (new_id,))
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise
    return {
        "schema": "phicloud.local-envelope-rotation/0.1",
        "rewrapped_markers": count,
        "payload_reencrypted": False,
        "plaintext_returned": False,
        "keys_deleted": False,
        "user_content_allowed": False,
        "production_effects": False,
    }


def create_envelope_demo(tenant_store, env=None):
    settings = os.environ if env is None else env
    if settings.get("PHICLOUD_ENABLE_ENVELOPE_DEV") != "1":
        return None
    if (tenant_store is None or settings.get("NODE_ENV") == "production"
            or settings.get("PHICLOUD_ENV") == "production"):
        raise LocalTenantConfigError("envelope_requires_private_nonproduction_tenant")
    key_path = settings.get("PHICLOUD_ENVELOPE_KEK_PATH")
    if not key_path:
        raise LocalTenantConfigError("independent_wrapping_key_required")
    return EnvelopeDemoStore(tenant_store, key_path)
