"""PhiCloud R6: private, local durable SYNTHETIC tenant/owner audit fixture.

NOT a general-purpose database for user files, tenant administration, or
production authorization. Membership is provisioned exclusively at startup
from a trusted operator-owned development fixture; HTTP callers cannot create
tenants, choose ownership, grant membership, or set record contents.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import stat
import sys
import threading
import time
from pathlib import Path

from .authz import ISSUER
from .tenant_fence import RevocationWitness, WitnessError

TENANT_SCHEMA = "phicloud.local-tenant-demo.v0.1"
_TENANT = re.compile(r"^[a-z][a-z0-9-]{2,31}$")
_ID = re.compile(r"^[A-Za-z0-9_-]{24,64}$")
MAX_TENANTS = 8
MAX_MEMBERS = 16
MAX_OWNER_RECORDS = 8
MAX_RECORDS = 128
MAX_AUDIT = 1024
RECORD_TTL = 30 * 24 * 3600
AUDIT_TTL = 90 * 24 * 3600


class LocalTenantError(Exception):
    """Wrong tenant, owner, membership or resource: indistinguishable 404."""


class LocalTenantCapacity(Exception):
    """Bounded development store is full; no eviction of other owners."""


class LocalTenantConfigError(ValueError):
    """Unsafe local database or operator-only fixture configuration."""


def _path_stat(path: Path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _check_db_path(path: Path) -> None:
    if sys.platform == "win32":
        raise LocalTenantConfigError("private_posix_or_wsl_environment_required")
    if not path.is_absolute() or path.suffix != ".sqlite":
        raise LocalTenantConfigError("absolute_private_sqlite_path_required")
    parent = path.parent
    directory = _path_stat(parent)
    if (directory is None or not stat.S_ISDIR(directory.st_mode)
            or stat.S_ISLNK(directory.st_mode)
            or (directory.st_mode & 0o077)):
        raise LocalTenantConfigError("private_directory_0700_required")
    file_stat = _path_stat(path)
    if file_stat and (not stat.S_ISREG(file_stat.st_mode)
                      or stat.S_ISLNK(file_stat.st_mode)
                      or file_stat.st_mode & 0o077):
        raise LocalTenantConfigError("private_file_0600_required")


def _acquire_private_database_lock(db_path: Path) -> int:
    """Exclusive POSIX advisory lock shared by app and offline operator.

    The lock file is never unlinked, preventing process-to-process inode swaps.
    A running server makes the offline membership command fail immediately.
    """
    import fcntl

    lock_path = Path(str(db_path) + ".lock")
    existing = _path_stat(lock_path)
    if existing is not None and (
        not stat.S_ISREG(existing.st_mode)
        or stat.S_ISLNK(existing.st_mode)
        or existing.st_mode & 0o077
    ):
        raise LocalTenantConfigError("unsafe_tenant_lock_file")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    old_mask = os.umask(0o077)
    try:
        fd = os.open(str(lock_path), flags, 0o600)
    finally:
        os.umask(old_mask)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or opened.st_mode & 0o077:
            raise LocalTenantConfigError("unsafe_tenant_lock_file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise LocalTenantConfigError("tenant_database_in_use_stop_service_first") from exc
        return fd
    except Exception:
        os.close(fd)
        raise


def _principal(principal) -> tuple[str, str]:
    issuer = getattr(principal, "issuer", None)
    subject = getattr(principal, "sub", None)
    if (issuer != ISSUER or not isinstance(subject, str)
            or not 1 <= len(subject) <= 255 or any(ord(c) < 33 for c in subject)):
        raise LocalTenantError("invalid_verified_principal")
    return issuer, subject


class LocalTenantStore:
    """One-process, lock-protected SQLite store with atomic tenant/owner checks."""

    def __init__(self, path: str | Path, *, clock=time.time,
                 fence_path: str | Path | None = None,
                 recovery_mode: bool = False) -> None:
        self.path = Path(path)
        _check_db_path(self.path)
        self._lease_fd = _acquire_private_database_lock(self.path)
        self._lock = threading.RLock()
        self._clock = clock
        self._fence = None
        self._recovery_mode = recovery_mode
        old_mask = os.umask(0o077)
        try:
            try:
                self._db = sqlite3.connect(str(self.path), isolation_level=None,
                                           check_same_thread=False, timeout=3.0)
            except Exception:
                os.close(self._lease_fd)
                raise
        finally:
            os.umask(old_mask)
        os.chmod(self.path, 0o600)
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.execute("PRAGMA journal_mode = DELETE")
        self._db.execute("PRAGMA synchronous = FULL")
        self._db.execute("PRAGMA trusted_schema = OFF")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tenants (
                id TEXT PRIMARY KEY NOT NULL
            );
            CREATE TABLE IF NOT EXISTS memberships (
                tenant_id TEXT NOT NULL REFERENCES tenants(id),
                principal_key TEXT NOT NULL,
                PRIMARY KEY (tenant_id, principal_key)
            );
            CREATE TABLE IF NOT EXISTS records (
                id TEXT PRIMARY KEY NOT NULL,
                tenant_id TEXT NOT NULL REFERENCES tenants(id),
                owner_key TEXT NOT NULL,
                created INTEGER NOT NULL,
                expires INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS records_by_owner
              ON records(tenant_id, owner_key, created);
            CREATE TABLE IF NOT EXISTS audit (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_id TEXT NOT NULL,
                actor_key TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('create', 'delete')),
                at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS audit_by_owner
              ON audit(tenant_id, actor_key, seq);
            CREATE TABLE IF NOT EXISTS membership_revocations (
                tenant_id TEXT NOT NULL,
                principal_key TEXT NOT NULL,
                revoked_at INTEGER NOT NULL,
                removed_markers INTEGER NOT NULL,
                PRIMARY KEY (tenant_id, principal_key)
            );
            CREATE TABLE IF NOT EXISTS recovery_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                at INTEGER NOT NULL,
                restored_revocations INTEGER NOT NULL
            );
        """)
        with self._lock:
            row = self._db.execute(
                "SELECT value FROM metadata WHERE key = 'salt'").fetchone()
            if row is None:
                self._db.execute("INSERT INTO metadata(key,value) VALUES (?,?)",
                                 ("salt", secrets.token_hex(32)))
                row = self._db.execute(
                    "SELECT value FROM metadata WHERE key = 'salt'").fetchone()
            if len(row[0]) != 64 or not re.fullmatch("[a-f0-9]{64}", row[0]):
                raise LocalTenantConfigError("malformed_local_principal_salt")
            self._salt = bytes.fromhex(row[0])
        try:
            self._load_recovery_fence(fence_path)
        except Exception:
            try:
                self._db.close()
            finally:
                os.close(self._lease_fd)
                self._lease_fd = None
            raise

    def close(self) -> None:
        with self._lock:
            try:
                self._db.close()
            finally:
                if self._lease_fd is not None:
                    os.close(self._lease_fd)
                    self._lease_fd = None

    def _load_recovery_fence(self, fence_path) -> None:
        row = self._db.execute(
            "SELECT value FROM metadata WHERE key='recovery_fence_id'").fetchone()
        if row is None:
            if fence_path is not None:
                raise LocalTenantConfigError("database_not_enrolled_in_recovery_fence")
            return
        if not fence_path:
            raise LocalTenantConfigError("enrolled_database_requires_independent_fence")
        try:
            self._fence = RevocationWitness(
                fence_path, db_path=self.path, database_id=row[0])
        except WitnessError as exc:
            raise LocalTenantConfigError(str(exc)) from exc
        if not self._recovery_mode:
            self._assert_fence_consistent()

    def _assert_fence_consistent(self) -> None:
        if self._fence is None:
            return
        database_tombstones = {
            (tenant, key): timestamp for tenant, key, timestamp in
            self._db.execute(
                "SELECT tenant_id,principal_key,revoked_at FROM membership_revocations"
            ).fetchall()
        }
        if database_tombstones != self._fence.records:
            raise LocalTenantConfigError("stale_or_mismatched_sqlite_revocations")
        for tenant, key in self._fence.records:
            active = self._db.execute(
                "SELECT 1 FROM memberships WHERE tenant_id=? AND principal_key=?",
                (tenant, key)).fetchone()
            resources = self._db.execute(
                "SELECT 1 FROM records WHERE tenant_id=? AND owner_key=?",
                (tenant, key)).fetchone()
            if active or resources:
                raise LocalTenantConfigError("revoked_tenant_access_in_restored_sqlite")

    def enroll_recovery_fence(self, fence_path: str | Path) -> dict:
        """One-time OFFLINE operator enrollment; never expose through HTTP."""
        if self._fence is not None or self._db.execute(
            "SELECT 1 FROM metadata WHERE key='recovery_fence_id'").fetchone():
            raise LocalTenantConfigError("recovery_fence_already_enrolled")
        if not self._db.execute(
            "SELECT 1 FROM metadata WHERE key='provisioned'").fetchone():
            raise LocalTenantConfigError("tenant_provisioning_required_before_fence")
        existing = self._db.execute(
            "SELECT tenant_id,principal_key,revoked_at FROM membership_revocations"
            " ORDER BY tenant_id,principal_key").fetchall()
        new_id = secrets.token_hex(32)
        with self._lock:
            # Bind the DB first: if file creation fails, subsequent server
            # startup MUST fail closed rather than quietly run unfenced.
            self._db.execute(
                "INSERT INTO metadata(key,value) VALUES('recovery_fence_id',?)",
                (new_id,))
            try:
                self._fence = RevocationWitness.enroll(
                    fence_path, db_path=self.path, database_id=new_id,
                    existing=existing)
            except WitnessError as exc:
                raise LocalTenantConfigError(str(exc)) from exc
            self._assert_fence_consistent()
        return {
            "schema": "phicloud.tenant-recovery-result/0.1",
            "enrolled": True, "existing_revocations": len(existing),
            "independent_witness": True, "production_effects": False,
        }

    def reconcile_recovery_fence(self) -> dict:
        """OFFLINE, one-way, crash-safe recovery: revoke, NEVER regrant."""
        if not self._recovery_mode or self._fence is None:
            raise LocalTenantConfigError("offline_recovery_mode_and_fence_required")
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                database = {
                    (tenant, key): timestamp for tenant, key, timestamp in
                    self._db.execute(
                        "SELECT tenant_id,principal_key,revoked_at"
                        " FROM membership_revocations").fetchall()
                }
                # We cannot infer whether DB-only tombstones were newly
                # created or witness entries were lost. Fail closed.
                if any(database[pair] != at for pair, at in database.items()
                       if pair not in self._fence.records
                       or self._fence.records[pair] != at):
                    raise LocalTenantConfigError("unwitnessed_sqlite_revocation")
                changes = 0
                for (tenant, key), at in self._fence.records.items():
                    member = self._db.execute(
                        "DELETE FROM memberships"
                        " WHERE tenant_id=? AND principal_key=?",
                        (tenant, key)).rowcount
                    removed = self._db.execute(
                        "DELETE FROM records"
                        " WHERE tenant_id=? AND owner_key=?",
                        (tenant, key)).rowcount
                    if (tenant, key) not in database:
                        self._db.execute(
                            "INSERT INTO membership_revocations"
                            " (tenant_id,principal_key,revoked_at,removed_markers)"
                            " VALUES(?,?,?,?)", (tenant, key, at, removed))
                    if member or removed or (tenant, key) not in database:
                        changes += 1
                if changes:
                    self._db.execute(
                        "INSERT INTO recovery_events(at,restored_revocations)"
                        " VALUES(?,?)", (self._now(), changes))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            self._assert_fence_consistent()
            return {
                "schema": "phicloud.tenant-recovery-result/0.1",
                "reconciled_revocations": changes,
                "revocation_entries": len(self._fence.records),
                "access_regranted": False,
                "external_tokens_revoked": False,
                "production_effects": False,
            }

    def _now(self) -> int:
        return int(self._clock())

    def _key(self, issuer: str, sub: str) -> str:
        return hashlib.sha256(
            b"PhiCloud-R6-owner-key/1\0" + self._salt
            + b"\0" + issuer.encode("utf-8") + b"\0" + sub.encode("utf-8")
        ).hexdigest()

    def _owner_key(self, principal) -> str:
        return self._key(*_principal(principal))

    @staticmethod
    def _tenant_id(value: str) -> str:
        if not isinstance(value, str) or not _TENANT.fullmatch(value):
            raise LocalTenantError("unknown_resource")
        return value

    def provision_once(self, fixture: object) -> None:
        """First-run operator fixture, NEVER called from an HTTP route.

        No implicit tenant enrollment when a user merely authenticates.
        Restarts may omit the fixture without discarding memberships. A later
        attempt to reseed fails closed, preventing accidental re-grant.
        """
        if (not isinstance(fixture, dict) or set(fixture) != {"schema", "tenants"}
                or fixture["schema"] != TENANT_SCHEMA
                or not isinstance(fixture["tenants"], list)
                or not 1 <= len(fixture["tenants"]) <= MAX_TENANTS):
            raise LocalTenantConfigError("invalid_operator_tenant_fixture")
        prepared = []
        seen = set()
        for item in fixture["tenants"]:
            if not isinstance(item, dict) or set(item) != {"id", "members"}:
                raise LocalTenantConfigError("invalid_tenant_fixture_fields")
            tenant_id = self._tenant_id(item["id"])
            if tenant_id in seen or not isinstance(item["members"], list) or not (
                    1 <= len(item["members"]) <= MAX_MEMBERS):
                raise LocalTenantConfigError("duplicate_or_invalid_tenant_membership")
            seen.add(tenant_id)
            keys = set()
            for principal in item["members"]:
                if not isinstance(principal, dict) or set(principal) != {"iss", "sub"}:
                    raise LocalTenantConfigError("invalid_member_fields")
                try:
                    key = self._key(*_principal(type("Principal", (), {
                        "issuer": principal["iss"], "sub": principal["sub"],
                    })()))
                except LocalTenantError as exc:
                    raise LocalTenantConfigError("invalid_member_issuer_or_subject") from exc
                if key in keys:
                    raise LocalTenantConfigError("duplicate_member")
                keys.add(key)
            prepared.append((tenant_id, tuple(keys)))

        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                done = self._db.execute(
                    "SELECT 1 FROM metadata WHERE key = 'provisioned'").fetchone()
                if done:
                    raise LocalTenantConfigError("operator_fixture_already_provisioned")
                for tenant_id, members in prepared:
                    self._db.execute("INSERT INTO tenants(id) VALUES(?)", (tenant_id,))
                    for key in members:
                        self._db.execute(
                            "INSERT INTO memberships(tenant_id,principal_key) VALUES(?,?)",
                            (tenant_id, key))
                self._db.execute("INSERT INTO metadata(key,value) VALUES('provisioned','1')")
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def preview_member_removal(self, tenant_id: str, principal) -> dict:
        """Operator-only preview, never reachable from HTTP routes."""
        tenant_id = self._tenant_id(tenant_id)
        key = self._owner_key(principal)
        with self._lock:
            active = self._db.execute(
                "SELECT 1 FROM memberships WHERE tenant_id=? AND principal_key=?",
                (tenant_id, key)).fetchone() is not None
            markers = self._db.execute(
                "SELECT COUNT(*) FROM records WHERE tenant_id=? AND owner_key=?",
                (tenant_id, key)).fetchone()[0]
            revoked = self._db.execute(
                "SELECT 1 FROM membership_revocations WHERE tenant_id=? AND principal_key=?",
                (tenant_id, key)).fetchone() is not None
            return {
                "schema": "phicloud.local-tenant-removal.v0.1",
                "tenant": tenant_id,
                "membership_active": active,
                "existing_markers": markers,
                "previously_revoked": revoked,
                "external_token_revoked": False,
                "regrant_supported": False,
                "production_effects": False,
            }

    def revoke_member_offline(self, tenant_id: str, principal) -> dict:
        """One-way local membership removal and owned marker purge.

        REQUIRES the exclusive process lease, a trusted *offline* operator,
        and an explicit confirmation outside this store. No HTTP route calls it.
        Existing synthetic create/delete audit rows are retained for 90 days.
        """
        tenant_id = self._tenant_id(tenant_id)
        key = self._owner_key(principal)
        now = self._now()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                # Never regrant; reject malformed DB where a revoked user has
                # become a member again, rather than silently erasing evidence.
                previous = self._db.execute(
                    "SELECT 1 FROM membership_revocations WHERE tenant_id=? AND principal_key=?",
                    (tenant_id, key)).fetchone()
                active = self._db.execute(
                    "SELECT 1 FROM memberships WHERE tenant_id=? AND principal_key=?",
                    (tenant_id, key)).fetchone()
                if previous and active:
                    raise LocalTenantConfigError("revoked_member_unexpectedly_active")
                if not active:
                    self._db.execute("COMMIT")
                    return {
                        "schema": "phicloud.local-tenant-removal.v0.1",
                        "tenant": tenant_id, "changed": False,
                        "previously_revoked": bool(previous),
                        "removed_markers": 0,
                        "external_token_revoked": False,
                        "production_effects": False,
                    }
                # Persist the independent witness BEFORE changing SQLite.
                # Crash/failure in the second write causes fail-closed
                # divergence, repairable only by offline revoke-only reconcile.
                if self._fence is not None:
                    self._fence.append(tenant_id, key, now)
                removed = self._db.execute(
                    "DELETE FROM records WHERE tenant_id=? AND owner_key=?",
                    (tenant_id, key)).rowcount
                self._db.execute(
                    "DELETE FROM memberships WHERE tenant_id=? AND principal_key=?",
                    (tenant_id, key))
                self._db.execute(
                    "INSERT INTO membership_revocations"
                    " (tenant_id,principal_key,revoked_at,removed_markers)"
                    " VALUES(?,?,?,?)", (tenant_id, key, now, removed))
                self._db.execute("COMMIT")
                return {
                    "schema": "phicloud.local-tenant-removal.v0.1",
                    "tenant": tenant_id,
                    "changed": True, "previously_revoked": False,
                    "removed_markers": removed,
                    "external_token_revoked": False,
                    "production_effects": False,
                }
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def _require_member(self, tenant_id: str, key: str) -> None:
        if self._fence is not None and (tenant_id, key) in self._fence.records:
            raise LocalTenantError("unknown_resource")
        row = self._db.execute(
            "SELECT 1 FROM memberships WHERE tenant_id = ? AND principal_key = ?",
            (tenant_id, key)).fetchone()
        if row is None:
            raise LocalTenantError("unknown_resource")

    def _prune(self, now: int) -> None:
        self._db.execute("DELETE FROM records WHERE expires <= ?", (now,))
        self._db.execute("DELETE FROM audit WHERE at < ?", (now - AUDIT_TTL,))

    def _record_view(self, row: tuple) -> dict:
        record_id, tenant_id, created, expires = row
        return {
            "schema": TENANT_SCHEMA, "id": record_id, "tenant": tenant_id,
            "kind": "durable_synthetic_test_marker",
            "created_at_epoch": created, "expires_at_epoch": expires,
            "persistent_local_only": True, "files_present": False,
            "cloud_storage_access": False, "mailbox_access": False,
            "phios_effect_authority": False,
        }

    def create(self, principal, tenant_id: str) -> dict:
        tenant_id = self._tenant_id(tenant_id)
        key = self._owner_key(principal)
        now = self._now()
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._require_member(tenant_id, key)
                self._prune(now)
                owned = self._db.execute(
                    "SELECT COUNT(*) FROM records WHERE tenant_id=? AND owner_key=?",
                    (tenant_id, key)).fetchone()[0]
                total = self._db.execute("SELECT COUNT(*) FROM records").fetchone()[0]
                audit_count = self._db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
                if (owned >= MAX_OWNER_RECORDS or total >= MAX_RECORDS
                        or audit_count >= MAX_AUDIT):
                    raise LocalTenantCapacity("local_dev_capacity")
                record_id = secrets.token_urlsafe(24)
                self._db.execute(
                    "INSERT INTO records(id,tenant_id,owner_key,created,expires)"
                    " VALUES(?,?,?,?,?)",
                    (record_id, tenant_id, key, now, now + RECORD_TTL))
                self._db.execute(
                    "INSERT INTO audit(tenant_id,actor_key,resource_id,action,at)"
                    " VALUES(?,?,?,?,?)", (tenant_id, key, record_id, "create", now))
                self._db.execute("COMMIT")
                return self._record_view((record_id, tenant_id, now, now + RECORD_TTL))
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def list_own(self, principal, tenant_id: str) -> list[dict]:
        tenant_id = self._tenant_id(tenant_id)
        key = self._owner_key(principal)
        with self._lock:
            self._require_member(tenant_id, key)
            now = self._now()
            self._prune(now)
            rows = self._db.execute(
                "SELECT id,tenant_id,created,expires FROM records"
                " WHERE tenant_id=? AND owner_key=? ORDER BY created,id",
                (tenant_id, key)).fetchall()
            return [self._record_view(row) for row in rows]

    def read_own(self, principal, tenant_id: str, record_id: str) -> dict | None:
        tenant_id = self._tenant_id(tenant_id)
        key = self._owner_key(principal)
        with self._lock:
            self._require_member(tenant_id, key)
            if not isinstance(record_id, str) or not _ID.fullmatch(record_id):
                return None
            now = self._now()
            row = self._db.execute(
                "SELECT id,tenant_id,created,expires FROM records"
                " WHERE id=? AND tenant_id=? AND owner_key=? AND expires>?",
                (record_id, tenant_id, key, now)).fetchone()
            return self._record_view(row) if row else None

    def delete_own(self, principal, tenant_id: str, record_id: str) -> bool:
        tenant_id = self._tenant_id(tenant_id)
        key = self._owner_key(principal)
        with self._lock:
            self._db.execute("BEGIN IMMEDIATE")
            try:
                self._require_member(tenant_id, key)
                if not isinstance(record_id, str) or not _ID.fullmatch(record_id):
                    raise LocalTenantError("unknown_resource")
                now = self._now()
                self._prune(now)
                record = self._db.execute(
                    "DELETE FROM records WHERE id=? AND tenant_id=? AND owner_key=?",
                    (record_id, tenant_id, key))
                if record.rowcount != 1:
                    raise LocalTenantError("unknown_resource")
                count = self._db.execute("SELECT COUNT(*) FROM audit").fetchone()[0]
                if count >= MAX_AUDIT:
                    raise LocalTenantCapacity("local_dev_audit_capacity")
                self._db.execute(
                    "INSERT INTO audit(tenant_id,actor_key,resource_id,action,at)"
                    " VALUES(?,?,?,?,?)", (tenant_id, key, record_id, "delete", now))
                self._db.execute("COMMIT")
                return True
            except Exception:
                self._db.execute("ROLLBACK")
                raise

    def own_audit(self, principal, tenant_id: str) -> list[dict]:
        tenant_id = self._tenant_id(tenant_id)
        key = self._owner_key(principal)
        with self._lock:
            self._require_member(tenant_id, key)
            now = self._now()
            self._prune(now)
            rows = self._db.execute(
                "SELECT resource_id,action,at FROM audit"
                " WHERE tenant_id=? AND actor_key=? ORDER BY seq DESC LIMIT 50",
                (tenant_id, key)).fetchall()
            return [
                {"record_id": rid, "action": action, "at_epoch": timestamp}
                for rid, action, timestamp in rows
            ]


def create_tenant_store(env: dict | None = None) -> LocalTenantStore | None:
    """Explicitly opt in to a localhost-only test fixture with a private DB."""
    settings = os.environ if env is None else env
    if settings.get("PHICLOUD_ENABLE_TENANT_DEV") != "1":
        return None
    if settings.get("PHICLOUD_ENABLE_OAUTH_DEV") != "1":
        raise LocalTenantConfigError("verified_oauth_gate_required")
    if settings.get("NODE_ENV") == "production" or settings.get("PHICLOUD_ENV") == "production":
        raise LocalTenantConfigError("local_tenant_fixture_not_for_production")
    db_path = settings.get("PHICLOUD_TENANT_DB_PATH")
    if not db_path:
        raise LocalTenantConfigError("private_absolute_db_path_required")
    fence_enabled = settings.get("PHICLOUD_ENABLE_FENCE_DEV") == "1"
    if settings.get("PHICLOUD_TENANT_FENCE_PATH") and not fence_enabled:
        raise LocalTenantConfigError("explicit_recovery_fence_opt_in_required")
    if fence_enabled and not settings.get("PHICLOUD_TENANT_FENCE_PATH"):
        raise LocalTenantConfigError("private_recovery_fence_path_required")
    store = LocalTenantStore(db_path, fence_path=(
        settings.get("PHICLOUD_TENANT_FENCE_PATH") if fence_enabled else None))
    fixture = settings.get("PHICLOUD_TENANT_PROVISION_JSON")
    if fixture:
        if len(fixture) > 8_192:
            store.close()
            raise LocalTenantConfigError("oversized_operator_fixture")
        try:
            store.provision_once(json.loads(fixture))
        except (ValueError, KeyError, TypeError) as exc:
            store.close()
            raise LocalTenantConfigError("invalid_operator_fixture") from exc
    return store
