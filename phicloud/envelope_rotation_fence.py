"""R12: separate, owner-private witness for LOCAL synthetic KEK rotation epochs.

This is an accidental/incomplete restore guard, NOT secure hardware monotonic
state or protection against a privileged actor restoring BOTH SQLite and the
witness. Never use this for real files or production user secrets.
"""
from __future__ import annotations

import os
import re
import secrets
from pathlib import Path

from .tenant_fence import (
    WitnessError, _private_directory, _private_file, _parse_line,
    _encode_line, _write_all, _fsync_directory,
)
from .tenant_store import LocalTenantConfigError

SCHEMA = "phicloud.local-envelope-rotation-witness/0.1"
HEX = re.compile(r"^[a-f0-9]{64}$")
MAX_EVENTS = 256
MAX_BYTES = 96 * 1024
BINDING_KEY = "envelope_rotation_witness_id"


def _hex(value):
    return type(value) is str and bool(HEX.fullmatch(value))


def _preflight(path: Path, db_path: Path, kek_path: Path | None = None, *, create=False):
    _private_directory(path)
    # Separate witness from both SQLite backup tree AND KEK directory.
    if path.parent.resolve() == db_path.parent.resolve():
        raise WitnessError("rotation_witness_inside_database_backup_directory")
    if kek_path is not None and path.parent.resolve() == kek_path.parent.resolve():
        raise WitnessError("rotation_witness_inside_key_backup_directory")
    if create:
        try:
            path.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise WitnessError("unsafe_rotation_witness_target") from exc
        raise WitnessError("rotation_witness_already_exists")
    _private_file(path)


class RotationWitness:
    def __init__(self, path: str | Path, *, db_path: str | Path,
                 database_id: str, kek_path: str | Path | None = None):
        self.path = Path(path)
        _preflight(self.path, Path(db_path),
                   Path(kek_path) if kek_path else None)
        if not _hex(database_id):
            raise WitnessError("invalid_rotation_database_binding")
        try:
            raw = self.path.read_bytes()
        except OSError as exc:
            raise WitnessError("rotation_witness_unreadable") from exc
        if not raw or len(raw) > MAX_BYTES or not raw.endswith(b"\n"):
            raise WitnessError("rotation_witness_truncated_or_oversized")
        lines = raw.splitlines()
        if not 1 <= len(lines) <= MAX_EVENTS + 1:
            raise WitnessError("rotation_witness_event_limit")
        head = _parse_line(lines[0])
        if (set(head) != {"schema", "type", "database_id", "initial_key"}
                or head["schema"] != SCHEMA or head["type"] != "begin"
                or head["database_id"] != database_id or not _hex(head["initial_key"])):
            raise WitnessError("rotation_witness_binding_mismatch")
        self.initial = head["initial_key"]
        self.active = self.initial
        self.events: list[tuple[str, str]] = []
        used = {self.initial}
        for line in lines[1:]:
            item = _parse_line(line)
            if (set(item) != {"type", "from", "to"} or item["type"] != "rotate"
                    or not _hex(item["from"]) or not _hex(item["to"])
                    or item["from"] != self.active
                    or item["to"] in used):
                raise WitnessError("invalid_rotation_witness_transition")
            used.add(item["to"])
            self.events.append((item["from"], item["to"]))
            self.active = item["to"]

    @classmethod
    def enroll(cls, path: str | Path, *, db_path: str | Path,
               database_id: str, initial_key: str,
               kek_path: str | Path):
        target = Path(path)
        _preflight(target, Path(db_path), Path(kek_path), create=True)
        if not _hex(database_id) or not _hex(initial_key):
            raise WitnessError("invalid_rotation_enrollment")
        data = _encode_line({
            "schema": SCHEMA, "type": "begin",
            "database_id": database_id, "initial_key": initial_key,
        })
        old_umask = os.umask(0o077)
        try:
            try:
                fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY
                             | getattr(os, "O_NOFOLLOW", 0), 0o600)
            except FileExistsError as exc:
                raise WitnessError("rotation_witness_already_exists") from exc
        finally:
            os.umask(old_umask)
        try:
            _write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_directory(target.parent)
        return cls(target, db_path=db_path, database_id=database_id,
                   kek_path=kek_path)

    def append_rotation(self, old: str, new: str) -> None:
        if (not _hex(old) or not _hex(new) or old != self.active
                or old == new or len(self.events) >= MAX_EVENTS
                or new in {self.initial, *(n for _, n in self.events)}):
            raise WitnessError("invalid_rotation_event_or_capacity")
        line = _encode_line({"type": "rotate", "from": old, "to": new})
        _private_file(self.path)
        if self.path.stat().st_size + len(line) > MAX_BYTES:
            raise WitnessError("rotation_witness_event_limit")
        fd = os.open(str(self.path), os.O_WRONLY | os.O_APPEND
                     | getattr(os, "O_NOFOLLOW", 0))
        try:
            st = os.fstat(fd)
            if (st.st_mode & 0o077 or st.st_nlink != 1
                    or not os.path.isfile(self.path)):
                raise WitnessError("unsafe_rotation_witness_file")
            _write_all(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.events.append((old, new))
        self.active = new


def load_for_database(store, witness_path, *, kek_path=None, allow_pending=False):
    """Guard every normal R11 startup when the DB has a witness binding."""
    row = store._db.execute(
        "SELECT value FROM metadata WHERE key=?", (BINDING_KEY,)).fetchone()
    if row is None:
        if witness_path is not None:
            raise LocalTenantConfigError("rotation_witness_not_enrolled")
        return None
    if not witness_path:
        raise LocalTenantConfigError("enrolled_envelope_requires_rotation_witness")
    try:
        witness = RotationWitness(
            witness_path, db_path=store.path, database_id=row[0],
            kek_path=kek_path)
    except WitnessError as exc:
        raise LocalTenantConfigError(str(exc)) from exc
    active = store._db.execute(
        "SELECT value FROM metadata WHERE key='envelope_active_kek_id'"
    ).fetchone()
    if active is None:
        raise LocalTenantConfigError("missing_envelope_key_binding")
    if active[0] != witness.active:
        if not (allow_pending and witness.events
                and active[0] == witness.events[-1][0]):
            raise LocalTenantConfigError("stale_or_pending_envelope_key_rotation")
    return witness


def enroll_rotation_witness(store, path: str | Path, key_path: str | Path):
    """Offline one-time enrollment; the SQLite lease must already be held."""
    from .envelope_demo import _key_id
    from .sealed_demo import read_local_key

    key = read_local_key(key_path, store.path)
    current_id = _key_id(key)
    with store._lock:
        db = store._db
        if db.execute(
            "SELECT 1 FROM metadata WHERE key=?", (BINDING_KEY,)).fetchone():
            raise LocalTenantConfigError("rotation_witness_already_enrolled")
        active = db.execute(
            "SELECT value FROM metadata WHERE key='envelope_active_kek_id'"
        ).fetchone()
        if active is None or active[0] != current_id:
            raise LocalTenantConfigError("envelope_current_key_required_for_enrollment")
        try:
            _preflight(Path(path), store.path, Path(key_path), create=True)
        except WitnessError as exc:
            raise LocalTenantConfigError(str(exc)) from exc
        binding = secrets.token_hex(32)
        # Mark DB BEFORE writing witness: interruption after this point denies
        # future unguarded startup. Predictable invalid paths were preflighted.
        db.execute("INSERT INTO metadata(key,value) VALUES(?,?)",
                   (BINDING_KEY, binding))
        try:
            RotationWitness.enroll(
                path, db_path=store.path, database_id=binding,
                initial_key=current_id, kek_path=key_path)
        except WitnessError as exc:
            raise LocalTenantConfigError(str(exc)) from exc
        return {
            "schema": "phicloud.local-envelope-witness-result/0.1",
            "enrolled": True,
            "initial_rotation_epoch": 0,
            "production_effects": False,
        }
