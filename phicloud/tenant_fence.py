"""R9 opt-in, independent revocation witness for *synthetic* PhiCloud tenants.

The witness is an owner-private append-only JSONL *development* record placed
outside the SQLite backup directory. It is not cryptographically tamper-proof:
a privileged operator who restores BOTH SQLite and witness can roll back both.
If SQLite alone is stale, verification fails closed until offline reconciliation.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

SCHEMA = "phicloud.tenant-revocation-witness/0.1"
MAX_WITNESS_BYTES = 256 * 1024
MAX_EVENTS = 1024
_HEX = re.compile(r"^[0-9a-f]{64}$")
_TENANT = re.compile(r"^[a-z][a-z0-9-]{2,31}$")


class WitnessError(ValueError):
    """Static-code failure; never include subjects, paths or secrets."""


def _private_directory(path: Path) -> None:
    if not path.is_absolute() or path.suffix != ".jsonl":
        raise WitnessError("absolute_jsonl_witness_required")
    try:
        st = path.parent.lstat()
    except OSError as exc:
        raise WitnessError("private_witness_directory_required") from exc
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_mode & 0o077:
        raise WitnessError("private_witness_directory_required")


def _private_file(path: Path) -> None:
    try:
        st = path.lstat()
    except OSError as exc:
        raise WitnessError("existing_private_witness_required") from exc
    if not stat.S_ISREG(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_mode & 0o077:
        raise WitnessError("unsafe_witness_file")


def _valid_entry(tenant: str, key: str, timestamp: int) -> bool:
    return (
        type(tenant) is str and bool(_TENANT.fullmatch(tenant))
        and type(key) is str and bool(_HEX.fullmatch(key))
        and type(timestamp) is int and 0 <= timestamp < 2**53
    )


def _pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise WitnessError("duplicate_witness_field")
        result[key] = value
    return result


def _parse_line(line: bytes):
    try:
        result = json.loads(line.decode("utf-8"), object_pairs_hook=_pairs_unique)
    except (UnicodeError, ValueError, json.JSONDecodeError) as exc:
        raise WitnessError("malformed_witness_entry") from exc
    if not isinstance(result, dict):
        raise WitnessError("malformed_witness_entry")
    return result


def _encode_line(obj: dict) -> bytes:
    return (json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n").encode("utf-8")


class RevocationWitness:
    def __init__(self, path: str | Path, *, db_path: str | Path, database_id: str) -> None:
        self.path = Path(path)
        db = Path(db_path)
        _private_directory(self.path)
        if self.path.parent == db.parent:
            raise WitnessError("witness_must_be_outside_database_backup_directory")
        _private_file(self.path)
        if not isinstance(database_id, str) or not _HEX.fullmatch(database_id):
            raise WitnessError("invalid_database_binding")
        raw = self.path.read_bytes()
        if not raw or len(raw) > MAX_WITNESS_BYTES or not raw.endswith(b"\n"):
            raise WitnessError("truncated_or_oversized_witness")
        lines = raw.splitlines()
        if not 1 <= len(lines) <= MAX_EVENTS + 1:
            raise WitnessError("witness_event_limit")
        head = _parse_line(lines[0])
        if (
            set(head) != {"schema", "type", "database_id", "existing"}
            or head["schema"] != SCHEMA or head["type"] != "begin"
            or head["database_id"] != database_id
            or not isinstance(head["existing"], list)
        ):
            raise WitnessError("witness_database_binding_mismatch")
        self.records: dict[tuple[str, str], int] = {}
        for entry in head["existing"]:
            if not isinstance(entry, dict) or set(entry) != {"tenant", "key", "at"}:
                raise WitnessError("invalid_witness_initial_entry")
            self._add(entry["tenant"], entry["key"], entry["at"])
        for line in lines[1:]:
            item = _parse_line(line)
            if set(item) != {"type", "tenant", "key", "at"} or item["type"] != "revoke":
                raise WitnessError("invalid_witness_event")
            self._add(item["tenant"], item["key"], item["at"])
        if len(self.records) > MAX_EVENTS:
            raise WitnessError("witness_event_limit")

    def _add(self, tenant, key, timestamp):
        if not _valid_entry(tenant, key, timestamp):
            raise WitnessError("invalid_witness_identity")
        pair = (tenant, key)
        if pair in self.records:
            raise WitnessError("duplicate_witness_revocation")
        self.records[pair] = timestamp

    @classmethod
    def enroll(cls, path: str | Path, *, db_path: str | Path,
               database_id: str, existing: list[tuple[str, str, int]]):
        target = Path(path)
        _private_directory(target)
        if target.parent == Path(db_path).parent:
            raise WitnessError("witness_must_be_outside_database_backup_directory")
        if len(existing) > MAX_EVENTS:
            raise WitnessError("witness_event_limit")
        checked = set()
        items = []
        for tenant, key, at in existing:
            if not _valid_entry(tenant, key, at) or (tenant, key) in checked:
                raise WitnessError("invalid_initial_revocations")
            checked.add((tenant, key))
            items.append({"tenant": tenant, "key": key, "at": at})
        raw = _encode_line({
            "schema": SCHEMA, "type": "begin",
            "database_id": database_id, "existing": items,
        })
        if len(raw) > MAX_WITNESS_BYTES:
            raise WitnessError("witness_event_limit")
        # O_EXCL and O_NOFOLLOW prevent silently replacing a prior witness.
        old_mask = os.umask(0o077)
        try:
            fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError as exc:
            raise WitnessError("witness_already_enrolled") from exc
        finally:
            os.umask(old_mask)
        try:
            _write_all(fd, raw)
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_directory(target.parent)
        return cls(target, db_path=db_path, database_id=database_id)

    def append(self, tenant: str, key: str, at: int):
        if not _valid_entry(tenant, key, at):
            raise WitnessError("invalid_witness_identity")
        pair = (tenant, key)
        if pair in self.records:
            raise WitnessError("duplicate_witness_revocation")
        if len(self.records) >= MAX_EVENTS:
            raise WitnessError("witness_event_limit")
        _private_file(self.path)
        line = _encode_line({"type": "revoke", "tenant": tenant, "key": key, "at": at})
        if self.path.stat().st_size + len(line) > MAX_WITNESS_BYTES:
            raise WitnessError("witness_event_limit")
        fd = os.open(str(self.path), os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077:
                raise WitnessError("unsafe_witness_file")
            _write_all(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.records[pair] = at


def _write_all(fd: int, payload: bytes):
    cursor = 0
    while cursor < len(payload):
        written = os.write(fd, payload[cursor:])
        if written <= 0:
            raise WitnessError("witness_write_failed")
        cursor += written


def _fsync_directory(path: Path):
    fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
