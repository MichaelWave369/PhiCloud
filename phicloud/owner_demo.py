"""R4 disposable, in-memory per-subject resource ownership proof.

This is intentionally not a cloud file store, tenant database, or capability
service. The caller cannot submit data, choose an owner or choose a record ID.
Ownership is always the verified OIDC (issuer, subject) pair returned by the
resource server's real-token introspection gate.
"""
from __future__ import annotations

import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

SCHEMA = "phicloud.local-owner-demo.v0.1"
MAX_PER_OWNER = 4
MAX_GLOBAL = 64
TTL_SECONDS = 10 * 60
_RECORD_ID = re.compile(r"^[A-Za-z0-9_-]{24,64}$")


class DemoStoreFull(Exception):
    """Capacity guard; never evict another user's data to accept a request."""


@dataclass(frozen=True)
class _DemoRecord:
    record_id: str
    issuer: str
    sub: str
    created: int
    expires: int

    def public(self) -> dict:
        return {
            "schema": SCHEMA,
            "id": self.record_id,
            "kind": "disposable_owner_test_only",
            "created_at_epoch": self.created,
            "expires_at_epoch": self.expires,
            "owner_isolated": True,
            "persistent": False,
            "files_present": False,
            "cloud_storage_access": False,
            "mailbox_access": False,
            "phios_effect_authority": False,
        }


class OwnerDemoStore:
    """Bounded ephemeral state with atomic owner checks on every operation."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._records: dict[str, _DemoRecord] = {}

    def _now(self) -> int:
        return int(self._clock())

    def _prune(self, now: int) -> None:
        for key, row in list(self._records.items()):
            if row.expires <= now:
                self._records.pop(key, None)

    @staticmethod
    def _owner(principal) -> tuple[str, str]:
        issuer = getattr(principal, "issuer", None)
        sub = getattr(principal, "sub", None)
        if not isinstance(issuer, str) or not isinstance(sub, str) or not issuer or not sub:
            raise ValueError("verified_principal_required")
        return issuer, sub

    def create(self, principal) -> dict:
        issuer, sub = self._owner(principal)
        with self._lock:
            now = self._now()
            self._prune(now)
            owned = sum(1 for record in self._records.values()
                        if record.issuer == issuer and record.sub == sub)
            if owned >= MAX_PER_OWNER or len(self._records) >= MAX_GLOBAL:
                raise DemoStoreFull("demo_store_capacity_reached")
            record_id = secrets.token_urlsafe(24)
            while record_id in self._records:
                record_id = secrets.token_urlsafe(24)
            record = _DemoRecord(record_id, issuer, sub, now, now + TTL_SECONDS)
            self._records[record_id] = record
            return record.public()

    def list_own(self, principal) -> list[dict]:
        issuer, sub = self._owner(principal)
        with self._lock:
            self._prune(self._now())
            return [record.public() for record in self._records.values()
                    if record.issuer == issuer and record.sub == sub]

    def read_own(self, principal, record_id: str) -> dict | None:
        issuer, sub = self._owner(principal)
        if not _RECORD_ID.fullmatch(record_id):
            return None
        with self._lock:
            self._prune(self._now())
            row = self._records.get(record_id)
            if row is None or (row.issuer, row.sub) != (issuer, sub):
                return None
            return row.public()

    def delete_own(self, principal, record_id: str) -> bool:
        issuer, sub = self._owner(principal)
        if not _RECORD_ID.fullmatch(record_id):
            return False
        with self._lock:
            self._prune(self._now())
            row = self._records.get(record_id)
            if row is None or (row.issuer, row.sub) != (issuer, sub):
                return False
            self._records.pop(record_id)
            return True
