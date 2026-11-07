"""R5 in-memory, operator-reviewed consent + synthetic-self ownership policy.

No HTTP endpoints, user database, OS actions, durable records, or secure
human authentication. Register and approve ONLY from a trusted local process.
The default is denial; a real remote client cannot submit approval evidence.
This module is a reference *state machine*, not production authorization.
"""
from __future__ import annotations

import secrets
import sys
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Callable, TextIO

from .authz import AUDIENCE, ISSUER
from .shield_policy import (
    AuthorityEvidence, ConsentEvidence, EffectRequest, _utc, _valid_request,
)

ALLOWED_ACTION = "profile.read"
ALLOWED_RESOURCE = "profile:synthetic-self"
ALLOWED_SCOPE = "pre_service"
MAX_REVIEW_SECONDS = 60
MAX_APPROVAL_SECONDS = 30


class PolicyDenied(ValueError):
    """An independently verified, exact-scope consent is unavailable."""


@dataclass(frozen=True, slots=True)
class ReviewTicket:
    review_id: str
    request: EffectRequest
    expires_at: datetime


class LocalOwnerConsentPolicy:
    """Trusted in-process synthetic-profile owner and one-use review ledger.

    This reference has NO API route and accepts no client-persisted consent
    receipts. A caller can fabricate state if it controls this Python process;
    therefore it does not establish consent across a trust boundary.
    """

    def __init__(self, *, capacity: int = 1024) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 100_000:
            raise ValueError("invalid policy capacity")
        self._capacity = capacity
        self._lock = threading.RLock()
        self._owners: set[tuple[str, str]] = set()
        self._used: set[tuple[str, str, str]] = set()
        self._pending: dict[str, ReviewTicket] = {}
        self._approved: dict[tuple[str, str, str], tuple[EffectRequest, datetime]] = {}

    @staticmethod
    def _key(req: EffectRequest) -> tuple[str, str, str]:
        return req.subject_issuer, req.subject_id, req.request_id

    @staticmethod
    def _owner(req: EffectRequest) -> tuple[str, str]:
        return req.subject_issuer, req.subject_id

    @staticmethod
    def _operation_allowed(req: object) -> bool:
        return (
            _valid_request(req)
            and req.subject_issuer == ISSUER
            and req.audience == AUDIENCE
            and req.scope == ALLOWED_SCOPE
            and req.action == ALLOWED_ACTION
            and req.resource == ALLOWED_RESOURCE
        )

    def register_synthetic_self(self, request: EffectRequest) -> None:
        """Trusted service attaches a synthetic self-profile to verified owner.

        Never call with a client-supplied issuer/sub, and do not generalize
        to real stored resources without an independent owner registry.
        """
        if not self._operation_allowed(request):
            raise PolicyDenied("unsupported resource or identity")
        with self._lock:
            if len(self._owners) >= self._capacity and self._owner(request) not in self._owners:
                raise PolicyDenied("owner registry full")
            self._owners.add(self._owner(request))

    def stage(self, request: EffectRequest, *, now: datetime) -> ReviewTicket:
        """Create a one-use, short-lived request that must be explicitly reviewed."""
        instant = _utc(now)
        if not self._operation_allowed(request):
            raise PolicyDenied("unsupported action")
        key = self._key(request)
        with self._lock:
            if self._owner(request) not in self._owners:
                raise PolicyDenied("synthetic profile owner not registered")
            if key in self._used or len(self._used) >= self._capacity:
                raise PolicyDenied("already used request or capacity reached")
            # Never silently recycle request IDs in this process.
            self._used.add(key)
            review = ReviewTicket(
                review_id=secrets.token_urlsafe(24),
                request=request,
                expires_at=instant + timedelta(seconds=MAX_REVIEW_SECONDS),
            )
            self._pending[review.review_id] = review
            return review

    def approve(
        self,
        review_id: str,
        *,
        shown_request: EffectRequest,
        acknowledged: bool,
        now: datetime,
    ) -> bool:
        """Trusted local reviewer acknowledges the EXACT staged effect.

        A boolean from a browser or other untrusted client is NOT independent
        user approval. Use operator_console_review for interactive local use.
        """
        instant = _utc(now)
        if type(review_id) is not str or type(acknowledged) is not bool:
            return False
        with self._lock:
            review = self._pending.pop(review_id, None)
            if review is None:
                return False
            if (
                acknowledged is not True
                or instant >= review.expires_at
                or review.request != shown_request
                or self._owner(review.request) not in self._owners
            ):
                return False
            key = self._key(review.request)
            self._approved[key] = (
                review.request,
                min(review.expires_at, instant + timedelta(seconds=MAX_APPROVAL_SECONDS)),
            )
            return True

    def revoke_owner(self, *, issuer: str, sub: str) -> None:
        """Deny all outstanding review and approval tickets for this owner."""
        owner = issuer, sub
        with self._lock:
            self._owners.discard(owner)
            self._pending = {
                rid: ticket for rid, ticket in self._pending.items()
                if self._owner(ticket.request) != owner
            }
            self._approved = {
                key: record for key, record in self._approved.items()
                if self._owner(record[0]) != owner
            }

    def consume(
        self, request: EffectRequest, *, now: datetime
    ) -> tuple[AuthorityEvidence, ConsentEvidence]:
        """Atomically consume one verified local review, bound to exact owner/effect.

        Consuming approval precedes ANC verification. If ANC denies, the
        approval is intentionally lost; a new request and review are needed.
        """
        instant = _utc(now)
        if not self._operation_allowed(request):
            raise PolicyDenied("unsupported operation")
        with self._lock:
            if self._owner(request) not in self._owners:
                raise PolicyDenied("not owner of the synthetic profile")
            record = self._approved.pop(self._key(request), None)
            if record is None or record[0] != request or instant >= record[1]:
                raise PolicyDenied("missing, mismatched, expired or consumed approval")
            until = record[1].isoformat()
            return (
                AuthorityEvidence(**asdict(request), not_after=until),
                ConsentEvidence(**asdict(request), not_after=until),
            )


def operator_console_review(
    policy: LocalOwnerConsentPolicy,
    ticket: ReviewTicket,
    *,
    now: datetime,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> bool:
    """Optional local terminal review with explicit typed confirmation.

    Test streams can be injected by trusted tests; normal use requires a TTY.
    Not cryptographic proof of who is at the keyboard, or a signed receipt.
    """
    incoming = sys.stdin if input_stream is None else input_stream
    outgoing = sys.stdout if output_stream is None else output_stream
    if input_stream is None and not incoming.isatty():
        return False
    if output_stream is None and not outgoing.isatty():
        return False
    req = ticket.request
    outgoing.write(
        "Review LOCAL synthetic profile access only:\n"
        f"  issuer: {req.subject_issuer}\n"
        f"  subject: {req.subject_id}\n"
        f"  audience: {req.audience}\n"
        f"  action: {req.action}\n"
        f"  resource: {req.resource}\n"
        f"  request: {req.request_id}\n"
        "No files, mailbox data, or PhiOS actions are authorized.\n"
        f"Type APPROVE {req.request_id} exactly to record one local review: "
    )
    outgoing.flush()
    try:
        answer = incoming.readline(160)
    except (OSError, ValueError):
        return False
    return policy.approve(
        ticket.review_id, shown_request=req,
        acknowledged=(answer.rstrip("\r\n") == f"APPROVE {req.request_id}"),
        now=now,
    )
