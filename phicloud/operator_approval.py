"""R7 exact-request Ed25519 operator review verification.

Public-key only. Private signing keys stay with a separately controlled
operator/signing process; this module NEVER creates or stores private keys.
This is *signature authentication*, not proof of live human consent.
"""
from __future__ import annotations

import base64
import json
import re
from dataclasses import asdict
from datetime import datetime

from .local_consent import PolicyDenied, ReviewTicket
from .shield_policy import EffectRequest, _utc

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # deliberate opt-in dependency; fail closed when missing
    InvalidSignature = None
    Ed25519PublicKey = None

SCHEMA = "phicloud.operator-review.ed25519.v1"
PURPOSE = "synthetic-profile-read-review"
DOMAIN = b"PHICLOUD_OPERATOR_REVIEW_ED25519_V1\x00"
MAX_LIFETIME_MS = 30_000
CLOCK_SKEW_MS = 5_000
MAX_RECEIPT_BYTES = 4096
_BODY_FIELDS = frozenset({
    "schema", "purpose", "operator_id", "kid", "review_id",
    "request", "issued_at_ms", "expires_at_ms", "nonce",
})
_RECEIPT_FIELDS = _BODY_FIELDS | {"signature"}
_REQUEST_FIELDS = frozenset({
    "request_id", "scope", "subject_issuer", "subject_id",
    "audience", "action", "resource",
})
_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,96}$")
_NONCE = re.compile(r"^[0-9a-f]{32}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")


def canonical_message(body: dict) -> bytes:
    """Domain-separated canonical bytes for a trusted signer to sign.

    The public API accepts only the exact receipt body fields so signing
    a different object cannot accidentally drop an unauthenticated field.
    """
    if type(body) is not dict or set(body) != _BODY_FIELDS:
        raise PolicyDenied("invalid operator receipt body")
    try:
        encoded = json.dumps(
            body, sort_keys=True, ensure_ascii=True, allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise PolicyDenied("uncanonicalizable operator receipt") from exc
    if len(encoded) > MAX_RECEIPT_BYTES:
        raise PolicyDenied("operator receipt too large")
    return DOMAIN + encoded


def verified_receipt_expiry(
    receipt: object,
    *,
    ticket: ReviewTicket,
    public_key: bytes,
    now: datetime,
) -> int:
    """Check a fully signed exact-purpose, exact-actor, one-ticket receipt.

    The key MUST come from a trusted pinned-key registry, NEVER from the
    receipt itself. Returned expiry is for the local approval ledger only.
    """
    if Ed25519PublicKey is None:
        raise PolicyDenied("Ed25519 verifier dependency unavailable")
    if type(ticket) is not ReviewTicket or type(ticket.request) is not EffectRequest:
        raise PolicyDenied("trusted staged review required")
    if type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS:
        raise PolicyDenied("operator receipt fields invalid")
    if type(public_key) is not bytes or len(public_key) != 32:
        raise PolicyDenied("invalid trusted operator public key")
    if (
        receipt["schema"] != SCHEMA or receipt["purpose"] != PURPOSE
        or type(receipt["operator_id"]) is not str
        or not _IDENTIFIER.fullmatch(receipt["operator_id"])
        or type(receipt["kid"]) is not str
        or not _IDENTIFIER.fullmatch(receipt["kid"])
        or type(receipt["review_id"]) is not str
        or receipt["review_id"] != ticket.review_id
        or type(receipt["nonce"]) is not str
        or not _NONCE.fullmatch(receipt["nonce"])
        or type(receipt["signature"]) is not str
        or not _SIGNATURE.fullmatch(receipt["signature"])
    ):
        raise PolicyDenied("untrusted or mismatched operator review")
    specified_request = receipt["request"]
    if (
        type(specified_request) is not dict
        or set(specified_request) != _REQUEST_FIELDS
        or specified_request != asdict(ticket.request)
    ):
        raise PolicyDenied("signed operator action differs from staged request")
    issued, expires = receipt["issued_at_ms"], receipt["expires_at_ms"]
    if type(issued) is not int or type(expires) is not int:
        raise PolicyDenied("invalid approval timestamps")
    current = int(_utc(now).timestamp() * 1000)
    review_deadline = int(_utc(ticket.expires_at).timestamp() * 1000)
    if (
        issued > current + CLOCK_SKEW_MS
        or current >= expires
        or expires <= issued
        or expires - issued > MAX_LIFETIME_MS
        or expires > review_deadline
        or issued > review_deadline
    ):
        raise PolicyDenied("stale, premature or overly broad operator approval")
    body = {k: receipt[k] for k in _BODY_FIELDS}
    message = canonical_message(body)
    try:
        raw = base64.urlsafe_b64decode(receipt["signature"] + "==")
        if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != receipt["signature"]:
            raise ValueError("noncanonical signature")
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw, message)
    except (ValueError, InvalidSignature) as exc:
        raise PolicyDenied("operator signature invalid") from exc
    return expires
