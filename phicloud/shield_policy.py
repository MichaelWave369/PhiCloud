"""Pure, local-only PhiShield R0 candidate gate for ANC advisory R1.

There is NO authentication, token validation, remote API, file mutation,
execution, or durable consent storage in this module. Instances of
AuthorityEvidence/ConsentEvidence must be constructed by a future TRUSTED
verifier, never unmarshalled from client JSON. An eligible candidate is
not permission to perform an action.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

ANC_SCHEMA = "phi369.anc.phishield.advisory.v1"
SCOPES = frozenset({"pre_service", "post_service", "memory_write", "output_commit"})
POSTURES = frozenset({"safe", "watch", "degraded", "hostile", "quarantined"})
ACTIONS = frozenset({"allow", "warn", "redact", "shadow", "sandbox", "quarantine", "refuse", "seal"})
FACES = frozenset({
    "foundation", "continuity", "integrity", "logic", "memory", "recovery",
    "stability", "observer", "face_09", "face_10", "face_11", "face_12",
})
ADVISORY_FIELDS = frozenset({
    "schema", "request_id", "scope", "posture", "recommended_action",
    "signal_count", "weakest_face", "weakest_face_score", "anchor_integrity",
    "observed_at", "not_after", "authority_granted",
})
MAX_ADVISORY_LIFETIME = 120
MAX_CLOCK_SKEW = 5
_BINDING = re.compile(r"^[A-Za-z0-9._~:/@-]{1,240}$")
_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


@dataclass(frozen=True, slots=True)
class EffectRequest:
    """Proposed action, identified by trusted caller, not raw user input."""

    request_id: str
    scope: str
    subject_issuer: str
    subject_id: str
    audience: str
    action: str
    resource: str


@dataclass(frozen=True, slots=True)
class AuthorityEvidence:
    """Reference context supplied by an EXTERNAL, verified authorization engine.

    This is not a signed token and its construction is not proof of validation.
    Every field is bound to exactly one intended request.
    """

    request_id: str
    scope: str
    subject_issuer: str
    subject_id: str
    audience: str
    action: str
    resource: str
    not_after: str


@dataclass(frozen=True, slots=True)
class ConsentEvidence:
    """Reference receipt from EXTERNAL, verified operator consent workflow."""

    request_id: str
    scope: str
    subject_issuer: str
    subject_id: str
    audience: str
    action: str
    resource: str
    not_after: str


@dataclass(frozen=True, slots=True)
class PolicyVerdict:
    disposition: str  # DENY, REVIEW, CANDIDATE
    reason: str
    authoritative: bool = False  # Never usable as an execution grant


def _utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("expected aware datetime")
    return value.astimezone(timezone.utc)


def _time(value: object) -> datetime:
    if type(value) is not str or len(value) > 40:
        raise ValueError("timestamp must be a short string")
    try:
        return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError as exc:
        raise ValueError("timestamp invalid") from exc


def _valid_request(request: object) -> bool:
    if not isinstance(request, EffectRequest):
        return False
    for field_name in ("subject_issuer", "subject_id", "audience", "action", "resource"):
        value = getattr(request, field_name)
        if type(value) is not str or not _BINDING.fullmatch(value):
            return False
    return (
        type(request.request_id) is str
        and bool(_REQUEST_ID.fullmatch(request.request_id))
        and type(request.scope) is str
        and request.scope in SCOPES
    )


def _same_binding(request: EffectRequest, evidence: object) -> bool:
    return all(
        getattr(evidence, f.name, None) == getattr(request, f.name)
        for f in fields(EffectRequest)
    )


def _independent_evidence_current(
    request: EffectRequest, evidence: object, expected_type: type, now: datetime
) -> bool:
    if type(evidence) is not expected_type or not _same_binding(request, evidence):
        return False
    try:
        return now < _time(evidence.not_after)
    except (ValueError, TypeError, AttributeError):
        return False


def _anc_posture(payload: object, request: EffectRequest, now: datetime) -> tuple[str, str, int] | None:
    """Parse strict ANC R1 wire format. Parsing does NOT authenticate origin."""
    if not isinstance(payload, Mapping) or set(payload) != ADVISORY_FIELDS:
        return None
    if (
        payload["schema"] != ANC_SCHEMA
        or type(payload["request_id"]) is not str
        or payload["request_id"] != request.request_id
        or type(payload["scope"]) is not str
        or payload["scope"] != request.scope
        or type(payload["authority_granted"]) is not bool
        or payload["authority_granted"] is not False
    ):
        return None
    if (
        type(payload["posture"]) is not str
        or payload["posture"] not in POSTURES
        or type(payload["recommended_action"]) is not str
        or payload["recommended_action"] not in ACTIONS
        or type(payload["weakest_face"]) is not str
        or payload["weakest_face"] not in FACES
    ):
        return None
    count = payload["signal_count"]
    if type(count) is not int or not 0 <= count <= 1_000_000:
        return None
    for key in ("weakest_face_score", "anchor_integrity"):
        value = payload[key]
        if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
            return None
    try:
        observed, expires = _time(payload["observed_at"]), _time(payload["not_after"])
    except (ValueError, TypeError, AttributeError):
        return None
    if not 0 < (expires - observed).total_seconds() <= MAX_ADVISORY_LIFETIME:
        return None
    if observed > now + timedelta(seconds=MAX_CLOCK_SKEW) or now >= expires:
        return None
    return payload["posture"], payload["recommended_action"], count


def evaluate_candidate(
    request: EffectRequest,
    *,
    authority: AuthorityEvidence | None,
    consent: ConsentEvidence | None,
    anc_advisory: Mapping[str, Any] | None,
    now: datetime | None = None,
) -> PolicyVerdict:
    """A deterministic **reference** policy, incapable of authorizing any action.

    All inputs except anc_advisory must be sourced from trusted, independently
    verified server-side context. A malicious producer can forge an unsigned
    ANC advisory, so a remote adapter MUST authenticate source and prevent replay
    *before* calling this function. Neither job is done here.
    """
    instant = _utc(now if now is not None else datetime.now(timezone.utc))
    if not _valid_request(request):
        return PolicyVerdict("DENY", "invalid request")
    if not _independent_evidence_current(request, authority, AuthorityEvidence, instant):
        return PolicyVerdict("DENY", "independent authority missing, mismatched or expired")
    if not _independent_evidence_current(request, consent, ConsentEvidence, instant):
        return PolicyVerdict("DENY", "independent operator consent missing, mismatched or expired")
    posture = _anc_posture(anc_advisory, request, instant)
    if posture is None:
        return PolicyVerdict("DENY", "ANC advisory missing, stale, malformed or unbound")
    risk_posture, action, count = posture
    if risk_posture in {"hostile", "quarantined"} or action in {"quarantine", "refuse", "seal"}:
        return PolicyVerdict("DENY", "ANC risk veto; separate incident review required")
    if risk_posture != "safe" or action != "allow" or count:
        return PolicyVerdict("REVIEW", "ANC risk uncertainty requires operator review")
    return PolicyVerdict("CANDIDATE", "risk advisory clear; execution STILL requires independent enforcement")
