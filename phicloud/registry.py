"""Strict validation for the public, declarative PhiCloud service inventory."""

from __future__ import annotations

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

SCHEMA = "phicloud.services.v0.1"
_SERVICE_ID = re.compile(r"^[a-z][a-z0-9-]{1,47}$")
_ROLES = frozenset({
    "identity", "mail", "security", "storage", "sync", "compute",
    "data", "network", "dns", "functions", "observability",
    "inference", "gateway",
})
_STAGES = frozenset({"planned", "integration-needed", "prototype"})
_TOP_FIELDS = frozenset({"schema", "services"})
_ENTRY_FIELDS = frozenset({"id", "title", "role", "stage", "repository", "endpoint_hint"})


class ManifestError(ValueError):
    """Manifest is malformed, inconsistent or unsafe to present as trusted metadata."""


def _endpoint_hint_is_safe(value: str | None) -> bool:
    """Only allow HTTPS, or an HTTP loopback hint. Does not make a request."""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    try:
        parsed = urlsplit(value)
        if not parsed.hostname or parsed.username or parsed.password:
            return False
        if parsed.query or parsed.fragment:
            return False
        # Limit host syntax and avoid misleading local-domain or encoded-host variants.
        _ = parsed.port  # reject malformed ports even though no connection is made
        host = parsed.hostname
        if parsed.scheme == "https":
            return bool(host) and not host.endswith(".invalid")
        if parsed.scheme == "http":
            return host in {"127.0.0.1", "localhost", "::1"}
        return False
    except ValueError:
        return False


def validate_manifest(manifest: object) -> dict:
    """Validate a JSON-compatible manifest. Never resolve/fetch any endpoints."""
    if not isinstance(manifest, dict) or set(manifest) != _TOP_FIELDS:
        raise ManifestError("top-level fields must be exactly: schema, services")
    if manifest["schema"] != SCHEMA:
        raise ManifestError("unsupported schema")
    services = manifest["services"]
    if not isinstance(services, list) or not (1 <= len(services) <= 64):
        raise ManifestError("services must be a list of 1..64 entries")
    seen = set()
    for index, svc in enumerate(services):
        if not isinstance(svc, dict) or set(svc) != _ENTRY_FIELDS:
            raise ManifestError(f"service {index}: unexpected or missing fields")
        service_id = svc["id"]
        if not isinstance(service_id, str) or not _SERVICE_ID.fullmatch(service_id):
            raise ManifestError(f"service {index}: invalid id")
        if service_id in seen:
            raise ManifestError(f"service {index}: duplicate id")
        seen.add(service_id)
        if not isinstance(svc["title"], str) or not (1 <= len(svc["title"]) <= 64):
            raise ManifestError(f"service {index}: invalid title")
        if not isinstance(svc["role"], str) or svc["role"] not in _ROLES:
            raise ManifestError(f"service {index}: unsupported role")
        if not isinstance(svc["stage"], str) or svc["stage"] not in _STAGES:
            raise ManifestError(f"service {index}: unsupported stage")
        repository = svc["repository"]
        if repository is not None:
            if not isinstance(repository, str):
                raise ManifestError(f"service {index}: invalid repository")
            parsed = urlsplit(repository)
            if (parsed.scheme != "https" or parsed.hostname != "github.com"
                    or parsed.username or parsed.password or parsed.query or parsed.fragment
                    or not re.fullmatch(r"/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", parsed.path)):
                raise ManifestError(f"service {index}: repository must be a GitHub repo URL")
        if not _endpoint_hint_is_safe(svc["endpoint_hint"]):
            raise ManifestError(f"service {index}: unsafe endpoint hint")
    return manifest


def load_manifest(path: str | Path) -> dict:
    """Read bounded UTF-8 JSON. Fail closed on missing or invalid inventory."""
    source = Path(path)
    try:
        if source.stat().st_size > 128_000:
            raise ManifestError("manifest too large")
        contents = source.read_text(encoding="utf-8")
        parsed = json.loads(contents)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError("manifest could not be read as valid UTF-8 JSON") from exc
    return validate_manifest(parsed)
