"""PhiCloud R3: strictly LOCAL resource-server OAuth2 introspection gate.

No handwritten JWT parsing, signing, identity provider, or token minting.
Keycloak's confidential-client token introspection is the authority.
The returned metadata is then restricted to this single local test resource.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import (
    HTTPRedirectHandler, ProxyHandler, Request, build_opener,
)

ISSUER = "http://127.0.0.1:8080/realms/phiid-dev"
INTROSPECTION_ENDPOINT = ISSUER + "/protocol/openid-connect/token/introspect"
AUDIENCE = "phicloud-resource-dev"
REQUIRED_SCOPE = "phicloud.profile.read"
DEMO_READ_SCOPE = "phicloud.demo.read"
DEMO_WRITE_SCOPE = "phicloud.demo.write"
RESOURCE_SCOPES = frozenset({REQUIRED_SCOPE, DEMO_READ_SCOPE, DEMO_WRITE_SCOPE})
MAX_TOKEN_LENGTH = 4096
MAX_RESPONSE_BYTES = 16_384
MAX_CLOCK_SKEW_SECONDS = 0
_TOKEN = re.compile(r"^[A-Za-z0-9._~+/-]+={0,2}$")


class AuthorizationDenied(Exception):
    """No proof of a valid access token, or insufficient scope/audience."""


class AuthorizationUnavailable(Exception):
    """Authoritative IdP unavailable. Never fail open or use stale results."""


@dataclass(frozen=True)
class AuthorizedPrincipal:
    issuer: str
    sub: str
    scope: str
    audience: str

    def public_profile(self) -> dict:
        # Stable pseudonym for this demo endpoint, not a credential or
        # substitute for service-side ownership checks on real data.
        identifier = hashlib.sha256(
            ("phicloud-local-profile-v0.1\0" + self.issuer + "\0" + self.sub)
            .encode("utf-8")
        ).hexdigest()
        return {
            "schema": "phicloud.private-profile.v0.1",
            "authenticated": True,
            "service": "phicloud",
            "resource": "local_demo_profile_only",
            "principal_fingerprint": identifier,
            "verified_issuer": self.issuer,
            "authorized_scope": self.scope,
            "authorized_audience": self.audience,
            "persistent_account": False,
            "cloud_storage_access": False,
            "mailbox_access": False,
            "phios_effect_authority": False,
        }


def validate_bearer_header(values: list[str] | None) -> str:
    if not values or len(values) != 1:
        raise AuthorizationDenied("one_bearer_header_required")
    header = values[0]
    if not isinstance(header, str) or len(header) > MAX_TOKEN_LENGTH + 7:
        raise AuthorizationDenied("invalid_bearer_header")
    if not header.startswith("Bearer "):
        raise AuthorizationDenied("invalid_bearer_scheme")
    token = header[7:]
    if not 20 <= len(token) <= MAX_TOKEN_LENGTH or not _TOKEN.fullmatch(token):
        raise AuthorizationDenied("invalid_bearer_token")
    return token


def validate_introspection(
    data: object, *, required_scope: str = REQUIRED_SCOPE, now: int | None = None
) -> AuthorizedPrincipal:
    """Treat every field of the introspection response as untrusted unless
    it came from our authenticated, pinned provider channel.
    """
    if required_scope not in RESOURCE_SCOPES:
        raise AuthorizationDenied("unsupported_resource_scope")
    if now is None:
        now = int(time.time())
    if not isinstance(data, dict) or data.get("active") is not True:
        raise AuthorizationDenied("inactive_token")
    if data.get("iss") != ISSUER:
        raise AuthorizationDenied("unexpected_issuer")
    if data.get("token_type") != "Bearer":
        raise AuthorizationDenied("not_an_access_token")
    sub = data.get("sub")
    if not isinstance(sub, str) or not 1 <= len(sub) <= 255:
        raise AuthorizationDenied("missing_subject")
    exp = data.get("exp")
    if type(exp) is not int or exp <= now - MAX_CLOCK_SKEW_SECONDS:
        raise AuthorizationDenied("expired_or_missing_expiration")
    nbf = data.get("nbf")
    if nbf is not None and (type(nbf) is not int or nbf > now):
        raise AuthorizationDenied("not_yet_valid")
    audience = data.get("aud")
    if isinstance(audience, str):
        audiences = [audience]
    elif isinstance(audience, list) and all(isinstance(v, str) for v in audience):
        audiences = audience
    else:
        audiences = []
    if AUDIENCE not in audiences:
        raise AuthorizationDenied("wrong_resource_audience")
    scopes = data.get("scope")
    if not isinstance(scopes, str) or required_scope not in scopes.split():
        raise AuthorizationDenied("required_scope_absent")
    return AuthorizedPrincipal(
        issuer=ISSUER, sub=sub, scope=required_scope, audience=AUDIENCE
    )


class _NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _pinned_introspection_transport(token: str, secret: str) -> dict:
    """Sends one POST to an EXACT loopback endpoint; no proxies/redirects."""
    basic = base64.b64encode((AUDIENCE + ":" + secret).encode("utf-8")).decode("ascii")
    body = urlencode({"token": token, "token_type_hint": "access_token"}).encode("ascii")
    request = Request(
        INTROSPECTION_ENDPOINT, data=body, method="POST",
        headers={
            "Authorization": "Basic " + basic,
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "Cache-Control": "no-store",
        }
    )
    opener = build_opener(ProxyHandler({}), _NoRedirects())
    try:
        with opener.open(request, timeout=3) as response:
            if response.status != 200 or response.geturl() != INTROSPECTION_ENDPOINT:
                raise AuthorizationUnavailable("provider_response_rejected")
            if response.headers.get_content_type() != "application/json":
                raise AuthorizationUnavailable("provider_content_type_rejected")
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise AuthorizationUnavailable("provider_response_too_large")
            parsed = json.loads(data.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise AuthorizationUnavailable("provider_malformed_response")
            return parsed
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, UnicodeError) as exc:
        raise AuthorizationUnavailable("provider_unavailable_or_invalid") from exc


class LocalTokenIntrospector:
    """Fail-closed resource authorization with NO cached active-token results."""

    def __init__(
        self, client_secret: str,
        transport: Callable[[str, str], dict] = _pinned_introspection_transport,
    ) -> None:
        if not isinstance(client_secret, str) or not 32 <= len(client_secret) <= 256:
            raise ValueError("private_confidential_client_secret_required")
        if any(ord(c) < 33 or ord(c) > 126 for c in client_secret):
            raise ValueError("invalid_confidential_client_secret")
        self._secret = client_secret
        self._transport = transport

    def authorize(self, token: str, *, required_scope: str = REQUIRED_SCOPE) -> AuthorizedPrincipal:
        if required_scope not in RESOURCE_SCOPES:
            raise AuthorizationDenied("unsupported_resource_scope")
        if not isinstance(token, str) or not 20 <= len(token) <= MAX_TOKEN_LENGTH:
            raise AuthorizationDenied("invalid_bearer_token")
        try:
            claims = self._transport(token, self._secret)
        except AuthorizationDenied:
            raise
        except AuthorizationUnavailable:
            raise
        except Exception as exc:
            raise AuthorizationUnavailable("provider_unavailable") from exc
        return validate_introspection(claims, required_scope=required_scope)


def create_local_introspector(env: dict | None = None) -> LocalTokenIntrospector | None:
    settings = os.environ if env is None else env
    if settings.get("PHICLOUD_ENABLE_OAUTH_DEV") != "1":
        return None
    if settings.get("NODE_ENV") == "production" or settings.get("PHICLOUD_ENV") == "production":
        raise ValueError("development_only_authz")
    secret = settings.get("PHICLOUD_OAUTH_CLIENT_SECRET")
    return LocalTokenIntrospector(secret)
