"""R10 operator-local browser WebAuthn *registration*, gated by console pairing.

Not a production authentication provider or a user identity enrollment API.
An already trusted local OS operator with access to an existing private SQLite
ledger must explicitly start this separate opt-in localhost-only one-shot
ceremony. The code is not a proof of which human is at the keyboard.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .durable_consent import DurableOwnerConsentPolicy
from .local_consent import PolicyDenied
from .operator_approval import _IDENTIFIER
from .webauthn_presence import RP_ID, ORIGIN

try:
    from webauthn import (
        generate_registration_options, options_to_json,
        verify_registration_response,
    )
    from webauthn.helpers.structs import (
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
except ImportError:
    generate_registration_options = None
    options_to_json = None
    verify_registration_response = None

MAX_AGE = timedelta(minutes=5)
MAX_ATTEMPTS = 5
MAX_INPUT = 16_384
MAX_CREDENTIAL = 4096


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON property")
        result[key] = value
    return result


def _json_object(raw: bytes) -> dict:
    if type(raw) is not bytes or len(raw) > MAX_INPUT:
        raise PolicyDenied("invalid registration input length")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_no_duplicates)
    except (UnicodeError, ValueError, TypeError) as exc:
        raise PolicyDenied("invalid registration JSON") from exc
    if type(obj) is not dict:
        raise PolicyDenied("registration JSON object required")
    return obj


@dataclass(slots=True)
class _Pending:
    challenge: bytes
    session: str
    expires_at: datetime


class LocalOperatorEnrollment:
    """Single-use trusted-terminal bootstrap + browser passkey registration.

    No credential public key is accepted without R10 WebAuthn registration
    verification and an active signing operator previously enrolled in R7.
    Every code/challenge is volatile; a process restart cancels registration.
    """

    def __init__(
        self, *, policy: DurableOwnerConsentPolicy, operator_id: str,
        pairing_code: str, now: datetime | None = None,
    ) -> None:
        if (
            type(policy) is not DurableOwnerConsentPolicy
            or type(operator_id) is not str
            or not _IDENTIFIER.fullmatch(operator_id)
            or type(pairing_code) is not str
            or len(pairing_code) < 24 or len(pairing_code) > 128
        ):
            raise PolicyDenied("invalid trusted local operator bootstrap")
        if generate_registration_options is None:
            raise PolicyDenied("WebAuthn registration verifier unavailable")
        # Registration can only attach to an existing operator with a
        # previously trusted, still-active Ed25519 signer.
        def check(conn):
            return conn.execute(
                "SELECT 1 FROM operator_keys WHERE operator_id=? AND revoked=0",
                (operator_id,),
            ).fetchone() is not None
        if not policy._transaction(check):
            raise PolicyDenied("operator must already have an active signed-review key")
        self.policy = policy
        self.operator_id = operator_id
        self._secret_digest = hashlib.sha256(pairing_code.encode("ascii")).digest()
        instant = now if now is not None else datetime.now(timezone.utc)
        if instant.tzinfo is None:
            raise PolicyDenied("timezone-aware startup required")
        self._expires = instant + MAX_AGE
        self._attempts = 0
        self._pending: _Pending | None = None
        self._spent = False

    def begin(self, *, pairing_code: str, now: datetime) -> dict:
        if now.tzinfo is None:
            raise PolicyDenied("timezone-aware clock required")
        if self._spent or self._pending is not None or now >= self._expires:
            raise PolicyDenied("registration already started or expired")
        if self._attempts >= MAX_ATTEMPTS:
            raise PolicyDenied("operator pairing locked")
        if type(pairing_code) is not str:
            raise PolicyDenied("invalid pairing entry")
        self._attempts += 1
        digest = hashlib.sha256(pairing_code.encode("utf-8")).digest()
        if not hmac.compare_digest(digest, self._secret_digest):
            raise PolicyDenied("incorrect pairing code")
        self._spent = True  # pairing code cannot restart ceremony
        challenge = secrets.token_bytes(32)
        nonce = secrets.token_urlsafe(32)
        # User handle contains NO operator/account email or subject.
        options = generate_registration_options(
            rp_id=RP_ID, rp_name="PhiCloud Local Operator DEV",
            user_name=self.operator_id,
            user_display_name=self.operator_id,
            user_id=secrets.token_bytes(32),
            challenge=challenge, timeout=120_000,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED,
                resident_key=ResidentKeyRequirement.PREFERRED,
            ),
        )
        self._pending = _Pending(
            challenge=challenge, session=nonce,
            expires_at=min(now + timedelta(minutes=2), self._expires),
        )
        return {
            "session": nonce,
            "options": json.loads(options_to_json(options)),
            "operator": self.operator_id,
            "mode": "dev_only_real_webauthn_registration",
        }

    def finish(self, *, session: object, credential: object, now: datetime) -> dict:
        pending = self._pending
        self._pending = None  # consume before validation, including error cases
        if (
            pending is None or type(session) is not str
            or not hmac.compare_digest(session, pending.session)
            or now.tzinfo is None or now >= pending.expires_at
            or type(credential) is not dict
        ):
            raise PolicyDenied("invalid, expired or already spent registration")
        raw = json.dumps(credential, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > MAX_INPUT:
            raise PolicyDenied("oversize WebAuthn registration response")
        try:
            verified = verify_registration_response(
                credential=credential,
                expected_challenge=pending.challenge,
                expected_rp_id=RP_ID,
                expected_origin=ORIGIN,
                require_user_verification=True,
                require_user_presence=True,
            )
        except Exception as exc:
            raise PolicyDenied("WebAuthn registration verification failed") from exc
        if not (
            type(verified.credential_id) is bytes
            and 16 <= len(verified.credential_id) <= 128
            and type(verified.credential_public_key) is bytes
            and 32 <= len(verified.credential_public_key) <= MAX_CREDENTIAL
            and type(verified.sign_count) is int
        ):
            raise PolicyDenied("verified credential metadata invalid")
        # This commits ONLY the verified COSE key from the RP library.
        # A browser-provided public key is never accepted.
        self.policy.register_operator_credential(
            operator_id=self.operator_id,
            credential_id=verified.credential_id,
            public_key=verified.credential_public_key,
            sign_count=verified.sign_count,
        )
        return {
            "enrolled": True, "operator": self.operator_id,
            "scope": "local_dev_synthetic_profile_read_only",
            "approval_granted": False, "execution_authority": False,
        }


class OneShotServer(ThreadingHTTPServer):
    allow_reuse_address = False
    daemon_threads = True


def handler_factory(ceremony: LocalOperatorEnrollment):
    root = Path(__file__).resolve().parent / "static"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            # Never print web paths, submitted code, WebAuthn assertion, IP.
            pass

        def _respond(self, status: int, payload: bytes, *, media: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", media + "; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Pragma", "no-cache")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(payload)

        def _local(self, *, mutation: bool) -> bool:
            if (
                self.client_address[0] != "127.0.0.1"
                or self.headers.get_all("Host", []) != ["localhost:8769"]
                or self.headers.get("Sec-Fetch-Site") == "cross-site"
            ):
                self._respond(403,b'{"error":"local_origin_required"}')
                return False
            if mutation:
                if (
                    self.headers.get_all("Origin", []) != [ORIGIN]
                    or self.headers.get("Sec-Fetch-Site") not in (None,"same-origin")
                ):
                    self._respond(403,b'{"error":"same_origin_post_required"}')
                    return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            if not self._local(mutation=False):
                return
            paths = {
                "/": ("operator_enroll.html","text/html"),
                "/operator_enroll.js":("operator_enroll.js","application/javascript"),
                "/operator_enroll.css":("operator_enroll.css","text/css"),
            }
            requested = urlsplit(self.path)
            if requested.query or requested.fragment or requested.path not in paths:
                self._respond(404,b'{"error":"not_found"}')
                return
            name,media = paths[requested.path]
            self._respond(200,(root/name).read_bytes(),media=media)

        def do_POST(self) -> None:  # noqa: N802
            if not self._local(mutation=True):
                return
            path = urlsplit(self.path)
            if path.query or path.fragment or path.path not in ("/v1/enroll/start","/v1/enroll/finish"):
                self._respond(404,b'{"error":"not_found"}')
                return
            lengths=self.headers.get_all("Content-Length",[])
            if (
                self.headers.get_all("Transfer-Encoding")
                or len(lengths)!=1 or not lengths[0].isdigit()
                or int(lengths[0]) > MAX_INPUT
                or self.headers.get_all("Content-Type",[]) != ["application/json"]
            ):
                self.close_connection=True
                self._respond(413,b'{"error":"invalid_body"}')
                return
            try:
                data = _json_object(self.rfile.read(int(lengths[0])))
                now=datetime.now(timezone.utc)
                if path.path=="/v1/enroll/start":
                    if set(data)!={"code"}:
                        raise PolicyDenied("invalid start request")
                    result=ceremony.begin(pairing_code=data["code"],now=now)
                else:
                    if set(data)!={"session","credential"}:
                        raise PolicyDenied("invalid completion request")
                    result=ceremony.finish(
                        session=data["session"],credential=data["credential"],now=now,
                    )
            except (PolicyDenied,TypeError,ValueError,OverflowError,UnicodeError):
                self._respond(403,b'{"error":"operator_enrollment_denied"}')
                return
            self._respond(200,json.dumps(result,separators=(",",":")).encode())

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser=argparse.ArgumentParser(
        description="PhiCloud R10 local-only one-shot WebAuthn operator enrollment"
    )
    parser.add_argument("--db",required=True,help="existing private operator SQLite database")
    parser.add_argument("--operator",required=True,help="existing R7 signing operator ID")
    args=parser.parse_args(argv)
    if (
        os.environ.get("PHICLOUD_OPERATOR_ENROLL_DEV") != "1"
        or os.environ.get("NODE_ENV") == "production"
        or os.environ.get("PHICLOUD_ENV") == "production"
        or not sys.stdin.isatty() or not sys.stdout.isatty()
    ):
        print("DENY: explicit local opt-in and interactive console required",file=sys.stderr)
        return 2
    path=Path(args.db)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        print("DENY: existing private absolute database required",file=sys.stderr)
        return 2
    try:
        policy=DurableOwnerConsentPolicy(path)
        code=secrets.token_urlsafe(24)
        ceremony=LocalOperatorEnrollment(
            policy=policy,operator_id=args.operator,pairing_code=code,
        )
        with OneShotServer(("127.0.0.1",8769),handler_factory(ceremony)) as server:
            print("PhiCloud R10 LOCAL development passkey enrollment")
            print("Open http://localhost:8769 on this same machine.")
            print("One-use pairing code (do not share): "+code)
            print("Only for this local operator and synthetic profile review.")
            print("Press Ctrl+C to end the session.")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
        return 0
    except (PolicyDenied,ValueError,OSError) as exc:
        print("DENY: local operator enrollment unavailable",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
