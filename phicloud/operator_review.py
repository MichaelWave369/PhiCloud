"""R11 independent signed review + real browser WebAuthn assertion ceremony.

Manual opt-in localhost *operator review* only. The browser never signs R7
Ed25519 receipts, enrolls operator keys or obtains PhiID OAuth tokens.
An independent trusted signer must produce the short-lived R7 receipt and
stage its exact request in the same existing private R9 SQLite database.

The RP records one signed-and-user-verified review but NEVER calls consume(),
PhiShield, real resources, file/mail services or a PhiOS effect.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .durable_consent import DurableOwnerConsentPolicy, _private_path
from .local_consent import PolicyDenied, ReviewTicket
from .operator_approval import _RECEIPT_FIELDS, verified_receipt_expiry
from .operator_enrollment import OneShotServer, _json_object, MAX_INPUT
from .shield_policy import EffectRequest
from .webauthn_presence import RP_ID, ORIGIN

MAX_ATTEMPTS = 5
CEREMONY_LIFETIME = timedelta(minutes=5)
MIN_PAIRING_LENGTH = 24


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _read_private_receipt(path_text: str) -> dict:
    """Read an explicitly supplied private R7 receipt through a nofollow FD.

    Signed receipts include a pseudonymous subject; do not pass them in
    command arguments, URLs, logs or browser assets. The file is not a key.
    """
    path = Path(path_text)
    if not path.is_absolute() or path.suffix != ".json":
        raise PolicyDenied("private absolute signed receipt file required")
    try:
        _private_path(path.parent, is_dir=True)
        _private_path(path, is_dir=False)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            meta = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(meta.st_mode) or stat.S_IMODE(meta.st_mode) & 0o077
                or (os.name == "posix" and meta.st_uid != os.getuid())
                or meta.st_size > 4096
            ):
                raise PolicyDenied("insecure signed review file")
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise PolicyDenied("signed review file oversized")
        result = _json_object(raw)
        if set(result) != _RECEIPT_FIELDS:
            raise PolicyDenied("unknown signed review receipt fields")
        return result
    except (ValueError, OSError) as exc:
        raise PolicyDenied("private signed review file unavailable") from exc


class LocalOperatorApproval:
    """One exact verified receipt, one enrolled credential, one one-shot UI.

    Only local trusted setup supplies the full signed receipt and selects the
    already registered authenticator. Neither is taken from browser requests.
    Session and pairing code are memory-only; a restart cancels the ceremony.
    """

    def __init__(
        self, *, policy: DurableOwnerConsentPolicy, receipt: dict,
        pairing_code: str, now: datetime | None = None,
        credential_id: bytes | None = None,
    ):
        instant = now if now is not None else datetime.now(timezone.utc)
        if (
            type(policy) is not DurableOwnerConsentPolicy
            or type(receipt) is not dict or set(receipt) != _RECEIPT_FIELDS
            or type(pairing_code) is not str
            or not MIN_PAIRING_LENGTH <= len(pairing_code) <= 128
            or instant.tzinfo is None
        ):
            raise PolicyDenied("trusted local approval setup required")
        try:
            digest = hashlib.sha256(pairing_code.encode("ascii")).digest()
        except UnicodeEncodeError as exc:
            raise PolicyDenied("ASCII operator pairing required") from exc
        operator_id, kid, review_id = (
            receipt.get("operator_id"), receipt.get("kid"), receipt.get("review_id"),
        )
        if any(type(v) is not str for v in (operator_id, kid, review_id)):
            raise PolicyDenied("invalid signed review selector")

        def check(conn):
            row = conn.execute("""
                SELECT r.issuer,r.subject,r.request_json,r.review_until_ms,
                       o.revoked,k.public_key,k.revoked
                FROM requests r JOIN owners o
                  ON r.issuer=o.issuer AND r.subject=o.subject
                LEFT JOIN operator_keys k ON k.operator_id=? AND k.kid=?
                WHERE r.review_id=? AND r.state='pending'
            """, (operator_id,kid,review_id)).fetchone()
            if row is None:
                raise PolicyDenied("pending exact signed review not found")
            issuer, subject, saved, until, revoked, key, key_revoked = row
            if revoked or key_revoked != 0 or key is None:
                raise PolicyDenied("review signer or owner revoked")
            try:
                request = EffectRequest(**json.loads(saved))
                ticket = ReviewTicket(
                    review_id=review_id, request=request,
                    expires_at=datetime.fromtimestamp(until/1000,timezone.utc),
                )
                expiry = verified_receipt_expiry(
                    receipt,ticket=ticket,public_key=bytes(key),now=instant,
                )
            except (ValueError,TypeError,KeyError,OverflowError,PolicyDenied) as exc:
                raise PolicyDenied("invalid exact signed request") from exc
            if (
                not policy._allow(request)
                or request.subject_issuer != issuer or request.subject_id != subject
            ):
                raise PolicyDenied("invalid owned synthetic request")
            if credential_id is None:
                credentials=conn.execute("""
                    SELECT credential_id FROM operator_credentials
                    WHERE operator_id=? AND revoked=0 AND rp_id=? AND origin=?
                    ORDER BY credential_id LIMIT 2
                """, (operator_id,RP_ID,ORIGIN)).fetchall()
                if len(credentials) != 1:
                    raise PolicyDenied("exactly one eligible credential required, or select in trusted CLI")
                selected=bytes(credentials[0][0])
            else:
                if type(credential_id) is not bytes:
                    raise PolicyDenied("invalid selected credential")
                found=conn.execute("""
                    SELECT 1 FROM operator_credentials
                    WHERE credential_id=? AND operator_id=? AND revoked=0
                      AND rp_id=? AND origin=?
                """, (credential_id,operator_id,RP_ID,ORIGIN)).fetchone()
                if found is None:
                    raise PolicyDenied("selected operator credential unavailable")
                selected=credential_id
            return request, selected, expiry

        request, selected, expiry=policy._transaction(check)
        self.policy=policy
        self.receipt=receipt
        self.request=request
        self.operator_id=operator_id
        self.credential_id=selected
        self._pairing_digest=digest
        self._expires=min(instant+CEREMONY_LIFETIME,
                          datetime.fromtimestamp(expiry/1000,timezone.utc))
        self._attempts=0
        self._session: str | None=None
        self._paired=False
        self._challenge_issued=False
        self._spent=False

    def _session_valid(self, session: object, now: datetime) -> bool:
        return (
            not self._spent and self._paired
            and self._session is not None and type(session) is str
            and hmac.compare_digest(session,self._session)
            and now.tzinfo is not None and now < self._expires
        )

    def unlock(self, *, pairing_code: object, now: datetime) -> dict:
        if (
            self._spent or self._paired or now.tzinfo is None
            or now >= self._expires or self._attempts >= MAX_ATTEMPTS
            or type(pairing_code) is not str
        ):
            raise PolicyDenied("operator approval pairing not available")
        self._attempts += 1
        digest=hashlib.sha256(pairing_code.encode("utf-8")).digest()
        if not hmac.compare_digest(digest,self._pairing_digest):
            raise PolicyDenied("invalid operator pairing")
        self._paired=True
        self._session=secrets.token_urlsafe(32)
        return {
            "session":self._session,
            "operator":self.operator_id,
            "review_id":self.receipt["review_id"],
            "request":asdict(self.request),
            "expires_at_ms":int(self._expires.timestamp()*1000),
            "scope":"synthetic-profile-read-only",
            "execution_authority":False,
        }

    def challenge(self, *, session: object, acknowledged: object, now: datetime) -> dict:
        if not self._session_valid(session,now) or self._challenge_issued:
            raise PolicyDenied("approval session or challenge unavailable")
        if type(acknowledged) is not bool or not acknowledged:
            raise PolicyDenied("explicit exact-action confirmation required")
        # R9 re-checks signer/owner/credential and persists the one-use
        # challenge, always bound to the exact signed R7 receipt.
        challenge=self.policy.begin_operator_stepup(
            self.receipt, credential_id=self.credential_id,now=now,
        )
        self._challenge_issued=True
        remaining_ms=max(1,min(30_000,int((self._expires-now).total_seconds()*1000)))
        return {
            "challenge":_b64url(challenge),
            "rpId":RP_ID,
            "timeout":remaining_ms,
            "allowCredentials":[{
                "type":"public-key","id":_b64url(self.credential_id)
            }],
            "userVerification":"required",
        }

    def complete(self, *, session: object, assertion: object, now: datetime) -> dict:
        if not self._session_valid(session,now):
            raise PolicyDenied("approval session expired or invalid")
        self._spent=True
        if not self._challenge_issued or type(assertion) is not dict:
            raise PolicyDenied("no matching WebAuthn challenge")
        accepted=self.policy.approve_signed_with_stepup(
            self.receipt,assertion,now=now,
        )
        if not accepted:
            raise PolicyDenied("signed WebAuthn approval denied")
        return {
            "review_recorded":True,
            "signed_review_verified":True,
            "webauthn_uv_verified":True,
            "execution_authority":False,
            "resource_read":False,
            "still_requires":"fresh PhiID token and independently verified ANC risk",
        }

    def decline(self, *, session: object, now: datetime) -> dict:
        if not self._session_valid(session,now):
            raise PolicyDenied("approval session expired or invalid")
        self._spent=True
        # R6's acknowledged=False burns the pending ticket regardless of
        # whether the UI ever issued its WebAuthn challenge.
        self.policy.approve(
            self.receipt["review_id"],shown_request=self.request,
            acknowledged=False,now=now,
        )
        return {
            "review_recorded":False,"declined":True,
            "execution_authority":False,
        }


def handler_factory(ceremony: LocalOperatorApproval):
    root=Path(__file__).resolve().parent/"static"
    files={
        "/":("operator_approve.html","text/html"),
        "/operator_approve.js":("operator_approve.js","application/javascript"),
        "/operator_approve.css":("operator_enroll.css","text/css"),
    }

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            # Never log review contents, subject identifiers or pairing inputs.
            pass

        def _respond(self, status: int, body: bytes, mime: str="application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type",mime+"; charset=utf-8")
            self.send_header("Content-Length",str(len(body)))
            self.send_header("Cache-Control","no-store")
            self.send_header("Pragma","no-cache")
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("X-Frame-Options","DENY")
            self.send_header("Referrer-Policy","no-referrer")
            self.send_header("Cross-Origin-Resource-Policy","same-origin")
            self.send_header("Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _local(self, *, mutation: bool) -> bool:
            if (
                self.client_address[0]!="127.0.0.1"
                or self.headers.get_all("Host",[])!=["localhost:8769"]
                or self.headers.get("Sec-Fetch-Site")=="cross-site"
            ):
                self._respond(403,b'{"error":"local_origin_required"}')
                return False
            if mutation and (
                self.headers.get_all("Origin",[])!=[ORIGIN]
                or self.headers.get("Sec-Fetch-Site") not in (None,"same-origin")
            ):
                self._respond(403,b'{"error":"same_origin_review_required"}')
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            if not self._local(mutation=False):
                return
            requested=urlsplit(self.path)
            if requested.query or requested.fragment or requested.path not in files:
                self._respond(404,b'{"error":"not_found"}')
                return
            name,mime=files[requested.path]
            self._respond(200,(root/name).read_bytes(),mime)

        def do_POST(self) -> None:  # noqa: N802
            if not self._local(mutation=True):
                return
            requested=urlsplit(self.path)
            paths={
                "/v1/review/unlock":"unlock",
                "/v1/review/challenge":"challenge",
                "/v1/review/complete":"complete",
                "/v1/review/decline":"decline",
            }
            if requested.query or requested.fragment or requested.path not in paths:
                self._respond(404,b'{"error":"not_found"}')
                return
            lengths=self.headers.get_all("Content-Length",[])
            if (
                self.headers.get_all("Transfer-Encoding")
                or len(lengths)!=1 or not lengths[0].isdigit()
                or int(lengths[0])>MAX_INPUT
                or self.headers.get_all("Content-Type",[])!=["application/json"]
            ):
                self.close_connection=True
                self._respond(413,b'{"error":"invalid_body"}')
                return
            try:
                data=_json_object(self.rfile.read(int(lengths[0])))
                method=paths[requested.path]
                expected={
                    "unlock":{"code"},"challenge":{"session","acknowledged"},
                    "complete":{"session","assertion"},"decline":{"session"},
                }[method]
                if set(data)!=expected:
                    raise PolicyDenied("unexpected review fields")
                now=datetime.now(timezone.utc)
                if method=="unlock":
                    result=ceremony.unlock(pairing_code=data["code"],now=now)
                elif method=="challenge":
                    result=ceremony.challenge(
                        session=data["session"],acknowledged=data["acknowledged"],now=now,
                    )
                elif method=="complete":
                    result=ceremony.complete(
                        session=data["session"],assertion=data["assertion"],now=now,
                    )
                else:
                    result=ceremony.decline(session=data["session"],now=now)
            except (PolicyDenied,TypeError,ValueError,OverflowError,UnicodeError):
                self._respond(403,b'{"error":"operator_review_denied"}')
                return
            self._respond(200,json.dumps(result,separators=(",",":")).encode())

    return Handler


def main(argv: list[str] | None=None) -> int:
    parser=argparse.ArgumentParser(
        description="R11 operator-paired localhost exact-action signed/passkey review"
    )
    parser.add_argument("--db",required=True,help="existing absolute private R9 SQLite DB")
    parser.add_argument("--receipt-file",required=True,
                        help="existing 0600 private signed R7 review JSON (not a key)")
    args=parser.parse_args(argv)
    if (
        os.environ.get("PHICLOUD_OPERATOR_APPROVAL_DEV")!="1"
        or os.environ.get("NODE_ENV")=="production"
        or os.environ.get("PHICLOUD_ENV")=="production"
        or not sys.stdin.isatty() or not sys.stdout.isatty()
    ):
        print("DENY: trusted local TTY and opt-in required",file=sys.stderr)
        return 2
    path=Path(args.db)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        print("DENY: existing private absolute database required",file=sys.stderr)
        return 2
    try:
        policy=DurableOwnerConsentPolicy(path)
        receipt=_read_private_receipt(args.receipt_file)
        code=secrets.token_urlsafe(24)
        ceremony=LocalOperatorApproval(
            policy=policy,receipt=receipt,pairing_code=code,
        )
        with OneShotServer(("127.0.0.1",8769),handler_factory(ceremony)) as server:
            print("PhiCloud R11 LOCAL synthetic-profile review (no execution)")
            print("Open http://localhost:8769 on this machine")
            print("One-use pairing code (private, do not share): "+code)
            print("The browser must show all signed fields before WebAuthn verification.")
            print("Press Ctrl+C to close this one-use approval server.")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
        return 0
    except (PolicyDenied,ValueError,OSError):
        print("DENY: local signed operator review unavailable",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
