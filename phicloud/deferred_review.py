"""R12 deferred local review, independent Unix signer, short-lived receipt.

The browser may inspect an *unsigned* five-minute preview only after a
one-use terminal pairing. Only after explicit confirmation does the
trusted server ask a SEPARATE signing service to sign the exact canonical
R7 bytes. The browser never submits or receives a signature/private key.

Signer service implementation and private-key custody are independent and
NOT implemented here. A local socket by itself does NOT authenticate a
human or isolate same-user malicious code. All outputs remain non-executable.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import stat
import struct
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .durable_consent import DurableOwnerConsentPolicy, _private_path
from .local_consent import PolicyDenied, ReviewTicket
from .operator_approval import (
    SCHEMA, PURPOSE, canonical_message, verified_receipt_expiry, _IDENTIFIER,
)
from .operator_enrollment import OneShotServer
from .operator_review import handler_factory, _b64url
from .shield_policy import EffectRequest, _utc
from .webauthn_presence import RP_ID, ORIGIN

PREVIEW_SECONDS = 300
SOCKET_RESPONSE_LIMIT = 256
SIGNER_SCHEMA = "phicloud.detached-sign.v1"


class UnixOperatorSigner:
    """Client for a *separately administered* policy-checked signer service.

    Requires a private operator-owned POSIX socket directory, Unix socket
    and Linux SO_PEERCRED with the same UID. It is not an HSM, and it is
    NOT proof against a compromised same-user host. No fallback signer.
    """

    def __init__(self, path: str | Path):
        if os.name != "posix" or not hasattr(socket, "SO_PEERCRED"):
            raise PolicyDenied("Linux Unix peer credentials required")
        self.path = Path(path)
        if not self.path.is_absolute():
            raise PolicyDenied("absolute signer socket path required")
        self._check_path()

    def _check_path(self):
        _private_path(self.path.parent,is_dir=True)
        info=self.path.lstat()
        if not stat.S_ISSOCK(info.st_mode):
            raise PolicyDenied("signer must be a Unix socket")
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise PolicyDenied("signer socket must be owner-private")

    def sign(self, message: bytes, *, operator_id: str, kid: str) -> bytes:
        if (
            type(message) is not bytes or not message.startswith(
                b"PHICLOUD_OPERATOR_REVIEW_ED25519_V1\x00"
            ) or len(message) > 4096
            or type(operator_id) is not str or not _IDENTIFIER.fullmatch(operator_id)
            or type(kid) is not str or not _IDENTIFIER.fullmatch(kid)
        ):
            raise PolicyDenied("invalid exact signer input")
        self._check_path()
        payload=json.dumps({
            "schema":SIGNER_SCHEMA,"operator_id":operator_id,
            "kid":kid,"message":_b64url(message),
        },separators=(",",":")).encode("ascii")+b"\n"
        try:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as conn:
                conn.settimeout(8)
                conn.connect(str(self.path))
                creds=conn.getsockopt(
                    socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize("3i")
                )
                _, uid, _ = struct.unpack("3i",creds)
                if uid != os.getuid():
                    raise PolicyDenied("signer peer UID mismatch")
                conn.sendall(payload)
                received=bytearray()
                while len(received) < SOCKET_RESPONSE_LIMIT:
                    chunk=conn.recv(1)
                    if not chunk:
                        break
                    received.extend(chunk)
                    if chunk==b"\n":
                        break
                if not received.endswith(b"\n"):
                    raise PolicyDenied("incomplete or oversized signer reply")
                reply=json.loads(
                    received.decode("ascii"),
                    object_pairs_hook=_reject_duplicates,
                )
                if type(reply) is not dict or set(reply)!={"signature"}:
                    raise PolicyDenied("invalid signer response shape")
                encoded=reply["signature"]
                if (
                    type(encoded) is not str or len(encoded)!=86
                    or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                           for c in encoded)
                ):
                    raise PolicyDenied("invalid signer signature encoding")
                sig=base64.urlsafe_b64decode(encoded+"==")
                if len(sig)!=64 or _b64url(sig)!=encoded:
                    raise PolicyDenied("noncanonical signer signature")
                return sig
        except (OSError,ValueError,UnicodeError,TypeError,OverflowError) as exc:
            raise PolicyDenied("independent signer unavailable") from exc


def _reject_duplicates(pairs):
    obj={}
    for name,value in pairs:
        if name in obj:
            raise ValueError("duplicate signer reply property")
        obj[name]=value
    return obj


class DeferredOperatorApproval:
    """Paired preview then late independent signature then R9 UV assertion.

    No signer private key enters this process. The signer object is a trusted
    dependency supplied by the local operator; the actual CLI uses only the
    Linux Unix-domain socket client above. R12 unit tests inject a disposable
    cryptographic signer fixture.
    """

    def __init__(
        self, *, policy: DurableOwnerConsentPolicy, review_id: str,
        operator_id: str, kid: str, signer: UnixOperatorSigner,
        pairing_code: str, now: datetime | None=None,
        credential_id: bytes | None=None,
    ) -> None:
        instant=_utc(now if now is not None else datetime.now(timezone.utc))
        if (
            type(policy) is not DurableOwnerConsentPolicy
            or type(review_id) is not str or not review_id
            or type(operator_id) is not str or not _IDENTIFIER.fullmatch(operator_id)
            or type(kid) is not str or not _IDENTIFIER.fullmatch(kid)
            or type(pairing_code) is not str
            or not 24 <= len(pairing_code) <= 128
            or not callable(getattr(signer,"sign",None))
        ):
            raise PolicyDenied("trusted deferred review setup required")
        try:
            pairing_hash=hashlib.sha256(pairing_code.encode("ascii")).digest()
        except UnicodeEncodeError as exc:
            raise PolicyDenied("ASCII pairing code required") from exc

        def preflight(conn):
            row=conn.execute("""
                SELECT r.issuer,r.subject,r.request_json,r.review_until_ms,
                       o.revoked,k.public_key,k.revoked,r.presence_challenge
                FROM requests r JOIN owners o
                  ON r.issuer=o.issuer AND r.subject=o.subject
                LEFT JOIN operator_keys k
                  ON k.operator_id=? AND k.kid=?
                WHERE r.review_id=? AND r.state='pending'
            """,(operator_id,kid,review_id)).fetchone()
            if row is None:
                raise PolicyDenied("pending review unavailable")
            iss,sub,saved,expires,revoked,key,key_revoked,presence=row
            if (
                revoked or key_revoked != 0 or key is None
                or presence is not None or int(instant.timestamp()*1000)>=expires
            ):
                raise PolicyDenied("review expired, already challenged or revoked")
            try:
                req=EffectRequest(**json.loads(saved))
                if (
                    not policy._allow(req)
                    or req.subject_issuer!=iss or req.subject_id!=sub
                ):
                    raise PolicyDenied("invalid exact reviewed action")
            except (KeyError,TypeError,ValueError) as exc:
                raise PolicyDenied("malformed staged request") from exc
            if credential_id is None:
                credential_rows=conn.execute("""
                    SELECT credential_id FROM operator_credentials
                    WHERE operator_id=? AND revoked=0 AND rp_id=? AND origin=?
                    ORDER BY credential_id LIMIT 2
                """,(operator_id,RP_ID,ORIGIN)).fetchall()
                if len(credential_rows)!=1:
                    raise PolicyDenied("one eligible operator credential required")
                selected=bytes(credential_rows[0][0])
            else:
                if type(credential_id) is not bytes:
                    raise PolicyDenied("invalid credential selection")
                match=conn.execute("""
                    SELECT 1 FROM operator_credentials
                    WHERE credential_id=? AND operator_id=? AND revoked=0
                      AND rp_id=? AND origin=?
                """,(credential_id,operator_id,RP_ID,ORIGIN)).fetchone()
                if not match:
                    raise PolicyDenied("selected credential not trusted")
                selected=credential_id
            return req,selected,datetime.fromtimestamp(expires/1000,timezone.utc)

        request,selected,deadline=policy._transaction(preflight)
        self.policy=policy
        self.review_id=review_id
        self.operator_id=operator_id
        self.kid=kid
        self.signer=signer
        self.request=request
        self.credential_id=selected
        self._deadline=min(deadline,instant+timedelta(seconds=PREVIEW_SECONDS))
        self._pairing_hash=pairing_hash
        self._attempts=0
        self._session=None
        self._paired=False
        self._signing_started=False
        self._challenge_issued=False
        self._spent=False
        self._receipt=None

    def _session_valid(self,session,now):
        return (
            self._paired and not self._spent
            and type(session) is str and self._session is not None
            and hmac.compare_digest(session,self._session)
            and _utc(now)<self._deadline
        )

    def unlock(self, *, pairing_code: object, now: datetime) -> dict:
        instant=_utc(now)
        if (
            self._spent or self._paired or instant>=self._deadline
            or self._attempts>=5 or type(pairing_code) is not str
        ):
            raise PolicyDenied("preview pairing unavailable")
        self._attempts+=1
        if not hmac.compare_digest(
            hashlib.sha256(pairing_code.encode("utf-8")).digest(),self._pairing_hash
        ):
            raise PolicyDenied("incorrect local pairing")
        self._paired=True
        self._session=secrets.token_urlsafe(32)
        return {
            "session":self._session,
            "operator":self.operator_id,
            "review_id":self.review_id,
            "request":asdict(self.request),
            "expires_at_ms":int(self._deadline.timestamp()*1000),
            "scope":"unsigned-preview-then-short-signed-webauthn",
            "execution_authority":False,
        }

    def _burn_pending(self,now):
        try:
            self.policy.approve(
                self.review_id,shown_request=self.request,
                acknowledged=False,now=now,
            )
        except PolicyDenied:
            pass

    def challenge(self, *, session: object, acknowledged: object, now: datetime) -> dict:
        instant=_utc(now)
        if not self._session_valid(session,instant) or self._signing_started:
            raise PolicyDenied("invalid or previously used preview session")
        if type(acknowledged) is not bool or not acknowledged:
            raise PolicyDenied("explicit reviewed-action acknowledgment required")
        self._signing_started=True  # one attempt, even if signer fails
        issued=int(instant.timestamp()*1000)
        expires=min(issued+30_000,int(self._deadline.timestamp()*1000))
        if expires-issued < 1000:
            self._burn_pending(instant)
            raise PolicyDenied("not enough time for signed approval")
        body={
            "schema":SCHEMA,"purpose":PURPOSE,
            "operator_id":self.operator_id,"kid":self.kid,
            "review_id":self.review_id,"request":asdict(self.request),
            "issued_at_ms":issued,"expires_at_ms":expires,
            "nonce":secrets.token_hex(16),
        }
        try:
            # Never ask an external signer to sign an already revoked,
            # expired, spent, replaced, or already-challenged request.
            # The R9 transaction independently rechecks after signing too.
            def current(conn):
                row=conn.execute("""
                    SELECT r.request_json,r.review_until_ms,r.presence_challenge,
                           o.revoked,k.revoked,c.revoked
                    FROM requests r JOIN owners o
                      ON o.issuer=r.issuer AND o.subject=r.subject
                    JOIN operator_keys k
                      ON k.operator_id=? AND k.kid=?
                    JOIN operator_credentials c
                      ON c.credential_id=? AND c.operator_id=?
                    WHERE r.review_id=? AND r.state='pending'
                """,(
                    self.operator_id,self.kid,self.credential_id,
                    self.operator_id,self.review_id,
                )).fetchone()
                if (
                    row is None or any(flag != 0 for flag in (row[3],row[4],row[5]))
                    or row[2] is not None
                    or row[1] <= issued
                    or json.loads(row[0]) != asdict(self.request)
                ):
                    raise PolicyDenied("staged request or operator trust changed")
            self.policy._transaction(current)
            sig=self.signer.sign(
                canonical_message(body),operator_id=self.operator_id,kid=self.kid
            )
            if type(sig) is not bytes or len(sig)!=64:
                raise PolicyDenied("signer returned invalid Ed25519 signature")
            receipt={**body,"signature":_b64url(sig)}
            # Pinned operator public key is retrieved again from trusted DB
            # to prevent accepting a signer with an injected public key.
            def check(conn):
                row=conn.execute("""
                    SELECT public_key,revoked FROM operator_keys
                    WHERE operator_id=? AND kid=?
                """,(self.operator_id,self.kid)).fetchone()
                if row is None or row[1]:
                    raise PolicyDenied("operator signer revoked")
                ticket=ReviewTicket(
                    review_id=self.review_id,request=self.request,
                    expires_at=self._deadline,
                )
                verified_receipt_expiry(
                    receipt,ticket=ticket,public_key=bytes(row[0]),now=instant,
                )
            self.policy._transaction(check)
            challenge=self.policy.begin_operator_stepup(
                receipt,credential_id=self.credential_id,now=instant,
            )
        except Exception as exc:
            self._spent=True
            self._burn_pending(instant)
            raise PolicyDenied("independent signing or stepup unavailable") from exc
        self._receipt=receipt
        self._challenge_issued=True
        remaining=max(1,min(
            expires-int(instant.timestamp()*1000),30_000
        ))
        return {
            "challenge":_b64url(challenge),
            "rpId":RP_ID,
            "timeout":remaining,
            "allowCredentials":[{
                "type":"public-key","id":_b64url(self.credential_id)
            }],
            "userVerification":"required",
        }

    def complete(self, *, session: object, assertion: object, now: datetime) -> dict:
        instant=_utc(now)
        if not self._session_valid(session,instant):
            raise PolicyDenied("preview session invalid")
        self._spent=True
        if not self._challenge_issued or self._receipt is None or type(assertion) is not dict:
            raise PolicyDenied("signed WebAuthn challenge missing")
        if not self.policy.approve_signed_with_stepup(
            self._receipt,assertion,now=instant,
        ):
            raise PolicyDenied("signed and user-verified approval denied")
        return {
            "review_recorded":True,
            "signed_review_verified":True,
            "webauthn_uv_verified":True,
            "execution_authority":False,
            "resource_read":False,
            "still_requires":"fresh PhiID token and verified ANC/PhiShield assessment",
        }

    def decline(self, *, session: object, now: datetime) -> dict:
        instant=_utc(now)
        if not self._session_valid(session,instant):
            raise PolicyDenied("preview session invalid")
        self._spent=True
        if self._challenge_issued and self._receipt is not None:
            self.policy.approve_signed_with_stepup(self._receipt,{},now=instant)
        else:
            self._burn_pending(instant)
        return {
            "review_recorded":False,"declined":True,
            "execution_authority":False,
        }


def _read_private_review_id(path: str) -> str:
    source=Path(path)
    if not source.is_absolute() or source.suffix!=".json":
        raise PolicyDenied("private absolute staged review file required")
    try:
        _private_path(source.parent,is_dir=True)
        _private_path(source,is_dir=False)
        fd=os.open(source,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
        with os.fdopen(fd,"rb") as file:
            meta=os.fstat(file.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077:
                raise PolicyDenied("review selector permissions invalid")
            raw=file.read(513)
        if len(raw)>512:
            raise PolicyDenied("review selector too large")
        obj=json.loads(raw.decode("utf-8"),object_pairs_hook=_reject_duplicates)
        if type(obj) is not dict or set(obj)!={"review_id"}:
            raise PolicyDenied("exact review selector required")
        review_id=obj["review_id"]
        if type(review_id) is not str or not 20<=len(review_id)<=128:
            raise PolicyDenied("invalid review selector")
        return review_id
    except (OSError,ValueError,UnicodeError) as exc:
        raise PolicyDenied("private review selector unreadable") from exc


def main(argv=None):
    parser=argparse.ArgumentParser(
        description="R12 locally paired preview then independent late R7 signature"
    )
    parser.add_argument("--db",required=True,help="existing private POSIX R9 SQLite DB")
    parser.add_argument("--review-file",required=True,help="existing 0600 private JSON containing only review_id")
    parser.add_argument("--operator",required=True,help="trusted existing signer operator ID")
    parser.add_argument("--kid",required=True,help="trusted existing Ed25519 signer key ID")
    parser.add_argument("--signer-socket",required=True,help="private Unix signer socket, not a key")
    args=parser.parse_args(argv)
    if (
        os.environ.get("PHICLOUD_DEFERRED_REVIEW_DEV")!="1"
        or os.environ.get("NODE_ENV")=="production"
        or os.environ.get("PHICLOUD_ENV")=="production"
        or not sys.stdin.isatty() or not sys.stdout.isatty()
    ):
        print("DENY: trusted local TTY and explicit opt-in required",file=sys.stderr)
        return 2
    db=Path(args.db)
    if not db.is_absolute() or not db.is_file() or db.is_symlink():
        print("DENY: private existing database required",file=sys.stderr)
        return 2
    try:
        policy=DurableOwnerConsentPolicy(db)
        review_id=_read_private_review_id(args.review_file)
        signer=UnixOperatorSigner(args.signer_socket)
        code=secrets.token_urlsafe(24)
        controller=DeferredOperatorApproval(
            policy=policy,review_id=review_id,operator_id=args.operator,
            kid=args.kid,signer=signer,pairing_code=code,
        )
        with OneShotServer(
            ("127.0.0.1",8769),
            handler_factory(controller,mode="deferred"),
        ) as server:
            print("PhiCloud R12 PRIVATE operator preview (no execution)")
            print("Open http://localhost:8769 on this machine")
            print("One-use preview pairing code (do not share): "+code)
            print("Signing occurs ONLY after exact-action preview + acknowledgment")
            print("Press Ctrl+C to stop this one-shot preview")
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
        return 0
    except (OSError,PolicyDenied,ValueError):
        print("DENY: deferred operator preview unavailable",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
