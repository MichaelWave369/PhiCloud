"""R6 opt-in SQLite-backed local synthetic-self review ledger.

Persistence makes review/revocation survive restarts, NOT an authenticated
human approval or production authorization service. No HTTP API is exposed.
Only trusted code may invoke its methods. A private operator-owned directory
is required. Windows ACLs, malicious filesystem races and host compromise
are NOT covered by this local POSIX development implementation.
"""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
import stat
import threading
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .authz import ISSUER
from .local_consent import (
    ALLOWED_ACTION, ALLOWED_RESOURCE, ALLOWED_SCOPE,
    MAX_APPROVAL_SECONDS, MAX_REVIEW_SECONDS,
    PolicyDenied, ReviewTicket,
)
from .shield_policy import AuthorityEvidence, ConsentEvidence, EffectRequest, _utc
from .local_consent import LocalOwnerConsentPolicy
from .operator_approval import verified_receipt_expiry
from .webauthn_presence import (
    RP_ID, ORIGIN, exact_receipt_digest, verify_stepup_assertion,
)

_VERSION = 3


def _request_json(req: EffectRequest) -> str:
    return json.dumps(asdict(req), sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _milliseconds(value: datetime) -> int:
    return int(_utc(value).timestamp() * 1000)


def _private_path(path: Path, *, is_dir: bool) -> None:
    info = path.lstat()  # never silently accept a symlink
    if is_dir and not stat.S_ISDIR(info.st_mode):
        raise ValueError("private policy parent must be a real directory")
    if not is_dir and not stat.S_ISREG(info.st_mode):
        raise ValueError("policy database must be a regular file")
    if os.name == "posix":
        if (info.st_mode & 0o077) != 0 or info.st_uid != os.getuid():
            raise ValueError("policy storage must be operator-owned and private")


class DurableOwnerConsentPolicy:
    """Multi-process atomic, persistent reference state for ONE synthetic resource.

    Does not inherit from the in-memory policy to avoid combining sources of
    authority. sqlite3 BEGIN IMMEDIATE serializes all stage/approve/consume
    and owner-revocation transitions across processes.
    """

    def __init__(self, db_path: str | Path, *, capacity: int = 1024) -> None:
        if type(capacity) is not int or not 1 <= capacity <= 100_000:
            raise ValueError("invalid ledger capacity")
        if os.name != "posix":
            raise ValueError("POSIX private-directory checks required; Windows ACL review pending")
        path = Path(db_path)
        if not path.is_absolute() or path.suffix not in {".sqlite3", ".db"}:
            raise ValueError("absolute SQLite .db or .sqlite3 path required")
        _private_path(path.parent, is_dir=True)
        if path.exists() or path.is_symlink():
            _private_path(path, is_dir=False)
        else:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                descriptor = os.open(path, flags, 0o600)
                os.close(descriptor)
            except FileExistsError:
                _private_path(path, is_dir=False)
        _private_path(path, is_dir=False)
        self._path = path
        self._capacity = capacity
        self._lock = threading.RLock()
        self._initialize()

    def _open(self) -> sqlite3.Connection:
        # The file and directory must remain private; detect moved/replaced
        # paths at each request. This is NOT a malicious-actor-safe openat.
        _private_path(self._path.parent, is_dir=True)
        _private_path(self._path, is_dir=False)
        connection = sqlite3.connect(str(self._path), timeout=3, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=3000")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("PRAGMA journal_mode=DELETE")
        return connection

    def _transaction(self, callback):
        with self._lock:
            try:
                conn = self._open()
                try:
                    conn.execute("BEGIN IMMEDIATE")
                    try:
                        result = callback(conn)
                    except BaseException:
                        if conn.in_transaction:
                            conn.execute("ROLLBACK")
                        raise
                    conn.execute("COMMIT")
                    return result
                finally:
                    conn.close()
            except (sqlite3.Error, OSError, ValueError) as exc:
                # Permission or file-type drift must deny, not raise through
                # the identity-to-PhiShield reference policy as an internal error.
                raise PolicyDenied("local policy storage unavailable") from exc

    def _initialize(self) -> None:
        def create(conn):
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1, 2, _VERSION):
                raise PolicyDenied("unrecognized policy schema; fail closed")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS owners(
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
                    PRIMARY KEY(issuer,subject)
                )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS requests(
                    review_id TEXT NOT NULL UNIQUE,
                    issuer TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('pending','approved','spent')),
                    review_until_ms INTEGER NOT NULL,
                    approval_until_ms INTEGER,
                    PRIMARY KEY(issuer,subject,request_id),
                    FOREIGN KEY(issuer,subject) REFERENCES owners(issuer,subject)
                )""")

            # R7 migrates existing R6 databases without losing owners,
            # previously approved entries, or irrevocable used ID tombstones.
            existing = {
                row[1] for row in conn.execute("PRAGMA table_info(requests)")
            }
            for column, declaration in (
                ("signer_id", "TEXT"),
                ("signer_kid", "TEXT"),
                ("signed_receipt", "TEXT"),
                ("presence_challenge", "BLOB"),
                ("presence_digest", "BLOB"),
                ("presence_credential_id", "BLOB"),
                ("presence_until_ms", "INTEGER"),
                ("presence_verified", "INTEGER NOT NULL DEFAULT 0"),
            ):
                if column not in existing:
                    conn.execute(
                        f"ALTER TABLE requests ADD COLUMN {column} {declaration}"
                    )
            conn.execute("""
                CREATE TABLE IF NOT EXISTS operator_keys(
                    operator_id TEXT NOT NULL,
                    kid TEXT NOT NULL,
                    public_key BLOB NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
                    PRIMARY KEY(operator_id,kid)
                )""")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS operator_credentials(
                    operator_id TEXT NOT NULL,
                    credential_id BLOB NOT NULL PRIMARY KEY,
                    public_key BLOB NOT NULL,
                    sign_count INTEGER NOT NULL DEFAULT 0,
                    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
                    rp_id TEXT NOT NULL,
                    origin TEXT NOT NULL
                )""")
            conn.execute(f"PRAGMA user_version={_VERSION}")
        self._transaction(create)

    @staticmethod
    def _allow(req: object) -> bool:
        return (
            LocalOwnerConsentPolicy._operation_allowed(req)
            and req.subject_issuer == ISSUER
            and req.action == ALLOWED_ACTION
            and req.resource == ALLOWED_RESOURCE
            and req.scope == ALLOWED_SCOPE
        )

    def register_synthetic_self(self, request: EffectRequest) -> None:
        if not self._allow(request):
            raise PolicyDenied("unsupported synthetic owner or operation")
        def register(conn):
            owner = (request.subject_issuer, request.subject_id)
            row = conn.execute(
                "SELECT revoked FROM owners WHERE issuer=? AND subject=?", owner
            ).fetchone()
            if row is not None:
                if row[0]:
                    raise PolicyDenied("owner has been revoked; cannot auto-reregister")
                return
            used = conn.execute("SELECT count(*) FROM owners").fetchone()[0]
            if used >= self._capacity:
                raise PolicyDenied("owner capacity exceeded")
            conn.execute(
                "INSERT INTO owners(issuer,subject,revoked) VALUES(?,?,0)", owner
            )
        self._transaction(register)

    def stage(self, request: EffectRequest, *, now: datetime) -> ReviewTicket:
        """Existing R6 one-minute review; unchanged for legacy callers."""
        return self._stage_bounded(request, now=now, seconds=MAX_REVIEW_SECONDS)

    def stage_operator_preview(
        self, request: EffectRequest, *, now: datetime
    ) -> ReviewTicket:
        """R12 trusted-only preview, up to five minutes before late signing.

        This does not extend R7 signature validity, an approved receipt,
        credential validity, or actual permission. Never expose as HTTP.
        """
        return self._stage_bounded(request, now=now, seconds=300)

    def _stage_bounded(
        self, request: EffectRequest, *, now: datetime, seconds: int
    ) -> ReviewTicket:
        if type(seconds) is not int or seconds not in (MAX_REVIEW_SECONDS, 300):
            raise PolicyDenied("unsupported local review lifetime")
        instant = _utc(now)
        if not self._allow(request):
            raise PolicyDenied("unsupported action")
        expires = instant + timedelta(seconds=seconds)
        review = ReviewTicket(
            review_id=secrets.token_urlsafe(24),
            request=request,
            expires_at=expires,
        )
        def stage_tx(conn):
            row = conn.execute(
                "SELECT revoked FROM owners WHERE issuer=? AND subject=?",
                (request.subject_issuer,request.subject_id),
            ).fetchone()
            if row is None or row[0] != 0:
                raise PolicyDenied("unregistered or revoked synthetic owner")
            used = conn.execute("SELECT count(*) FROM requests").fetchone()[0]
            if used >= self._capacity:
                raise PolicyDenied("request ledger full, no expired ID recycling")
            try:
                conn.execute("""
                    INSERT INTO requests(review_id,issuer,subject,request_id,request_json,
                                         state,review_until_ms,approval_until_ms)
                    VALUES(?,?,?,?,?,'pending',?,NULL)
                """, (
                    review.review_id, request.subject_issuer, request.subject_id,
                    request.request_id, _request_json(request), _milliseconds(expires),
                ))
            except sqlite3.IntegrityError as exc:
                raise PolicyDenied("request ID or review nonce already used") from exc
            return review
        return self._transaction(stage_tx)

    def approve(
        self,
        review_id: str,
        *,
        shown_request: EffectRequest,
        acknowledged: bool,
        now: datetime,
    ) -> bool:
        instant = _utc(now)
        if type(review_id) is not str or type(acknowledged) is not bool:
            return False
        def approve_tx(conn):
            row = conn.execute("""
                SELECT r.issuer,r.subject,r.request_json,r.review_until_ms,o.revoked
                FROM requests r JOIN owners o
                  ON (r.issuer=o.issuer AND r.subject=o.subject)
                WHERE r.review_id=? AND r.state='pending'
                  AND r.presence_challenge IS NULL
            """, (review_id,)).fetchone()
            if row is None:
                return False
            # Burn the review even if acknowledgment, binding or time fails.
            conn.execute(
                "UPDATE requests SET state='spent' WHERE review_id=?", (review_id,)
            )
            issuer,subject,request_json,review_until,revoked = row
            now_ms = _milliseconds(instant)
            if (
                not acknowledged or revoked
                or now_ms >= review_until
                or not self._allow(shown_request)
                or shown_request.subject_issuer != issuer
                or shown_request.subject_id != subject
                or _request_json(shown_request) != request_json
            ):
                return False
            deadline = min(
                review_until, _milliseconds(instant + timedelta(seconds=MAX_APPROVAL_SECONDS))
            )
            conn.execute(
                "UPDATE requests SET state='approved',approval_until_ms=? WHERE review_id=?",
                (deadline,review_id),
            )
            return True
        return self._transaction(approve_tx)

    def register_operator_key(
        self, *, operator_id: str, kid: str, public_key: bytes
    ) -> None:
        """Trusted provisioning of a public verifier key; no private key here.

        Key IDs are immutable, including after revocation. Rotation means
        enrolling a new kid and revoking the old kid through trusted code.
        """
        from .operator_approval import _IDENTIFIER, Ed25519PublicKey
        if (
            Ed25519PublicKey is None
            or type(operator_id) is not str or not _IDENTIFIER.fullmatch(operator_id)
            or type(kid) is not str or not _IDENTIFIER.fullmatch(kid)
            or type(public_key) is not bytes or len(public_key) != 32
        ):
            raise PolicyDenied("invalid operator key enrollment")
        def register_key(conn):
            row = conn.execute(
                "SELECT 1 FROM operator_keys WHERE operator_id=? AND kid=?",
                (operator_id,kid),
            ).fetchone()
            if row is not None:
                raise PolicyDenied("operator key ID already enrolled or revoked")
            # An old compromised public key must not be re-enrolled under
            # a new kid to bypass its durable revocation tombstone.
            same_public = conn.execute(
                "SELECT 1 FROM operator_keys WHERE public_key=?", (public_key,)
            ).fetchone()
            if same_public is not None:
                raise PolicyDenied("operator public key already enrolled under another ID")
            if conn.execute("SELECT count(*) FROM operator_keys").fetchone()[0] >= self._capacity:
                raise PolicyDenied("operator key registry at capacity")
            conn.execute(
                "INSERT INTO operator_keys(operator_id,kid,public_key,revoked) VALUES(?,?,?,0)",
                (operator_id,kid,public_key),
            )
        self._transaction(register_key)

    def revoke_operator_key(self, *, operator_id: str, kid: str) -> None:
        """Persist a public-key tombstone and atomically burn unspent approvals."""
        from .operator_approval import _IDENTIFIER
        if (
            type(operator_id) is not str or not _IDENTIFIER.fullmatch(operator_id)
            or type(kid) is not str or not _IDENTIFIER.fullmatch(kid)
        ):
            raise PolicyDenied("invalid operator key revocation target")
        def revoke_key(conn):
            changed = conn.execute(
                "UPDATE operator_keys SET revoked=1 WHERE operator_id=? AND kid=?",
                (operator_id,kid),
            )
            if changed.rowcount != 1:
                raise PolicyDenied("operator key not enrolled")
            conn.execute("""
                UPDATE requests SET state='spent', approval_until_ms=NULL
                WHERE signer_id=? AND signer_kid=? AND state='approved'
            """, (operator_id,kid))
        self._transaction(revoke_key)

    def approve_signed(self, receipt: object, *, now: datetime) -> bool:
        """Verify exact Ed25519 receipt against trusted operator public key.

        A malformed or refused review burns the staged ticket. The signature
        is verified again at consumption. No client-supplied keys are trusted.
        """
        instant = _utc(now)
        if type(receipt) is not dict:
            return False
        operator_id, kid, review_id = (
            receipt.get("operator_id"), receipt.get("kid"), receipt.get("review_id")
        )
        if any(type(v) is not str for v in (operator_id,kid,review_id)):
            return False
        def check_and_approve(conn):
            row = conn.execute("""
                SELECT r.issuer,r.subject,r.request_json,r.review_until_ms,
                       o.revoked,k.public_key,k.revoked
                FROM requests r JOIN owners o
                  ON r.issuer=o.issuer AND r.subject=o.subject
                LEFT JOIN operator_keys k
                  ON k.operator_id=? AND k.kid=?
                WHERE r.review_id=? AND r.state='pending'
                  AND r.presence_challenge IS NULL
            """, (operator_id,kid,review_id)).fetchone()
            if row is None:
                return False
            conn.execute(
                "UPDATE requests SET state='spent' WHERE review_id=?",
                (review_id,),
            )
            issuer,subject,saved,until,owner_revoked,key,signer_revoked = row
            if owner_revoked or signer_revoked != 0 or key is None:
                return False
            try:
                request = EffectRequest(**json.loads(saved))
                ticket = ReviewTicket(
                    review_id=review_id,
                    request=request,
                    expires_at=datetime.fromtimestamp(until / 1000,timezone.utc),
                )
                expiry = verified_receipt_expiry(
                    receipt,ticket=ticket,public_key=bytes(key),now=instant,
                )
            except (PolicyDenied,ValueError,TypeError,OverflowError,KeyError):
                return False
            if not self._allow(request) or request.subject_issuer != issuer or request.subject_id != subject:
                return False
            deadline = min(until,expiry)
            conn.execute("""
                UPDATE requests
                SET state='approved',approval_until_ms=?,
                    signer_id=?,signer_kid=?,signed_receipt=?
                WHERE review_id=?
            """, (
                deadline,operator_id,kid,
                json.dumps(receipt,sort_keys=True,separators=(",",":"),ensure_ascii=True),
                review_id,
            ))
            return True
        return self._transaction(check_and_approve)

    def register_operator_credential(
        self, *, operator_id: str, credential_id: bytes, public_key: bytes,
        sign_count: int = 0
    ) -> None:
        """Trusted, out-of-band VERIFIED WebAuthn registration result only.

        Caller MUST independently verify a real RP registration ceremony and
        bind the credential to the authenticated operator. This is not a
        browser-facing enrollment endpoint or evidence of correct enrollment.
        Credential IDs are immutable, even after revocation.
        """
        from .operator_approval import _IDENTIFIER
        if (
            type(operator_id) is not str or not _IDENTIFIER.fullmatch(operator_id)
            or type(credential_id) is not bytes or not 16 <= len(credential_id) <= 128
            or type(public_key) is not bytes or not 32 <= len(public_key) <= 4096
            or type(sign_count) is not int or not 0 <= sign_count < 2**32
        ):
            raise PolicyDenied("invalid trusted WebAuthn enrollment")
        def register(conn):
            active = conn.execute(
                "SELECT 1 FROM operator_keys WHERE operator_id=? AND revoked=0",
                (operator_id,),
            ).fetchone()
            if active is None:
                raise PolicyDenied("active signing operator required")
            if conn.execute(
                "SELECT count(*) FROM operator_credentials"
            ).fetchone()[0] >= self._capacity:
                raise PolicyDenied("operator credential capacity reached")
            if conn.execute(
                "SELECT 1 FROM operator_credentials WHERE credential_id=?",
                (credential_id,),
            ).fetchone():
                raise PolicyDenied("WebAuthn credential already enrolled or revoked")
            conn.execute("""
                INSERT INTO operator_credentials(
                    operator_id,credential_id,public_key,sign_count,
                    revoked,rp_id,origin
                ) VALUES(?,?,?,?,0,?,?)
            """, (operator_id,credential_id,public_key,sign_count,RP_ID,ORIGIN))
        self._transaction(register)

    def revoke_operator_credential(self, *, credential_id: bytes) -> None:
        """Atomic revocation tombstone; never re-enroll this credential ID."""
        if type(credential_id) is not bytes or not 16 <= len(credential_id) <= 128:
            raise PolicyDenied("invalid credential revocation target")
        def revoke(conn):
            changed = conn.execute(
                "UPDATE operator_credentials SET revoked=1 WHERE credential_id=?",
                (credential_id,),
            )
            if changed.rowcount != 1:
                raise PolicyDenied("credential not registered")
            conn.execute("""
                UPDATE requests SET state='spent',approval_until_ms=NULL
                WHERE presence_credential_id=? AND state IN ('pending','approved')
            """, (credential_id,))
        self._transaction(revoke)

    def begin_operator_stepup(
        self,
        receipt: object,
        *,
        credential_id: bytes,
        now: datetime,
    ) -> bytes:
        """Issue a one-use random challenge bound to the full R7 signed receipt.

        The resulting challenge MUST be presented to the authenticator with
        userVerification='required' on the fixed RP and origin. The browser
        must separately display the exact request and warn about its scope.
        """
        instant = _utc(now)
        if type(receipt) is not dict or type(credential_id) is not bytes:
            raise PolicyDenied("signed receipt and enrolled credential required")
        try:
            digest = exact_receipt_digest(receipt)
        except (PolicyDenied, UnicodeError, ValueError):
            raise PolicyDenied("invalid signed review digest")
        review_id, operator_id, kid = (
            receipt.get("review_id"), receipt.get("operator_id"), receipt.get("kid")
        )
        if any(type(v) is not str for v in (review_id,operator_id,kid)):
            raise PolicyDenied("invalid signed review selector")
        def issue(conn):
            row = conn.execute("""
                SELECT r.issuer,r.subject,r.request_json,r.review_until_ms,
                       r.presence_challenge,o.revoked,
                       k.public_key,k.revoked,
                       c.revoked,c.rp_id,c.origin
                FROM requests r JOIN owners o ON
                  r.issuer=o.issuer AND r.subject=o.subject
                LEFT JOIN operator_keys k ON k.operator_id=? AND k.kid=?
                LEFT JOIN operator_credentials c ON c.credential_id=?
                AND c.operator_id=?
                WHERE r.review_id=? AND r.state='pending'
            """, (operator_id,kid,credential_id,operator_id,review_id)).fetchone()
            if row is None:
                raise PolicyDenied("pending operator review missing")
            (issuer,subject,request_json,review_until,existing,owner_revoked,
             key,key_revoked,cred_revoked,rp_id,origin) = row
            if (
                owner_revoked or existing is not None or key is None
                or key_revoked != 0 or cred_revoked != 0
                or rp_id != RP_ID or origin != ORIGIN
            ):
                raise PolicyDenied("untrusted operator or already-issued stepup")
            try:
                req = EffectRequest(**json.loads(request_json))
                ticket = ReviewTicket(
                    review_id=review_id,request=req,
                    expires_at=datetime.fromtimestamp(review_until/1000,timezone.utc),
                )
                expiry=verified_receipt_expiry(
                    receipt,ticket=ticket,public_key=bytes(key),now=instant,
                )
            except (PolicyDenied,ValueError,TypeError,KeyError,OverflowError):
                raise PolicyDenied("signed review not valid for this challenge")
            if not self._allow(req) or req.subject_issuer != issuer or req.subject_id != subject:
                raise PolicyDenied("unsupported or mismatched operator action")
            deadline=min(
                review_until, expiry,
                int((instant+timedelta(seconds=30)).timestamp()*1000),
            )
            if int(instant.timestamp()*1000) >= deadline:
                raise PolicyDenied("stepup challenge already expired")
            challenge=secrets.token_bytes(32)
            conn.execute("""
                UPDATE requests SET presence_challenge=?,presence_digest=?,
                    presence_credential_id=?,presence_until_ms=?
                WHERE review_id=? AND state='pending'
            """, (challenge,digest,credential_id,deadline,review_id))
            return challenge
        return self._transaction(issue)

    def approve_signed_with_stepup(
        self,
        receipt: object,
        assertion: object,
        *,
        now: datetime,
    ) -> bool:
        """One atomic signed-review + WebAuthn UV stepup, or burn review.

        The challenge must have been issued from begin_operator_stepup().
        Credentials, counters and allowed origin/RP all come from trusted
        SQLite enrollment. No public endpoint, browser-provided keys or
        fake user-presence booleans are accepted.
        """
        instant=_utc(now)
        if type(receipt) is not dict or type(assertion) is not dict:
            return False
        review_id,operator_id,kid=(
            receipt.get("review_id"),receipt.get("operator_id"),receipt.get("kid")
        )
        if any(type(v) is not str for v in (review_id,operator_id,kid)):
            return False
        def verify_and_approve(conn):
            row=conn.execute("""
                SELECT r.issuer,r.subject,r.request_json,r.review_until_ms,
                    r.presence_challenge,r.presence_digest,
                    r.presence_credential_id,r.presence_until_ms,
                    o.revoked,k.public_key,k.revoked,
                    c.public_key,c.sign_count,c.revoked,c.operator_id,c.rp_id,c.origin
                FROM requests r JOIN owners o
                   ON r.issuer=o.issuer AND r.subject=o.subject
                LEFT JOIN operator_keys k
                   ON k.operator_id=? AND k.kid=?
                LEFT JOIN operator_credentials c
                   ON c.credential_id=r.presence_credential_id
                WHERE r.review_id=? AND r.state='pending'
            """, (operator_id,kid,review_id)).fetchone()
            if row is None:
                return False
            # Denied/forged attempts burn this one-use review even on failure.
            conn.execute("UPDATE requests SET state='spent' WHERE review_id=?",(review_id,))
            (issuer,subject,saved,review_until,challenge,digest,
             credential_id,stepup_until,owner_revoked,key,key_revoked,
             cred_public,counter,cred_revoked,cred_operator,rp_id,origin)=row
            now_ms=int(instant.timestamp()*1000)
            if (
                owner_revoked or key is None or key_revoked != 0
                or cred_public is None or cred_revoked != 0
                or cred_operator != operator_id or rp_id != RP_ID or origin != ORIGIN
                or type(challenge) is not bytes or len(challenge) != 32
                or type(stepup_until) is not int or now_ms >= stepup_until
            ):
                return False
            try:
                if exact_receipt_digest(receipt) != bytes(digest):
                    return False
                req=EffectRequest(**json.loads(saved))
                ticket=ReviewTicket(
                    review_id=review_id,request=req,
                    expires_at=datetime.fromtimestamp(review_until/1000,timezone.utc),
                )
                expiry=verified_receipt_expiry(
                    receipt,ticket=ticket,public_key=bytes(key),now=instant,
                )
                new_count=verify_stepup_assertion(
                    assertion=assertion,challenge=bytes(challenge),
                    credential_id=bytes(credential_id),
                    credential_public_key=bytes(cred_public),
                    sign_count=counter,
                )
            except (PolicyDenied,ValueError,TypeError,KeyError,OverflowError,UnicodeError):
                return False
            if not self._allow(req) or req.subject_issuer != issuer or req.subject_id != subject:
                return False
            deadline=min(stepup_until,expiry)
            conn.execute(
                "UPDATE operator_credentials SET sign_count=? WHERE credential_id=?",
                (new_count,credential_id),
            )
            conn.execute("""
                UPDATE requests SET state='approved',approval_until_ms=?,
                    signer_id=?,signer_kid=?,signed_receipt=?,
                    presence_verified=1,presence_challenge=NULL
                WHERE review_id=?
            """,(
                deadline,operator_id,kid,
                json.dumps(receipt,sort_keys=True,separators=(",",":"),ensure_ascii=True),
                review_id,
            ))
            return True
        return self._transaction(verify_and_approve)

    def revoke_owner(self, *, issuer: str, sub: str) -> None:
        """Persist a tombstone. Fresh sign-in cannot silently reenable owner."""
        if type(issuer) is not str or type(sub) is not str or not issuer or not sub:
            raise PolicyDenied("invalid revocation target")
        def revoke_tx(conn):
            existing = conn.execute(
                "SELECT 1 FROM owners WHERE issuer=? AND subject=?", (issuer,sub)
            ).fetchone()
            if existing is None and conn.execute(
                "SELECT count(*) FROM owners"
            ).fetchone()[0] >= self._capacity:
                raise PolicyDenied("revocation tombstone capacity exceeded")
            conn.execute("""
                INSERT INTO owners(issuer,subject,revoked)
                VALUES(?,?,1)
                ON CONFLICT(issuer,subject) DO UPDATE SET revoked=1
            """, (issuer,sub))
            conn.execute("""
                UPDATE requests SET state='spent',approval_until_ms=NULL
                WHERE issuer=? AND subject=? AND state!='spent'
            """, (issuer,sub))
        self._transaction(revoke_tx)

    def consume(
        self, request: EffectRequest, *, now: datetime,
        require_signed: bool = False, require_presence: bool = False
    ) -> tuple[AuthorityEvidence, ConsentEvidence]:
        """Spend exactly one request; optionally REQUIRE a trusted signed review.

        Every signed review is verified again on consumption, even for R6
        callers that do not opt into require_signed. A revoked key can never
        authorize after key rotation or process restart.
        """
        instant = _utc(now)
        if (
            type(require_signed) is not bool or type(require_presence) is not bool
            or not self._allow(request)
        ):
            raise PolicyDenied("unsupported operation or review mode")
        def consume_tx(conn):
            row = conn.execute("""
                SELECT r.review_id,r.request_json,r.state,r.review_until_ms,
                       r.approval_until_ms,o.revoked,r.signer_id,r.signer_kid,
                       r.signed_receipt,k.public_key,k.revoked,
                       r.presence_verified,r.presence_until_ms,
                       r.presence_credential_id,c.revoked,c.operator_id,
                       c.rp_id,c.origin
                FROM requests r JOIN owners o
                  ON r.issuer=o.issuer AND r.subject=o.subject
                LEFT JOIN operator_keys k
                  ON r.signer_id=k.operator_id AND r.signer_kid=k.kid
                LEFT JOIN operator_credentials c
                  ON r.presence_credential_id=c.credential_id
                WHERE r.issuer=? AND r.subject=? AND r.request_id=?
            """, (request.subject_issuer,request.subject_id,request.request_id)).fetchone()
            if row is None:
                raise PolicyDenied("missing owner approval")
            (review_id,saved,state,review_until,deadline,owner_revoked,
             signer_id,kid,receipt_json,key,key_revoked,
             present,presence_until,credential_id,cred_revoked,
             cred_operator,rp_id,origin) = row
            if owner_revoked or state != "approved" or deadline is None:
                raise PolicyDenied("approval absent, revoked or already consumed")
            # Consume BEFORE independently rechecking the signature so
            # any invalid or expired attempt commits an irrevocable tombstone.
            conn.execute("""
                UPDATE requests SET state='spent',approval_until_ms=NULL
                WHERE issuer=? AND subject=? AND request_id=?
            """, (request.subject_issuer,request.subject_id,request.request_id))
            if saved != _request_json(request) or _milliseconds(instant) >= deadline:
                return _SpentApproval("mismatched or expired approval")
            if require_signed and signer_id is None:
                return _SpentApproval("independently signed review required")
            # A UV-verified review cannot be downgraded through an older
            # signed-only call after its authenticator credential is revoked.
            if require_presence or present == 1:
                if (
                    signer_id is None or present != 1
                    or type(presence_until) is not int
                    or _milliseconds(instant) >= presence_until
                    or type(credential_id) is not bytes
                    or cred_revoked != 0 or cred_operator != signer_id
                    or rp_id != RP_ID or origin != ORIGIN
                ):
                    return _SpentApproval("unrevoked WebAuthn user-verification stepup required")
            if signer_id is not None:
                if (
                    type(kid) is not str or key is None or key_revoked != 0
                    or type(receipt_json) is not str
                ):
                    return _SpentApproval("operator signer unavailable or revoked")
                try:
                    ticket = ReviewTicket(
                        review_id=review_id,request=request,
                        expires_at=datetime.fromtimestamp(review_until/1000,timezone.utc),
                    )
                    verified_receipt_expiry(
                        json.loads(receipt_json),ticket=ticket,
                        public_key=bytes(key),now=instant,
                    )
                except (PolicyDenied,ValueError,TypeError,KeyError,OverflowError):
                    return _SpentApproval("stored signer evidence unverifiable")
            elif kid is not None or receipt_json is not None:
                return _SpentApproval("partial operator signature metadata")
            until = datetime.fromtimestamp(deadline / 1000, tz=timezone.utc).isoformat()
            return (
                AuthorityEvidence(**asdict(request),not_after=until),
                ConsentEvidence(**asdict(request),not_after=until),
            )
        result = self._transaction(consume_tx)
        if isinstance(result, _SpentApproval):
            raise PolicyDenied(str(result))
        return result


class _SpentApproval:
    """Sentinel for returning a denial while committing the spent state."""

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def __str__(self) -> str:
        return self.reason
