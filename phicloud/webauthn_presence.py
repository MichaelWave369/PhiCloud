"""R9 WebAuthn verification boundary for an exact R7 signed review.

This is NOT a credential enrollment ceremony or a browser endpoint. Credential
public keys have to be registered through a *separate trusted* registration
process; an arbitrary credential supplied by the client must never be enrolled.
"""
from __future__ import annotations

import hashlib
import json

from .local_consent import PolicyDenied
from .operator_approval import canonical_message

try:
    from webauthn import verify_authentication_response
except ImportError:
    verify_authentication_response = None

RP_ID = "localhost"
ORIGIN = "http://localhost:8769"  # fixed dev secure-context loopback origin
MAX_ASSERTION_BYTES = 16_384


def exact_receipt_digest(receipt: object) -> bytes:
    """Bind challenge to ALL receipt bytes including signer signature.

    No caller-provided digest, hash, purpose, or request scope can stand in
    for the actual receipt. Strict R7 body schema is checked first.
    """
    if type(receipt) is not dict or type(receipt.get("signature")) is not str:
        raise PolicyDenied("signed review receipt required")
    body = {name: value for name, value in receipt.items() if name != "signature"}
    signed = canonical_message(body)
    signature = receipt["signature"]
    if len(signature) != 86:
        raise PolicyDenied("noncanonical signed receipt")
    return hashlib.sha256(
        b"PHICLOUD_R9_WEBAUTHN_REVIEW_BINDING\x00" + signed
        + b"\x00" + signature.encode("ascii")
    ).digest()


def verify_stepup_assertion(
    *,
    assertion: object,
    challenge: bytes,
    credential_id: bytes,
    credential_public_key: bytes,
    sign_count: int,
) -> int:
    """Validate RP, origin, signature, challenge, UP+UV and counter.

    The registered authenticator key is a verified COSE public key from a
    trusted enrollment service, NEVER supplied by the assertion itself.
    """
    if verify_authentication_response is None:
        raise PolicyDenied("pinned WebAuthn verifier not installed")
    if (
        type(assertion) is not dict
        or type(challenge) is not bytes or len(challenge) != 32
        or type(credential_id) is not bytes or len(credential_id) not in range(16, 129)
        or type(credential_public_key) is not bytes
        or not 32 <= len(credential_public_key) <= 4096
        or type(sign_count) is not int or not 0 <= sign_count < 2**32
    ):
        raise PolicyDenied("invalid registered WebAuthn assertion context")
    try:
        encoded = json.dumps(
            assertion,sort_keys=True,separators=(",",":"),allow_nan=False
        ).encode("utf-8")
        if len(encoded) > MAX_ASSERTION_BYTES:
            raise PolicyDenied("WebAuthn assertion too large")
        verified = verify_authentication_response(
            credential=assertion,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )
        if verified.credential_id != credential_id or not verified.user_verified:
            raise PolicyDenied("credential/user verification mismatch")
        return verified.new_sign_count
    except PolicyDenied:
        raise
    except Exception as exc:
        raise PolicyDenied("WebAuthn user verification failed") from exc
