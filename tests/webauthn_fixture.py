"""DISPOSABLE synthetic WebAuthn authenticator fixture, for tests only.

Constructs correctly signed ES256 assertion data to test the RP verifier.
Nothing here proves the presence of a human or a hardware authenticator.
Never copy this code into an actual credential enrollment service.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import asdict
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
import cbor2

from phicloud.operator_approval import canonical_message, SCHEMA, PURPOSE
from phicloud.webauthn_presence import RP_ID, ORIGIN


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class SyntheticAuthenticator:
    def __init__(self):
        self.credential_id=secrets.token_bytes(32)
        self.private=ec.generate_private_key(ec.SECP256R1())
        public=self.private.public_key().public_numbers()
        self.cose_public=cbor2.dumps({
            1:2,3:-7,-1:1,
            -2:public.x.to_bytes(32,"big"),
            -3:public.y.to_bytes(32,"big"),
        })

    def registration(
        self, challenge, *, counter=0, verified=True, present=True,
        origin=ORIGIN, rp_id=RP_ID, credential_id=None,
    ):
        """Synthetic fmt=none registration; ES256 credential public key is valid.

        No attestation/hardware/human identity is claimed by this fixture.
        """
        cid = credential_id if credential_id is not None else self.credential_id
        flags = (1 if present else 0) | (4 if verified else 0) | 0x40
        auth_data = (
            hashlib.sha256(rp_id.encode("utf-8")).digest()
            + bytes([flags]) + counter.to_bytes(4,"big")
            + bytes(16) + len(cid).to_bytes(2,"big") + cid
            + self.cose_public
        )
        attestation = cbor2.dumps({
            "fmt":"none", "attStmt":{}, "authData":auth_data,
        })
        client = json.dumps({
            "type":"webauthn.create",
            "challenge":b64(challenge),
            "origin":origin,"crossOrigin":False,
        }, separators=(",",":")).encode("utf-8")
        return {
            "id":b64(cid),"rawId":b64(cid),"type":"public-key",
            "response":{
                "attestationObject":b64(attestation),
                "clientDataJSON":b64(client),
                "transports":["internal"],
            },
            "clientExtensionResults":{},
        }

    def assertion(self, challenge, *, counter=1, verified=True,
                  present=True, origin=ORIGIN, rp_id=RP_ID,
                  credential_id=None, wrong_private=None):
        flags=(1 if present else 0) | (4 if verified else 0)
        auth_data=(
            hashlib.sha256(rp_id.encode("utf-8")).digest()
            + bytes([flags]) + counter.to_bytes(4,"big")
        )
        client_data=json.dumps({
            "type":"webauthn.get","challenge":b64(challenge),
            "origin":origin,"crossOrigin":False,
        },separators=(",",":")).encode("utf-8")
        signing=wrong_private if wrong_private is not None else self.private
        signature=signing.sign(
            auth_data+hashlib.sha256(client_data).digest(),
            ec.ECDSA(hashes.SHA256()),
        )
        cid=credential_id if credential_id is not None else self.credential_id
        return {
            "id":b64(cid),"rawId":b64(cid),"type":"public-key",
            "response":{
                "authenticatorData":b64(auth_data),
                "clientDataJSON":b64(client_data),
                "signature":b64(signature),
                "userHandle":None,
            },
            "clientExtensionResults":{},
        }


def sign_review(ticket, private, *, now: datetime,
                operator="test-operator", kid="signing-key", **modifications):
    stamp=int(now.timestamp()*1000)
    body={
        "schema":SCHEMA,"purpose":PURPOSE,
        "operator_id":operator,"kid":kid,"review_id":ticket.review_id,
        "request":asdict(ticket.request),
        "issued_at_ms":stamp,"expires_at_ms":stamp+20_000,
        "nonce":secrets.token_hex(16),
    }
    body.update(modifications)
    return {**body,"signature":b64(private.sign(canonical_message(body)))}


def ed25519_public_bytes(private) -> bytes:
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
