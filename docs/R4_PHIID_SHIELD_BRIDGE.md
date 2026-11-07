# PhiCloud R4: verified PhiID identity to PhiShield reference gate

**Status:** Opt-in, localhost-only integration and disposable Keycloak CI.
**Not:** a deployed security service, general resource permission system,
verified human approval, production identity provider, or PhiOS OS authority.

R3 already validates genuine Keycloak user **access tokens** via the resource
server's confidential-client token introspection endpoint. R4 adds a restricted
**in-process** bridge that passes this verified principal into PhiShield's
existing authenticated ANC evidence and non-authoritative policy checks.

## End-to-end boundary

```text
Keycloak authorization-code/PKCE login (real disposable test user)
       |
       v
PhiCloud LocalTokenIntrospector
(active + iss + aud + scope + expiry + sub; fresh every request)
       |
       v
Fixed PhiCloud request:
  scope = pre_service
  action = profile.read
  resource = profile:synthetic-self
  audience = phicloud-resource-dev
  principal = verified (issuer, subject)
       |
       +-----------------+
       |                 |
local signed ANC       separately verified consent
advisory v2            (test fixture ONLY so far)
       |                 |
       +--------+--------+
                |
                v
  PhiShield DENY / REVIEW / CANDIDATE
       |
       v
  NO OS effect, file access, mailbox access,
  cloud storage access, or execution authority.
```

### What is implemented

- `phicloud/shield_identity.py` produces an `EffectRequest` using the
  independently introspected principal, never a browser-provided `sub`,
  email, display export or consent receipt.
- Both service operation and resource are hard-coded to a **synthetic
  self-profile read**. The client cannot replace them with `mail.read`,
  `file.write`, `service.execute` or other operations.
- The bridge rejects invalid, insufficient, revoked or unavailable identity
  and requires a separate trusted consent verifier callback.
- Even with valid OIDC identity and an independently supplied consent
  fixture, a PhiShield advisory remains `CANDIDATE`, **never** authorization
  to execute an action. Risk veto and nonce replay denial still apply.
- ANC's signed envelope v2 binds the validated issuer/subject and the
  exact service action/resource to its authenticated risk summary.
- No public policy HTTP route is added. `/v1/private/profile` remains the
  existing R3 read-only synthetic demo resource and is not silently modified.

### Unit and real-provider verification

```sh
python -m unittest discover -s tests -v
```

New `tests/test_shield_identity.py` covers deterministic negative cases,
including wrong issuer, audience, scope, subject, token expiry, Keycloak
outage, absent or mismatched consent, swapped verified user, replay and
tampered risk evidence. These use an injected introspection stub in unit
tests and **are not** claims of real user authentication by themselves.

The pre-existing [R3 real Keycloak CI](../.github/workflows/keycloak-authz.yml)
boots disposable Keycloak, creates a temporary user, and completes a real
OIDC authorization-code + PKCE flow. R4 extends that job with a private
Python subprocess receiving the real access token on **stdin**, not
argv, URL or source control. The subprocess derives a restricted request
through fresh real Keycloak introspection and checks:

1. Active correctly scoped PhiID token + a **synthetic trusted consent
   fixture** + local signed synthetic ANC risk evidence => `CANDIDATE`,
   not a permission to execute.
2. The same valid token but **without independent consent** => `DENY`.
3. Wrong audience/scope or a PhiMail app token => `DENY`.
4. A token after Keycloak revokes the disposable user's sessions => `DENY`.

The unit test and real-provider smoke do **not** verify a live PhiID
human-consent service, and the in-process risk fixture is synthetic. A
separate [pinned cross-repository ANC integration](../tests/anc_contract_smoke.py)
already checks the real ANC detector-to-risk-envelope wire compatibility.

### Important trust limitations

The R4 method is a **trusted-process integration seam**. Python types do
not authenticate a remote caller: a compromised process can fabricate
objects, replace dependencies or steal secrets. In a deployment, the
introspector configuration, token receiver, consent verifier, keys, and
resource policy must all be controlled by trusted service components.

The current `ConsentEvidence` dataclass is *not* a cryptographic consent
receipt. Production must substitute a separately verified user approval
or a reviewed operation-specific policy rather than passing arbitrary
objects or client booleans.

PhiID R2 consent preferences and R6 **PocketMesh-specific** Ed25519
approvals do **not** authorize PhiCloud requests. Do not convert them
into generic permission by renaming fields. They have different purpose,
audience, and trust constraints.

The R3 localhost Keycloak resource server also does **not** provide
production HTTPS, tenant isolation, ownership checks, persistent policies,
signer key lifecycle, replay persistence, security audits, or internet
exposure protections. Its fixed HTTP loopback test endpoint must remain
unreachable from LAN/WAN or public GitHub Pages.

**PhiOS stays usable offline and without a PhiID account.**

## Next step

Implement an independently reviewed, **purpose- and resource-specific**
consent/authority verifier, then add negative-path tests for revocation,
resource ownership, signer compromise and user denial before any
consequential effect is considered. Do not make `CANDIDATE` executable.
