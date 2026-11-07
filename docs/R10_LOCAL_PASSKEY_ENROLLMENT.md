# PhiCloud R10: real local browser passkey enrollment ceremony

**Status: experimental localhost-only enrollment tool, opt-in.** The
browser uses a real `navigator.credentials.create()` WebAuthn ceremony
with an authenticator available to the operating system. The server verifies
the returned registration with pinned `webauthn==3.0.1`, including the
origin, RP ID, challenge, user presence, and **required user verification**.

This is **not a production account or independent identity-verification
service**, and test CI uses a synthetic ES256 authenticator. No real device
enrollment has been physically tested in CI.

## Boundary

R9's code could verify **authentication assertions** but had no actual
credential registration workflow. R10 now provides a separate, short-lived
browser **registration** ceremony. It does not offer approval UI yet.

- Only an OS operator with the existing private R7/R9 SQLite database and
  an already-enrolled active Ed25519 operator signer can initiate enrollment.
  The local bootstrapping tool cannot create operator signing identities.
- The server binds to **127.0.0.1:8769** only. The browser opens
  **http://localhost:8769**. Browsers permit WebAuthn for localhost as a
  trustworthy local context. Do not put it behind a proxy, expose it on a
  LAN, share it with another device, or use the endpoint in production.
- An interactive terminal displays an unpredictable, **one-use** pairing
  code, which the operator manually types in the browser. The code is
  never in a URL, cookie, Git repository, HTML page or server access log.
  After five incorrect attempts the ceremony is locked. Successful pairing
  consumes the code and creates a 2-minute registration challenge.
- The page shows the target operator ID and calls the browser's
  **native** credential creation method with UV required.
- The server accepts the **exact verified COSE credential public key**
  and credential ID from the vetted WebAuthn verifier. It never trusts a
  browser-supplied public key, arbitrary account ID or credential ID without
  verifying the RP's signed registration result.
- The new credential is stored with the actual initial authenticator
  sign counter, bound to the operator and fixed R9 RP ID/origin. A
  duplicate or previously revoked credential ID cannot be re-enrolled.
- No signed review, authority, WebAuthn login session, PhiCloud API token,
  record access, file/mail permission, or PhiOS device action is granted
  by this ceremony. Real approval still needs R7's independently signed
  request and R9's separate, fresh authentication assertion.

**A pairing code is not human identity proof.** A locally compromised
operator process or stolen pairing code can enroll an attacker's credential.
Before production use, enrollment needs audited operator identity, explicit
approved signer-to-user linking, strong device proof/recovery, credential
lifecycle management and a reviewed local OS isolation model.

## Start it manually (Linux/WSL dev only)

R10 reuses R9's `localhost:8769` WebAuthn RP origin.
The R0 service registry cannot listen on the same port simultaneously.
Start this only after stopping the default registry process.

The database path must already exist, be private (owner-only `0700`
parent / `0600` DB) and contain an operator with a trusted active R7
Ed25519 signer key. **R10 will not bootstrap one itself.**

```sh
python -m pip install --only-binary=:all: -r requirements-operator.txt
export PHICLOUD_OPERATOR_ENROLL_DEV=1
python -m phicloud.operator_enrollment \
  --db "$HOME/.local/share/phicloud-r6/reviews.sqlite3" \
  --operator local-dev-operator
```

The example operator ID is a placeholder. Supply an existing enrolled
operator's ID, not a default account. The CLI requires an interactive
TTY, refuses production environment flags, and rejects new/missing,
symlinked or non-absolute database paths. No native Windows ACL
bypass is provided. WSL requires the browser to reach that exact loopback
listener; a Windows-hosted browser may not reach WSL2's localhost
under every network configuration.

Open `http://localhost:8769`, enter the **terminal-displayed code**,
press Unlock registration, review the operator ID, then press
Register this device / passkey and follow your operating system's
passkey prompt. The browser serializes the returned WebAuthn registration
response and submits it only to the same-origin private server. A successful
response explicitly reports `approval_granted:false` and
`execution_authority:false`. Stop the enrollment server with Ctrl+C.

The one-use code and challenge are never persisted. Restart creates a
different code, and a failed/expired registration must restart.
The newly registered public credential *does* survive in the existing
private SQLite policy ledger and is subject to R9 credential revocation.

## How to verify

```sh
python -m unittest discover -s tests -v
```

`tests/test_operator_enrollment.py` runs the real
`webauthn.verify_registration_response()` against a synthetic
ES256 credential/attestation, checks missing UV/UP, wrong challenge,
RP/origin, repeated code, expired session, duplicate credential,
CSRF/Host denial, and direct R9 signed-review consumption after
the verified enrollment.

It is a **cryptographically correct synthetic attestation**, not a
hardware authenticator test or verified human interaction. Browser
compatibility on Windows/WSL, macOS, Android and native mobile browsers
must be manually tested before any production claim.

## Remaining work

The human-facing **approval** UI must display every R7 request field,
authenticate the already enrolled WebAuthn credential against the
one-use R9 challenge, and require an independent operator-held R7
signature. A signed browser response or newly registered credential
alone must never authorize execution. Secure operator identity linkage,
certificate/attestation policy where appropriate, hardware custody,
encrypted storage, durable audit, key recovery and access-controlled
remote deployment are separately scoped future work.
