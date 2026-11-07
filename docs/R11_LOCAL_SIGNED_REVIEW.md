# PhiCloud R11: localhost exact-action signed approval screen

**Status:** experimental, one-shot local operator review with a real
browser-native `navigator.credentials.get()` API and verified WebAuthn
authentication assertion. **Not a production human authorization system or
a real resource/effect gate.** Automated tests use synthetic authenticators.

R10 built browser passkey **registration**, but the existing R7/R9 review
could only be completed programmatically. R11 adds the missing human-facing
preview/approval screen, without importing a private R7 signing key into the
browser or relaxing R9's user-verification requirement.

## Flow

1. A separately trusted PhiID/introspection and operator-signing workflow
   has already staged exactly one allowed `profile.read` /
   `profile:synthetic-self` request in the private R9 SQLite policy, and
   produced a short-lived **R7 Ed25519 receipt** for that exact request.
   **This repository does not implement that separate signer or the
   authenticated signing ceremony.**
2. A local operator invokes `phicloud.operator_review` against an
   **existing** private policy database and **existing 0600 private JSON
   receipt**. A trusted signer and an R10-registered WebAuthn credential
   must already be bound to the same operator. No key, OAuth token,
   pseudonymous subject or entire receipt is passed as a CLI argument.
3. A standalone server listens only on `127.0.0.1:8769`. A short-lived
   one-use pairing code is printed in the trusted terminal. The browser
   opens `http://localhost:8769`; the HTML/JS contains no receipt,
   private key, bearer token or pairing code.
4. After pairing, the server displays **all seven signed request fields**
   plus operator ID, review ID and deadline. The browser uses
   `textContent` rather than HTML interpolation to prevent script
   injection from identifiers. Until pairing, the review data is not
   returned at all.
5. The operator checks each field, explicitly marks the review checkbox,
   and presses **Verify with passkey and record review**. This issues
   the already existing R9 random challenge, bound to the entire R7
   receipt. The browser calls the native
   `navigator.credentials.get()` with `userVerification: "required"`,
   the exact `localhost` RP, and the **previously enrolled** credential.
6. The trusted R9 verifier checks origin, RP, signature, challenge,
   authenticator ID, user presence, user verification and counter state.
   On success the SQLite policy records a short-lived signed+UV review.
   **No action is consumed or executed.** The result explicitly states
   `execution_authority:false` and `resource_read:false`.
7. **Decline and close review** burns the pending ticket, including one
   with a WebAuthn challenge already issued. Failed verifications
   consume the challenge. A process restart or stale session cancels
   the browser ceremony rather than automatically approving anything.

The separate `evaluate_user_verified_profile_candidate` still requires
**fresh PhiID Keycloak token introspection** and authenticated ANC/PhiShield
evidence before producing, at most, a non-authoritative `CANDIDATE`.
PhiOS effect approval remains completely separate.

## How to start (Linux/WSL development only)

Stop the R0 registry or R10 enrollment server on port 8769 before starting.
The private database must exist under an owner-owned `0700` directory
with `0600` file mode. It must contain the staged R7 request and an
active signer/previously R10-registered authenticator. R11 will **never**
create signers or WebAuthn credentials. If multiple active credentials
exist for the selected operator, the standalone ceremony denies rather
than allowing a browser to select an arbitrary credential.

R7 receipts have a **maximum 30-second lifetime** (often 20 seconds
in fixtures). The operator must perform the review before expiry;
this prototype does **not** extend signatures or cache acceptance.
This tight timeout is a known usability limitation, not proof of a
production-ready approval UX.

```sh
python -m pip install --only-binary=:all: -r requirements-operator.txt
export PHICLOUD_OPERATOR_APPROVAL_DEV=1
python -m phicloud.operator_review \
  --db "$HOME/.local/share/phicloud-r6/reviews.sqlite3" \
  --receipt-file "$HOME/.local/share/phicloud-r6/current-review.json"
```

`current-review.json` must already have been written by an independently
trusted signer as an **exact R7 receipt**. Give it mode `0600`; never
commit, upload, echo, query-string encode, or log real receipts. The
receipt contains pseudonymous owner identifiers. The command requires
an interactive TTY, rejects production flags, symlinked or missing
files, non-private directories and unsafe DB permissions. The local
OS user controlling this database is currently the operator trust root.

Enter the terminal pairing code in the local browser, inspect all
fields, then deliberately approve with an existing passkey or decline.
End the server with Ctrl+C. A paired session is one-shot and volatile.

## Threat protections and limitations

- Strict fixed localhost Host/origin/peer, same-origin POST with exact
  JSON schemas, no cookies or CORS, five-attempt pairing lockout, CSRF
  and clickjacking protection, CSP with separate static scripts, no
  referrer, no cache or access logging.
- No receipt, credential ID or pseudonymous request details before
  successful pairing. The browser receives **display details and a
  challenge**, never the signed R7 receipt or the R7 private signer key.
- Challenge issuance blocks legacy R6 approval and R7 signed-only
  approval on the same pending ticket. Once R9 UV has been recorded,
  credential trust and expiry still apply even if a legacy consumer
  attempts signed-only consumption.
- An exact-action check box is **not evidence of independent human
  identity**, and the local pairing code is **not an authenticated
  operator identity**. Trust is anchored in the local OS user and
  previously enrolled signer + credential.
- No proof against a compromised same-user process, unauthorized
  local DB writes, filesystem rollback, credential key theft,
  a malicious or tricked operator, unsafe backup restoration, or
  a phishing replacement of the independent signing process.
- A user may need additional registration and authenticator work
  for platform-specific browsers, WSL2 forwarding and real hardware.
  The existing R10 code and current CI have **not** been manually
  tested on a physical authenticator.
- R11 is not an HTTP PhiCloud policy service. No public approval API,
  managed identity enrollment, synchronized cloud account, real files,
  messages or device/OS actions exist. **Offline PhiOS remains
  independent of PhiID/PhiCloud account availability.**

## Tests

```sh
python -m unittest discover -s tests -v
node --check phicloud/static/operator_approve.js
```

`tests/test_operator_review.py` checks exact fields and pre-pairing
privacy; full signed/UV review acceptance; pairing lockout, wrong
session, explicit acknowledgment, expiry, declined reviews, wrong
RP/origin/UV, forged challenge, signed receipt tampering, credential
ambiguity, private file/JSON rejection, Host/Origin CSRF checks and
one-use consumption. It also tests the critical R6/R7 downgrade
block and signer/credential revocation after WebAuthn issuance.

Real Keycloak CI continues to validate signed + WebAuthn synthetic
authentication paths, but uses a **synthetic** authenticator. It does
not assert a person touched a real passkey or that a production
identity ceremony is complete.

**Next:** review the independent signer UX, stronger operator identity
binding to PhiID/tenant, durable protected approval audit, realistic
session length, credential recovery, authentic hardware/browser
coverage, and the separate PhiOS device-side permission ceremony.
