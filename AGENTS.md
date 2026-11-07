# PhiCloud public-repository guardrails

PhiCloud is an open-source integration layer. **Capability is not authority.**

- Never copy proprietary PhiKernel, TIEKAT, BioStack or other protected internals into this public repository. Consume only documented, normalized, versioned contracts and operator-approved values.
- Never imply that a declarative service registry confirms network reachability, healthy backends, authenticated users or completed deployments.
- Preserve PhiOS offline operation. Remote identity must not gate local unlock, local storage or pre-existing app access.
- Authentication is not authorization, and authorization does not substitute for independent PhiOS effect approval.
- The default listener for prototypes is loopback only; public exposure requires a separately reviewed authenticated deployment design.
- No real user data, passwords, tokens, session cookies, API keys, signing keys, or mailbox contents may appear in commits, tests, docs, logs, examples or browser bundles.
- Avoid auto-mutating infrastructure. Start with observation, advisory, operator review and audited manual change.
- Do not couple PhiServe's local model endpoint to cloud identity or silently make it internet-reachable.
- Require deterministic tests for contracts, errors and safe defaults; describe what has not been tested.

## R3 local OAuth resource gate

- The optional `/v1/private/profile` is a **development-only synthetic read resource**; it cannot unlock cloud files, mailboxes, funds, PhiServe, PhiOS local actions or PocketMesh effects.
- Keep the default registry endpoint public, declarative and independent of cloud account sign-in.
- Do not write your own JWT signature verifier or trust browser-provided claims. Require server-to-server **confidential-client Keycloak introspection** at one hard-coded IPv4 loopback endpoint, followed by exact active, issuer, audience, scope, token type and expiry checks.
- No introspection allow-cache. Errors, unavailable Keycloak, wrong/expired/revoked tokens must fail closed. Never log bearer tokens, raw introspection responses, OAuth codes, client secrets or callback URLs.
- Client credentials are process-only, secret-free in source, and the R3 route is disabled by default. Production deployment and non-loopback binding are forbidden for this prototype.
- Scope `phicloud.profile.read` and audience `phicloud-resource-dev` are for **this specific demo resource**, not a wildcard authority across the ecosystem.
- The real integration test creates disposable Keycloak clients/scopes/users at runtime; it does not modify PhiID's committed realm or require actual user accounts.
- Real stored resources require separately verified subject ownership, tenant, operation-level policy, record deletion, auditing and an independent local PhiOS effect gate.

## R4 owner-isolation development proof

- Do not accept caller-supplied owner or actor IDs, file names, content, or storage object paths. Bind every R4 demo record to the **real introspection-verified** `(iss,sub)` at request time.
- R4 remains disabled unless explicitly opted in alongside the existing R3 OAuth gate. All routes stay IPv4 loopback-only. Never connect an R4 record to real files, object storage, Gmail, data exports, or PhiOS device effects.
- Enforce separate exact `phicloud.demo.read` and `phicloud.demo.write` scopes with audience `phicloud-resource-dev`. An authenticated account, R3 profile-only token, consent receipt or Pocket approval does not authorize an R4 operation.
- Re-introspect EVERY request; fail closed on provider outage and upstream revocation, do not cache authorized decisions.
- Foreign IDs and nonexistent IDs return identical 404 responses; never reveal existence across users. Keep data ephemeral, bounded and free of personal information.
- Require a guarded mutation action header, no request bodies, and exact loopback origin for browser-originated mutations. Test arbitrary owner injection, timeouts, concurrency, expiry, capacity, cross-user delete and logout isolation.
- A passed R4 test is not production storage or tenant isolation. Any real owner database and internet deployment requires independent security review, HTTPS, durable policy enforcement, encryption and recovery guarantees.

## R6 private durable tenant-owner **development** fixture

- R6 is **not** user file storage or production multi-tenant authorization. Never attach actual files, credentials, email, mailboxes, PhiVault, PhiOS effects, or privileged processes to its synthetic records.
- Only an operator-owned, exact-schema first-start fixture may provision tenant membership. Never derive membership from a client-supplied tenant name, token email, a UI claim, a PhiID consent receipt or a Pocket approval. Never expose tenant/member provisioning as an unauthenticated HTTP route.
- Derive every actor only from fresh confidential-client Keycloak introspection; require exact `phicloud.tenant.read` or `phicloud.tenant.write` and `phicloud-resource-dev` audience, plus server-side tenant membership and exact record ownership. Foreign/missing records return an indistinguishable 404.
- Require both R3 OAuth and R6 tenant-development opt-in flags. Enforce POSIX 0700 directory/0600 SQLite permissions and refuse symlinks or native Windows until tested ACL protections exist. Store only synthetic markers and pseudonymous owner keys; do not log tokens or operator fixture content.
- Preserve atomic create/delete+audit semantics, owner-isolated bounded history, 30-day record expiry, 90-day audit expiry and capacity ceilings. Recheck upstream token validity on every resource request.
- Keep R0 service inventory, R4 ephemeral owner demo, PhiShield consent flows and standalone/offline PhiOS independent. Use a distinct R6 Keycloak workflow rather than overwriting concurrent R5 consent tests.
- Never claim the private SQLite audit is tamper-evident, encrypted, multi-process reliable, backed up, production-ready or appropriate for personal data.

## R8 offline tenant revocation safety

- Offline tenant membership revoke **never** comes from a public HTTP request, PhiID browser consent, R7 operator signature, or cloud token alone. Only a trusted local operator with access to the existing private SQLite fixture can invoke the opted-in CLI.
- Both the PhiCloud server and offline operator hold the same nonblocking, owner-private exclusive POSIX lock file. Refuse a second process; never unlink/recreate the lock file while the service may be active.
- Require explicit per-tenant typed confirmation in stdin JSON before an irreversible local revoke; no subject/email/token in argv, logs or response. Don't accept additional, duplicate or unrecognized request fields.
- Atomically remove only that member's records and membership in one tenant; persist a local revocation tombstone. Do not remove other people's records or unrelated tenant memberships. Revoke remains effective against active Keycloak tokens because every HTTP request checks server-side membership after token introspection.
- IdP logout/token revocation, production account deletion, backups/restore protection, cloud object deletion and real user file erasure are out of scope. Never represent this local test fixture as tamper-evident or suitable for production personal data.

## R9 independent witness and backup-aware revocation

- R9 is **only** an opt-in local, synthetic, single-host rollback guard. A witness file in a different private directory from SQLite must survive a SQLite-only restore. It is not tamper-proof or resistant to privileged restoration of both copies; never claim production safety.
- Enrollment must be one-time, operator-confirmed and offline with the shared R8 SQLite process lease; neither endpoint nor service token may enroll a fence or reconcile a stale restore.
- The R9 witness must be a separate owner-private non-symlink JSONL, never auto-recreated, overwritten, or placed under the same SQLite backup directory. Database startup refuses a missing/mismatched/truncated witness or missing binding. An enrolled DB opened without its witness must fail closed.
- Append and fsync irreversible local witness revocation **before** modifying SQLite. If SQLite later fails, a mismatch must stop normal startup. Reconciliation may only remove memberships/markers and restore missing tombstones; NEVER add members or delete the witness to “fix” test failures.
- Any still-active Keycloak token must remain blocked by server-side membership checks, even after an offline recovery. Keep explicit route scopes and per-resource ownership intact.
- Never log raw OIDC subjects, credentials, bearer tokens, private file locations, or raw witness entries. No real cloud files, production backups, mailbox data, personal information, or PhiOS effects in this fixture.
- A witness-only rollback guard is insufficient for multi-node deployments, backup integrity, encryption, adversarial host tampering or production account restoration. Those require independently protected recovery design and review.

## R10 encrypted synthetic marker security invariants

- R10 is a **disabled-by-default synthetic canary only**. Never accept user-provided plaintext, file paths, mail, PhiVault data, credentials, OAuth tokens, wallet or PhiOS device effects through these endpoints.
- AES-256-GCM uses random nonces and authenticated associated data binding exact tenant, verified owner pseudonym, marker ID and timestamps. Do not roll your own crypto. The pinned `cryptography` package supplies AESGCM; never expose ciphertext or decryption keys to a browser or log.
- Key file is an independent 32-byte random value in a separate POSIX owner-private directory, provisioned explicitly offline with a private DB lock. Key must NEVER appear in SQLite, source, backups in the same directory, logs or a static website. A wrong/missing/broadly readable/symlink key fails closed, not silently replaced.
- Every sealed request gets fresh real resource-specific Keycloak introspection and exact `phicloud.sealed.read` / `phicloud.sealed.write` scopes, plus tenant membership and individual owner checks. Other users' sealed marker IDs must be indistinguishable from nonexistent IDs.
- Writes have exact action headers, origin protections and **no body or owner field**. R8/R9 tenant revocation must purge revoked owners' encrypted markers within the same SQLite transaction; no cloud data or real user files involved.
- R10 is NOT full-database encryption, recovery escrow, KMS, envelope encryption, customer data protection or production key rotation. Key loss is permanent for test canaries; do not claim otherwise.
