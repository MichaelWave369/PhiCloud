# PhiCloud roadmap

Checkpoints are **acceptance conditions**, not a claim that the services exist.

## R0: Public contracts and safe local discovery

- [x] Architecture and trust-boundary documentation
- [ ] Read-only local service registry running on loopback
- [ ] Contract validation and deterministic tests
- [ ] CI test gate on pull requests
- [ ] PhiOS service-discovery prototype reviewed without granting app authority

**Done when:** a local user can list declared services and inspect the registry without signing in or hitting any remote endpoint.

## R1: Plain Sovereign substrate

- [ ] One-node reference installation of PostgreSQL, S3-compatible storage, metrics and reverse proxy
- [ ] Reproducible dev deployment and threat model
- [ ] Backup/restore/export verified on independently owned storage
- [ ] Data residency and non-availability states clearly surfaced
- [ ] No PhiKernel dependency in the critical path

## R2: PhiID + PhiMail account integration

- [ ] Audited OIDC issuer and passkey/recovery flows
- [ ] PhiMail single-sign-on client with explicit consent
- [ ] Email aliases separated from immutable identity subjects
- [ ] PhiOS Desktop, WebOS, Mobile smoke tests against the same IdP
- [ ] Tenant isolation, token validation, session revocation, user export and delete

## R3: Portable sync and user storage

- [ ] PhiVault namespace per (`iss`, `sub`) with scoped encryption keys
- [ ] PhiSync opt-in, conflict resolution and offline queue
- [ ] Restore across different owned nodes with integrity checks
- [ ] No silent data exfiltration or compulsory cloud backup

## R4: PhiEye + PhiKernel advisory bridge

- [ ] Normalized, versioned telemetry interface only
- [ ] Recommendation explanations and append-only audit
- [ ] Manual review gates for any prospective privileged action
- [ ] Demonstrated Plain Sovereign fallback
- [ ] Tested safe behavior when metrics are missing, stale or inconsistent

## R5: Optional hosted services and email delivery

- [ ] Deployment isolation, TLS, abuse controls, incident response and resource limits
- [ ] Domain verification, MX/SPF/DKIM/DMARC and delivery/reputation validation for PhiMail
- [ ] User-controlled local/private/hosted selection and migration
- [ ] Availability and performance claims supported by observed evidence

**Principle:** built and green tests != securely deployed; an inventory entry != a live service.

## R3a: Protected local OAuth resource-server proof (security milestone)

- [x] Add opt-in resource endpoint without changing public registry behavior
- [x] Require confidential-client Keycloak introspection, exact issuer/audience/scope/expiry checks, no bearer-token decoding or homebuilt crypto
- [x] Refuse wrong PhiMail/identity token, revoked/expired token, malformed bearer header and provider outages
- [x] Add separate disposable Keycloak + authorization-code PKCE CI workflow proving real token validation and revocation
- [ ] Confirm all CI checks green on R3a PR
- [ ] Add real per-resource owner/tenant isolation and permission checks before any file/mail content
- [ ] Review TLS, secret rotation, audit, recovery and public security perimeter separately before hosting

## R4: Scoped owner-isolated temporary resources (local-only evidence)

- [x] Add default-off, in-memory demo records with strict verified issuer+subject ownership
- [x] Separate exact `phicloud.demo.read` and `phicloud.demo.write` Keycloak scopes, checked at resource server on every request
- [x] Prevent other subjects from listing/reading/deleting even when an opaque record ID is known
- [x] Reject caller-controlled owner/body, cross-origin mutations, bad action headers, stale/invalid scopes and unavailable identity provider
- [x] Bound TTL, owner/global capacity, and concurrency-safe store operations
- [x] Extend real Keycloak CI to use two distinct signed-in users and independent logout checks
- [ ] Confirm latest-commit Python/ANC/PhiShield and real Keycloak workflow are green
- [ ] Design actual tenant-aware durable resource persistence and owner/operation authorization before files or mailbox data

## R6: Private durable synthetic tenant ownership (separate from R5 consent)

- [x] Add opt-in local SQLite fixture with operator-only one-time tenant membership and pseudonymous Keycloak subject indices
- [x] Guard exact tenant read/write OAuth scopes, private record ownership, explicit mutation actions and absence of arbitrary payloads
- [x] Make record creation/deletion and bounded local actor audit atomic; preserve state across restarts
- [x] Add Python privacy, ownership, restart, TTL, capacity, revocation and path-safety tests
- [x] Add distinct real Keycloak workflow with two independent test users, server restarts and deletion/audit verification
- [ ] Verify all independent R6, existing R3, PhiShield and ANC CI checks pass after PR review
- [ ] Design encrypted tenant-aware database, account recovery, operator membership lifecycle and backed-up audit **before any real user file storage**

## R8: Offline one-way membership removal and no-resurrection verification

- [x] Add a private shared exclusive database lease, blocking service and offline operator from overlapping on the same SQLite test file
- [x] Add opt-in, nonproduction stdin-only operator preview and explicit per-tenant confirmation before apply
- [x] Atomically purge one member's synthetic markers and remove membership in the selected tenant, preserving other owners and private audit
- [x] Write durable revocation tombstone; fail closed on re-grant anomaly, allow safe repeat revoke
- [x] Extend real two-user Keycloak integration to prove still-active token cannot resurrect removed membership after restart
- [ ] Obtain all CI checks green and review after other active PhiCloud PRs merge
- [ ] Design production-safe tenant lifecycle, backup-aware revocation and real file data protection separately

## R9: Independent revocation witness vs stale SQLite backups

- [x] Add opt-in, separate owner-private append-only JSONL witness bound to existing SQLite test fixture
- [x] Carry forward old R8 tenant tombstones on one-time operator enrollment; block missing, unsafe, mismatched or stale backup state
- [x] Append+fsync witness before transactionally revoking tenant membership; fail closed on crash window or restored stale SQLite
- [x] Provide offline revoke-only reconciliation with explicit operator acknowledgment and durable recovery count; never regrant access
- [x] Add unit tests for stale snapshot denial, crash/rollback, missing/corrupted witness, duplicate entries and safe, idempotent repair
- [x] Extend real two-user Keycloak CI to restore older SQLite only and prove a still-active token cannot regain membership after reconciliation
- [ ] Verify latest-head Python/ANC and both real Keycloak workflows pass, then review and merge
- [ ] External tamper-resistant revocation authority, tenant lifecycle and encrypted real resource storage remain separate future security gates

## R10: Separately scoped AES-GCM synthetic marker storage

- [x] Add default-off AES-256-GCM fixed synthetic marker encryption using the already-pinned cryptography library
- [x] Provision raw test encryption key offline in private directory separately from SQLite, bound by key fingerprint; reject missing/wrong keys
- [x] Authenticate tenant, owner, record ID and timestamp as AES-GCM associated data; prevent tamper, metadata swaps and foreign reads
- [x] Add independent exact sealed read/write OAuth scopes, no browser plaintext or supplied payloads
- [x] Purge a revoked tenant member's sealed test rows within R8/R9 membership removal transaction
- [x] Add unit/HTTP tests and extend real two-user Keycloak CI to cover restart with independent key
- [ ] Confirm full Python matrix, ANC/PhiShield and two actual Keycloak workflow checks are green
- [ ] Design actual data-key envelope encryption, independent recovery/rotation, export and trustworthy backup policy before real files

## R11: Per-record DEK envelope wrapping and offline key rotation (synthetic only)

- [x] Give each new fixed synthetic marker its own random 256-bit DEK; AES-GCM encrypt payload and independently wrap each DEK under an operator-only KEK
- [x] Bind schema, tenant, owner, ID, timestamps and distinct payload/wrap domains as authenticated data, with random independent nonces
- [x] Add exact `phicloud.envelope.read/write` token scopes and membership/ownership enforcement with no supplied payload
- [x] Provide offline operator rewrap with exclusive SQLite lease, atomic all-record key rotation and unchanged encrypted payload bytes
- [x] Purge wrapped DEKs from revoked tenants during R8/R9 SQL transactions
- [x] Add Python tests and real two-user Keycloak rotation/ownership test
- [ ] Confirm all three CI workflows green on current PR head, followed by review and merge
- [ ] Independently protected key rotation epochs, actual user export/recovery/escrow and production file-encryption requirements remain unimplemented

## R12: Independent KEK rotation epochs and rollback-safe offline reconciliation

- [x] Add separate private JSONL witness in directory distinct from SQLite and KEK backups, one-time DB binding and epoch validation
- [x] Gate enrolled envelope startup on matching witness even when older KEK matches an older restored database
- [x] Fsync witnessed rotation before transactional wrapped-DEK changes; fail closed if SQLite commit fails
- [x] Add offline exact pending-epoch reconciliation, never silently skip/repeat/roll back epochs or recover user content
- [x] Test stale DB+old KEK, corrupted/missing witness, crash window and no-regrant recovery in Python tests
- [x] Extend two-real-user Keycloak CI to simulate stale DB+old KEK rollback and exact recovery with owner isolation
- [ ] Verify all Python, ANC, R3/PhiShield and real Keycloak R6/R9/R10/R11/R12 workflows green on final PR head
- [ ] Add independently trusted hardware/server monotonic key authority, actual key custody, backup/export/retirement before any PhiVault files
