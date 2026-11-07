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
