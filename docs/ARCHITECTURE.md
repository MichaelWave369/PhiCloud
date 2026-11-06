# PhiCloud R0 architecture

Status: **proposal plus local-only discovery prototype**, not cloud deployment.

## Mission

Provide one consistent, sovereign web-services boundary for PhiOS Desktop, WebOS and Mobile, while keeping local PhiOS useful without an account or internet access. PhiCloud is a replaceable layer over existing open components, not a new proprietary replacement for every protocol.

## Four planes, carried forward from MK1

| Plane | Purpose | Candidate components |
| --- | --- | --- |
| Substrate | Reliable, independently functional storage, compute and networking | PostgreSQL, S3-compatible object storage/MinIO, Linux containers/VMs, WireGuard, reverse proxy |
| Control | Service inventory, health observation, scheduling advice and policy interfaces | Versioned manifests, PhiShield adapters, optional PhiKernel advisory bridge |
| Field | Optional signals and historical workload context | Bounded, normalized telemetry; no inferred authority |
| Operator | Clearly differentiated observed facts, declarations, recommendations and approvals | PhiEye dashboards, receipts, audit, manual review |

**Two modes:** Plain Sovereign requires no Phi-specific orchestration; Phi-Orchestrated adds advisory telemetry and explanations. If the second fails, the first still operates.

## Platform flow

```text
PhiOS Desktop / PhiOS WebOS / PhiOS Mobile / ecosystem apps
        |
        +-- PhiMail: account doorway + email UX (optional)
        +-- PhiID: OIDC issuer + account lifecycle (planned)
        |      |
        |      +-- stable user subject; device/session credentials
        |      +-- sign-in != scope != PhiOS authority
        |
        +-- PhiCloud API / discovery (R0: localhost, read-only)
                  |
                  +-- PhiVault + PhiSync (planned; opt-in)
                  +-- PhiCompute / PhiBase / PhiNet / PhiRoute
                  +-- PhiTrigger + PhiEye + PhiShield
                  +-- PhiServe local bridge (separate, opt-in)
                  |
                  +-- Plain Sovereign open-source substrate
                         + optional PhiKernel advisory bridge
```

### Trust boundaries

1. **Local OS authority:** PhiOS alone evaluates a specific local action against its current capability, explicit approval, and receipt contracts. An OIDC token cannot bypass it.
2. **PhiID:** authenticates users and issues scoped, audience-restricted tokens for remote services. A verified email address is not a stable account key.
3. **PhiMail:** renders mail/account UI and delegates sign-in to PhiID. It does not store signing keys and does not silently become the OS login provider.
4. **PhiCloud services:** independently validate tokens, audiences, permissions and resource ownership. Never trust a client-provided user ID.
5. **PhiServe:** existing loopback inference stays independent. Any remote proxy needs explicit owner approval, transport protection, narrow scopes and per-request limits.
6. **Hosting:** public endpoints sit behind TLS and authenticated gates. This R0 prototype has no remote host, user database, email service or administrative mutation endpoint.

## Transport and deployment profiles

- **Local/desktop:** Python standard-library service discovery bound to `127.0.0.1`; no cloud requirement.
- **LAN/private mesh (future):** authenticated mTLS or WireGuard plus validated capability scopes and local operator approval.
- **Hosted (future):** OIDC provider, TLS, private service network, rate limiting, backups, deletion/export, abuse control, incident response.
- **Air-gapped:** local-only PhiOS features must continue unaffected; sync queues require user opt-in and explicit reconciliation.

## Service identity and inventory

The R0 service registry is a **declaration**, not a probe. Its entries describe names, owning repos, optional endpoint hints and integration stages. `/healthz` reports only that the local prototype is running, not that PhiID, PhiMail, PhiServe or any other service is alive.

Future authenticated discovery must include tamper-resistant signed manifests, a pinned trust root, revocation, explicit endpoint allowlisting and user review. This prototype does not initiate requests to declared endpoints.

## Existing repos and compatibility

- PhiOS: governed app execution, Covenant Runtime, offline sovereignty and effect receipts remain authoritative.
- PhiMail: provider-independent client first; OAuth/IMAP/SMTP and sovereign hosting later. Do not describe a planned mailbox as working email.
- PhiServe: loopback real-inference serving exists separately. PhiCloud must not claim integrated or internet-exposed inference.
- PhiMadaPrime: possible operator experience, not a replacement for independent review.

## Relation to MK1 v0.1–v0.3

Keep the canonical **goal**: observable, explainable, sovereign behavior. Keep the notion of advisory pressure, confidence, escalation and append-only audit, but **do not publish protected implementation internals** in this repository. The v0.2 spec contains an inconsistent pressure-zone label; the later v0.3 definitions should be the review baseline, not silently mixed. PhiKernel integration remains a separately gated contract.

## R0 exclusions

Not implemented: SSO, Keycloak setup, user registration, passkeys, email service, DNS, deployment, live service probes, synchronization, public API gateway, secure multi-tenancy, infrastructure autoscaling, control actions, audit durability or encryption.
