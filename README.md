# Φ PhiCloud

**Sovereign web services for the PhiOS ecosystem.**

PhiCloud is the proposed **local-first service backbone** for PhiOS Desktop, WebOS, Mobile, and ecosystem applications such as PhiMail and PhiServe. The project is designed to provide service discovery, identity integration, storage, synchronization, observability, and optional hosted infrastructure without making the cloud mandatory.

> **Status: foundation / design stage.** This repository is being initialized. No hosted service, production identity provider, mailbox delivery, account sync, or deployed infrastructure is claimed.

## Operating principles

- **Sovereignty:** PhiOS must remain usable offline and without a PhiCloud account.
- **Interoperability:** use open protocols, documented exports, and portable data.
- **Capability is not authority:** signing in does not grant permission to execute actions on a user's device.
- **Plain Sovereign first:** independently functional infrastructure, even if advisory orchestration is offline.
- **Advisory before automation:** observable recommendations and audit records before privileged control.
- **No fake availability:** registry declarations are not runtime health checks.
- **No secrets in static sites, public manifests, source control, or browser bundles.**

## Naming and responsibilities

| Component | Responsibility |
| --- | --- |
| **PhiID** | Account identity, OIDC sign-in, passkeys, user lifecycle (future service) |
| **PhiMail** | Email client, mailbox experience, and eventual optional hosted mail |
| **PhiShield** | Policy enforcement and access control at service boundaries |
| **PhiVault** | Object storage, files, backups and user-directed exports |
| **PhiSync** | Opt-in cross-device data synchronization |
| **PhiCompute / PhiBase** | Compute and database substrate |
| **PhiNet / PhiRoute** | Private network and service discovery |
| **PhiTrigger** | Governed functions, workflows and events |
| **PhiEye** | Health, telemetry, operator explanations, audit |
| **PhiServe** | Independently governed local AI serving; remote access is not implied |
| **PhiKernel bridge** | Advisory-only, normalized contract, no internal implementation in this public repo |

**PhiMail is the user-facing account doorway, not the security root.** Accounts use stable opaque identifiers (OIDC `sub`), while mailbox addresses are mutable login/contact aliases. Mail delivery and email recovery must never become the only access path to the operating system.

For PhiMail R1's **development-only service declaration adapter**, see [the PhiMail registry compatibility guide](docs/PHIMAIL_ADAPTER_R1.md). A successful inventory read never confirms service health or identity.

See the [architecture](docs/ARCHITECTURE.md), [PhiID ↔ PhiMail identity contract](docs/PHIID_PHIMAIL_IDENTITY.md), and [roadmap](docs/ROADMAP.md).

PhiID and PhiMail now share a **local development OIDC issuer** through independent clients. PhiCloud still exposes **no identity gateway or mail API**; see [R2 verified-identity boundary](docs/PHIMAIL_IDENTITY_R2.md).

## R3: Protected localhost demo resource via real Keycloak tokens

The optional **PhiCloud R3 resource-server gate** validates a real OAuth 2.0 access token through Keycloak confidential-client introspection on fixed IPv4 loopback. It checks `active`, exact issuer, `aud=phicloud-resource-dev`, `scope=phicloud.profile.read`, expiry and subject on **every** request. A disabled or revoked token fails closed, and arbitrary PhiID display exports or consent receipts never grant access.

The new `/v1/private/profile` route returns only a pseudonymous, *synthetic local test profile* with explicit `cloud_storage_access:false`, `mailbox_access:false`, and `phios_effect_authority:false`. The existing public `/v1/services` registry remains unchanged.

**Disabled by default**. Requires `PHICLOUD_ENABLE_OAUTH_DEV=1` and a private `PHICLOUD_OAUTH_CLIENT_SECRET` for a dedicated confidential Keycloak development client. No hosted login, file storage, authorization for real resources or production deployment is implemented.

See [R3 scope, setup, real-provider CI and limitations](docs/R3_LOCAL_OAUTH_GATE.md).

## First executable milestone

The R0 prototype offers **local-only, read-only service declarations** and standard-library tests. It is not an IAM server, mail server, storage host, or cloud provider. Any inventory is explicitly declarative, not a live-health or integration claim.

Requirements: Python 3.11+; no third-party packages.

```sh
python -m unittest discover -s tests -v
python -m phicloud.server --port 8769
# In another terminal:
curl http://127.0.0.1:8769/healthz
curl http://127.0.0.1:8769/v1/services
```

The server always binds to `127.0.0.1`; its default public registry has no account, mailbox, remote request or mutating API. The optional R3 profile test endpoint performs fresh localhost-only OAuth introspection and is disabled unless explicitly configured. `/healthz` checks **only the registry process**, not whether any service is online. Service stage values are planning/integration labels, not observations. Do not expose this unauthenticated prototype directly to the internet.

## PhiShield R0: local ANC-linked policy candidate (prototype)

The PhiCloud repository now contains an **in-process, side-effect-free
PhiShield policy consumer** at `phicloud/shield_policy.py`. It validates
ANC's versioned risk advisory alongside independent, request-bound
authority and consent evidence, then returns only `DENY`, `REVIEW`, or
`CANDIDATE`. It never grants execution authority.

The new CI interoperability job fetches ANC at an **exact commit**
and verifies real ANC-generated advisory envelopes against PhiCloud's
independent consumer. The existing registry HTTP server remains
**read-only**, unauthenticated and **does not expose a policy endpoint**.
This is not working PhiID authentication, live PhiShield enforcement,
or a remotely accessible security API.

See [the PhiShield R0 trust boundary](docs/PHISHIELD_ANC_LOCAL_R0.md).
Test locally with `python -m unittest discover -s tests -v`.

## Existing projects

- [PhiOS](https://github.com/MichaelWave369/PhiOS)
- [PhiMail](https://github.com/MichaelWave369/PhiMail)
- [PhiServe](https://github.com/MichaelWave369/PhiServe)
- [PhiMadaPrime](https://github.com/MichaelWave369/PhiMadaPrime)

### Historical source

PhiCloud MK1 v0.1-v0.3 specified a two-mode sovereign infrastructure with four planes (substrate, control, field, operator) and a read-only telemetry-to-audit control loop. Its **latest v0.3 operator-safe intent** informs this repo; private PhiKernel/TIEKAT internals are not reproduced here. The v0.2 and v0.3 threshold descriptions should not be mixed without an explicit contract revision.

**License:** MIT (see [LICENSE](LICENSE)).
