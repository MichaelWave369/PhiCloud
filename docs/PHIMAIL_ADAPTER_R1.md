# Φ PhiCloud → PhiMail R1: read-only registry compatibility

The PhiCloud R0 localhost registry exposes versioned, **declarative** service metadata. PhiMail now has a read-only adapter that can consume this inventory in local development.

## Contract

- HTTP GET /v1/services on loopback 127.0.0.1:8769
- Schema: phicloud.services.v0.1
- Fields: id, title, role, stage, repository, endpoint_hint
- Stage values: planned, integration-needed, prototype
- Service health: **not observed** by this endpoint
- Authentication, authorization and account sessions: **not supplied** by this endpoint

PhiMail's adapter validates the complete schema and renders roles and planning stages. It discards all endpoint_hint values and does not probe any declared service. Its developer-only Vite proxy connects to one fixed loopback address and cannot be pointed at an arbitrary service.

## Minimal PhiMail smoke test

1. Run python -m phicloud.server --port 8769 in the PhiCloud directory.
2. Run npm run dev in the PhiMail directory (dev server binds to loopback).
3. Open PhiMail's Field Connections and select Read local PhiCloud registry.
4. Confirm that the registry declares PhiID and PhiMail, but the panel still reports **No service health checked**.

The PhiID service declaration remains in the planned stage: a preview website exists but does not provide a real OIDC issuer. PhiMail's declaration remains integration-needed because real secure account integration is unfinished.

## Security requirements for next rung

A future hosted PhiCloud gateway must validate real OIDC tokens and authorize each resource, using audited libraries and tenant isolation. It must not treat a user-supplied email address, preview export, declared endpoint, or arbitrary JSON as proof of authority.

No existing PhiOS offline capability should depend on the registry's availability. Never expose this unauthenticated R0 service on a public interface.

References: [PhiID contract](https://github.com/MichaelWave369/PhiID/blob/main/docs/IDENTITY_CONTRACT.md), [PhiMail Field Connections](https://github.com/MichaelWave369/PhiMail/blob/main/docs/INTEGRATION_R1.md).
