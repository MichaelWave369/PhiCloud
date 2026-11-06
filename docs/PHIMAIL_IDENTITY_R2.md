# PhiCloud R2: PhiID/PhiMail verified-local identity boundary

This is an architecture and negative-test milestone, NOT a deployed cloud identity gateway.

## What now exists in separate repositories

- PhiID: localhost Keycloak development realm, using audited OpenID Connect.
- PhiMail: an independent development relying party that can authenticate a synthetic test user against that SAME issuer. PhiMail validates its own ID token through openid-client and holds a short-lived local session.
- PhiCloud: a loopback-only declaration registry. It does NOT validate access tokens, authorize mailbox access, host identity services, persist tokens, or bind users to remote resources.

## Rules for a production PhiCloud identity gateway

1. A shared identity provider is NOT a shared application session. PhiMail has its own OAuth client, redirect URI, session and scope.
2. The verified identity key is validated issuer plus subject. A browser-supplied profile, email address, JSON export, local consent receipt or service registry declaration is NOT a credential.
3. Cloud resource authorization requires a token intended for that resource and validated by an audited JWT/OIDC library, including issuer, audience, expiration, signature and resource ownership. A PhiMail ID token is not a cloud API access token.
4. Identity does not grant ownership of an external Gmail mailbox. Mail provider connection and storage require explicit authenticated owner consent and independent OAuth.
5. Provider credentials and mailbox contents belong in appropriate encrypted resources, never in PhiID static pages, PhiCloud R0 inventory, browser localStorage, logs or public GitHub repositories.
6. PhiOS local capabilities remain independent and must always require their existing effect-approval checks.
7. No R0 service health inference: a successful GET /v1/services response means only that the local declarative registry responded.
8. Before public deployment, build account isolation, scope validation, revocation, audit, rate limiting, device recovery, session rotation, secure HTTPS, threat modelling and penetration tests.

## Safety checks

The regression tests ensure the existing PhiCloud R0 server does not accidentally expose identity, mail or token APIs. There is no authentication endpoint here to connect to from a browser.

Next milestone: design a private PhiCloud gateway with a real OIDC provider and per-service resource authorization, preserving independent local PhiOS and PhiMail operation.

See [PhiID](https://github.com/MichaelWave369/PhiID) and [PhiMail local OIDC R2](https://github.com/MichaelWave369/PhiMail/blob/main/docs/LOCAL_PHIID_R2.md).
