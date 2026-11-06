# PhiID ↔ PhiMail ↔ PhiOS identity contract (proposal)

## Decision

A **Phi account** is a stable, opaque principal from a dedicated identity provider (**PhiID**, proposed). **PhiMail** is the welcome/account and email experience for that principal. **PhiOS** keeps its own local authority and need not depend on either provider.

> An email address may be used to discover or sign into a Phi account, but the address is never the database primary key, permission key, tenant ID or proof of ownership.

## Identity model

```json
{
  "schema_version": "phi-account/0.1",
  "issuer": "https://example.invalid/phiid",
  "sub": "opaque-identity-provider-subject",
  "preferred_username": "example-user",
  "email": "example@example.invalid",
  "email_verified": false
}
```

These values are **illustrative only**, not issued credentials and not a live endpoint. Within an issuer, `sub` is the durable account identifier. Applications bind an account to the pair (`iss`, `sub`) rather than email or username; use provider-native pairwise subject handling as required.

PhiMail may eventually offer a Phi-hosted address such as `user@phi-field.com` **only after mail hosting, DNS, anti-abuse and deliverability are actually deployed**. Existing external email addresses and users without a mailbox must also be supported. A mailbox outage cannot be the only route to account recovery.

## Sign-in protocol

- Adopt an audited OpenID Connect provider (Keycloak is a candidate) rather than inventing password storage, token signing or an OAuth server.
- Use authorization code with PKCE S256 for browser and native clients; match registered redirect URIs exactly. Never use the implicit flow or resource-owner password grant.
- Support WebAuthn/passkeys and recovery codes; address loss-of-device and lost-mailbox recovery separately.
- Keep web session secrets server-side where applicable. Do not put refresh tokens or OAuth client secrets in a public static bundle.
- Issue short-lived, audience-specific access tokens with the least privileges; refresh/revocation and session termination belong to the IdP.
- Services validate issuer, signature/JWKS, audience, expiration, tenant and scopes. Never trust `email_verified` for resource authorization.
- Linking a local PhiOS profile to PhiID requires explicit owner action. Disconnecting must preserve an export/restore path and offline access.

## Responsibility split

| Action | Owner |
| --- | --- |
| Sign up, passkey enrollment, login, sessions, recovery | PhiID / audited OIDC provider |
| Mail client UX, compose, search, provider adapters | PhiMail |
| Eventual SMTP/IMAP mailboxes, delivery reputation | Optional dedicated mail infrastructure |
| Remote API authorization, object ownership, revocation checks | Each PhiCloud service / PhiShield gateway |
| Approval for local file, package, tool, agent or OS effects | PhiOS, separately from remote login |
| Human-reviewed account linking and sync permission | User-facing PhiOS consent flow |

## Example user journey (planned)

1. User opens PhiOS without internet: local tools continue working.
2. User voluntarily opens PhiMail / Phi Account and signs in via PhiID or creates an account.
3. PhiOS asks for narrowly scoped linkage to the identified (`iss`, `sub`).
4. User independently enables PhiVault backups and/or PhiSync on selected data, with clear retention/deletion controls.
5. Revoking the remote account stops remote sync; it does not revoke offline data ownership.

## Not yet implemented

There is no PhiID issuer, login endpoint, universal account, working `@phi-field.com` mailbox, verified domain mail routing or cross-device session in this repository. This document is an integration contract, not deployment evidence.

See [OAuth 2.0 Security Best Current Practice, RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html).
