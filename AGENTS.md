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
