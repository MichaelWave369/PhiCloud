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
