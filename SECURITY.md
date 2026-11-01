# Security policy

AgentWarden is a security project, and reports are welcome.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting instead
(**Security → Report a vulnerability** on this repository). Include:

- affected version or commit, and configuration (policy, settings)
- steps to reproduce or a proof of concept
- impact: what an attacker gains (bypass, escalation, forgery, disclosure…)

You can expect an acknowledgement within a few days. Fixes are released as soon as practical, with
credit unless you prefer otherwise.

## Scope

In scope: authorization bypasses, token forgery or confusion, delegation escalation, approval
bypass or replay, audit-chain forgery that verification doesn't detect, secret leakage into
logs, and injection-detection bypasses that also defeat the **deterministic** controls (scope,
policy, taint, approvals). Pure detector evasion is useful too; please share samples so they can
join the evaluation corpus.

Out of scope: issues that require the signing key or database write access *and* the ability to
rebuild checkpoints; the demo credentials in `directory.yaml`; denial of service against a
deployment without rate limiting (a known gap).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Deployment hardening checklist

- [ ] Generate a persistent key: `agentwarden keygen`, then mount it read-only with mode `0600`
- [ ] Set a long random `AGENTWARDEN_ADMIN_KEY` (or leave it unset to disable admin routes)
- [ ] Replace the demo directory: no demo API keys, your own users, tools and trusted domains
- [ ] Terminate TLS in front of the service; never expose it on plain HTTP
- [ ] Keep token TTLs short (`AGENTWARDEN_DEFAULT_TOKEN_TTL`, default 900s)
- [ ] Export signed audit checkpoints (`GET /v1/audit/checkpoint`) to storage the service can't modify
- [ ] Run `agentwarden policy test` for your policy in CI
- [ ] Make tools *require* an allow decision (don't rely on agents choosing to call `authorize`)
- [ ] Enable the LLM judge only if sending untrusted content to the Anthropic API is acceptable
