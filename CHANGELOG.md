# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **Approver console** at `/console`: approvers sign in with an API key or ID token, see each pending
  request with the user's original prompt, risk signals and evidence, redacted arguments, the agent
  chain and context sources, and approve or deny with a note. It never renders data as HTML, runs
  under a strict CSP, and blocks self-approval in the UI as well as the API. Approval records now
  store these review details (existing SQLite and Postgres databases are migrated on startup), and
  `GET /v1/me` reports the signed-in user.
- **PostgreSQL backend** (`AGENTWARDEN_DATABASE_URL`, `pip install 'agentwarden[postgres]'`): several
  AgentWarden instances can share tokens, revocations, the kill switch, approvals and the audit chain.
  Audit appends and schema creation are serialized across instances with advisory locks; approval
  consumption stays single-use under races. The storage test suite runs on both SQLite and Postgres,
  and CI has a Postgres 16 job. `docker-compose.ha.yml` runs two instances on one database.
- **Signing-key rotation**: a key ring (`AGENTWARDEN_SIGNING_KEY_DIR`) with one active key, retired
  keys that keep verifying tokens for one maximum token lifetime, and pruning that deletes retired
  private keys while keeping their public halves for audit checkpoints. The JWKS publishes every key
  that still verifies tokens. Running instances pick up rotations without a restart. Managed with
  `agentwarden keys rotate|list|prune` or `/v1/admin/keys`, and rotations are audited.
- **OIDC sign-in and RFC 8693 token exchange** (`POST /v1/token/exchange`): users exchange an ID
  token from their identity provider for a scoped agent token. Verification accepts asymmetric
  algorithms only, checks issuer, audience, `azp` and expiry, discovers and rotates IdP keys (with a
  rate-limited refresh), and requires a verified email when matching users by email. Approvers can
  sign in with an ID token too, and the demo API keys can be turned off (`AGENTWARDEN_API_KEYS=false`).
  Includes `examples/dev_idp.py`, a throwaway local IdP for trying it out.
- **MCP proxy mode** (`agentwarden mcp-proxy -- <server command>`): wraps any stdio MCP server and
  authorizes every `tools/call`. Denied and pending calls never reach the server and come back as
  MCP tool errors that explain why. Approvals work without client support (retry the same call once
  approved). Tool results are recorded as untrusted context, and a YAML mapping translates MCP tool
  names and can hide unmapped tools from `tools/list`. Works against a remote service
  (`AGENTWARDEN_TOKEN`) or an in-process gateway (`--local`).

## [0.1.0] - 2026-11-01

First MVP release.

### Added
- **Identity**: Ed25519 (`EdDSA`) agent tokens with RFC 8693 `sub`/`act` delegation chains, scope
  attenuation, concrete-only requested scopes, JWKS, revocation by token, ancestor and subject,
  agent registry with trust tiers, scope ceilings and a kill switch.
- **Policy**: deny-by-default YAML policy engine with `all`/`any`/`not`, 16 operators,
  deny > default-deny > approval > allow, and a policy-as-code test runner. Default policy with
  16 rules and a 23-case suite.
- **Risk engine**: injection detection with de-obfuscation (Unicode tags, zero-width, bidi,
  homoglyphs, full-width, base64), destination taint tracking, secret, exfiltration and
  behavioral detectors, per-detector aggregation with a context-only cap, and an optional Claude judge.
- **Governance**: bound single-use approvals with separation of duties, a hash-chained audit log
  with signed checkpoints, and a least-privilege analyzer.
- **Interfaces**: FastAPI service, Python SDK (`WardenClient`, `LocalWarden`, `@guard`), CLI
  (`serve`, `keygen`, `hash-key`, `policy`, `audit`, `analyze`, `eval`, `demo`), Docker image.
- **Quality**: 219 tests (97% coverage), CI on Python 3.11–3.13, bandit, Trojan Source scan,
  detection quality gate (precision 0.909, recall 0.952, FPR 0.087 on the bundled corpus).
