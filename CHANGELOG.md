# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
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
