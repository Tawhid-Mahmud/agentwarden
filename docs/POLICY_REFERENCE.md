# Policy reference

Policies are YAML documents evaluated for every tool call that passes AgentWarden's deterministic
checks (valid token, enabled agents, known tool, scope held and still entitled). The bundled
policy lives at [`src/agentwarden/data/policy.yaml`](../src/agentwarden/data/policy.yaml). Point
`AGENTWARDEN_POLICY_PATH` at your own file.

## Document structure

```yaml
version: 1
description: Optional text
default_effect: deny          # the only allowed value; stated for readability
rules:
  - id: allow-workspace-writes          # unique; [a-z0-9][a-z0-9_.-]*
    description: Shown in decision reasons
    effect: allow                       # allow | deny | require_approval
    agents: ["*"]                       # glob(s) on the acting agent id      (default ["*"])
    users:  ["*"]                       # glob(s) on the user id              (default ["*"])
    tools:  [write_file]                # glob(s) on the tool name            (default ["*"])
    when:                               # conditions, ANDed                   (default: always)
      - { field: facts.path, op: glob, value: "/workspace/*" }
```

Validation is strict: unknown keys, malformed field paths, wrongly typed values, invalid regexes,
duplicate ids and policies without any `allow` rule are rejected at load time.

## Combining algorithm

1. Any matching **deny** → **deny**.
2. No matching **allow** → **deny** (default deny).
3. A matching **allow** *and* a matching **require_approval** → **require approval**.
4. Otherwise → **allow**.

`require_approval` rules are an additional gate on actions that some allow rule permits. They
never grant access on their own, so a human approval can't unlock something the policy forbids.

## Conditions

A condition is either a leaf `{field, op, value}` or exactly one combinator:

```yaml
when:
  - any:
      - { field: risk.detectors, op: contains, value: injection }
      - not: { field: agent.trust_tier, op: eq, value: privileged }
  - all:
      - { field: args.amount, op: gt, value: 100 }
      - { field: args.currency, op: in, value: [USD, EUR] }
```

### Operators

| Operator | Value type | Meaning |
|---|---|---|
| `eq`, `ne` | any | Equality (strings casefolded; lists compared element-wise) |
| `in`, `not_in` | list | Membership. For a list field: `in` = subset, `not_in` = disjoint |
| `contains`, `not_contains` | scalar | List field contains the value, or string field contains the substring |
| `starts_with`, `ends_with`, `glob` | string | String matching; for a list field **every** element must match |
| `regex` | string | Python `re.search`, applied **as written** (use `(?i)` for case-insensitive) |
| `gt`, `gte`, `lt`, `lte` | number | Numeric comparison (booleans and numeric strings never match) |
| `exists` | bool | Field is present and not null |
| `empty` | bool | Field is missing, null, or an empty string/list/map |

Semantics to keep in mind:

- **Missing fields never satisfy a comparison**, including `ne`, `not_in` and `not_contains`. Use
  `exists`/`empty` to test presence explicitly.
- **String comparisons ignore case** for every operator except `regex`, so `@EVIL.example` can't
  dodge an `ends_with: "@evil.example"` deny.
- **An empty list never matches** string operators, so "all recipients are internal" is false when
  there are no recipients.

## Evaluation context

| Field | Example | Notes |
|---|---|---|
| `user.id`, `user.roles` | `alice`, `[employee, finance]` | Current directory values |
| `agent.id`, `agent.owner`, `agent.trust_tier` | `inbox-assistant`, `alice`, `standard` | Acting (outermost) agent |
| `actor_chain` | `[summarizer, inbox-assistant]` | Acting agent first, root agent last |
| `delegation.depth` | `1` | `0` = token issued directly by the user |
| `tool.name`, `tool.scope`, `tool.risk`, `tool.side_effect` | `send_email`, `email:send`, `high`, `external` | From the directory |
| `args.*` | `args.to`, `args.amount` | Raw call arguments |
| `facts.recipients`, `facts.external_recipients` | `[partner@contoso.example]` | Emails under `to/cc/bcc/recipient(s)/reply_to/email` |
| `facts.urls`, `facts.domains`, `facts.external_domains` | `[collector.evil.example]` | URLs anywhere in the arguments |
| `facts.path` | `/etc/passwd` | `args.path`/`file`/`filename`/`filepath`, percent-decoded, normalized |
| `facts.has_untrusted_context`, `facts.args_size` | `true`, `412` | |
| `risk.score`, `risk.level` | `0.94`, `critical` | See [ARCHITECTURE.md](ARCHITECTURE.md#risk-scoring) |
| `risk.signals` | `[tainted_external_destination, …]` | Signal names |
| `risk.detectors` | `[injection, taint]` | Detectors that produced signals |
| `token.task`, `token.scopes` | `triage inbox`, `[email:read]` | |
| `time.hour`, `time.weekday` | `14`, `monday` | UTC |

## Recipes

Business hours only for payments:

```yaml
- id: deny-payments-after-hours
  effect: deny
  tools: [transfer_funds]
  when:
    - any:
        - { field: time.hour, op: lt, value: 8 }
        - { field: time.hour, op: gte, value: 18 }
        - { field: time.weekday, op: in, value: [saturday, sunday] }
```

Contractors' agents are read-only:

```yaml
- id: deny-contractor-side-effects
  effect: deny
  when:
    - { field: user.roles, op: contains, value: contractor }
    - { field: tool.side_effect, op: in, value: [write, external] }
```

Only the root agent may send email:

```yaml
- id: deny-delegated-email
  effect: deny
  tools: [send_email]
  when:
    - { field: delegation.depth, op: gt, value: 0 }
```

Tie actions to the declared task:

```yaml
- id: approve-email-outside-task
  effect: require_approval
  tools: [send_email]
  when:
    - not: { field: token.task, op: regex, value: "(?i)email|inbox|reply" }
```

## Testing policies

Write YAML cases next to your policy and run them in CI:

```yaml
policy: ../policy.yaml
cases:
  - name: contractor agents can't write
    input:
      user: { id: carol, roles: [contractor] }
      tool: { name: write_file, side_effect: write }
      facts: { path: /workspace/x.md }
    expect: deny
    expect_rules: [deny-contractor-side-effects]
```

```bash
agentwarden policy validate path/to/policy.yaml
agentwarden policy test path/to/cases.yaml
```

Missing context fields are filled with defaults, so cases only need the fields that matter.
