# Policy backends: YAML, Cedar and OPA

AgentWarden decides every tool call in two stages. **Deterministic checks** always run first:
valid token, DPoP binding, enabled agents in the chain, known tool, and the tool's scope in the
token. Then a **policy backend** decides what is appropriate *in context*: `allow`, `deny` or
`require_approval`. A backend can only make decisions stricter. It never grants a scope the token
doesn't carry.

| Backend | Language | Runs | Good for |
|---|---|---|---|
| `yaml` (default) | AgentWarden's YAML rules ([POLICY_REFERENCE.md](POLICY_REFERENCE.md)) | in-process | Getting started; no extra moving parts |
| `cedar` | [Cedar](https://www.cedarpolicy.com) | in-process (`cedarpy`) | Teams standardizing on Cedar (e.g. Amazon Verified Permissions); analyzable policies |
| `opa` | [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) | OPA server (usually a sidecar) | Organizations already running OPA; central policy bundles and decision logs |

The default policy ships in all three languages, with the same rules and rule IDs:
[`policy.yaml`](../src/agentwarden/data/policy.yaml), [`policy.cedar`](../src/agentwarden/data/policy.cedar)
and [`policy.rego`](../src/agentwarden/data/policy.rego). The same test suite runs against each:

```bash
agentwarden policy test tests/policy/default_policy_cases.yaml                     # yaml
agentwarden policy test --backend cedar tests/policy/default_policy_cases.yaml     # policy.cedar
agentwarden policy test --backend opa --opa-url http://localhost:8181 tests/policy/default_policy_cases.yaml
```

CI runs all three, the OPA one against a real OPA server, so the ports can't drift apart.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AGENTWARDEN_POLICY_BACKEND` | `yaml` | `yaml`, `cedar` or `opa` |
| `AGENTWARDEN_POLICY_PATH` | bundled policy | The `.yaml` or `.cedar` file (Cedar uses the bundled `policy.cedar` unless set) |
| `AGENTWARDEN_OPA_URL` | | OPA base URL, e.g. `http://localhost:8181` |
| `AGENTWARDEN_OPA_PATH` | `agentwarden/authz/decision` | Path of the decision rule under `/v1/data/` |
| `AGENTWARDEN_OPA_TOKEN` | | Bearer token, if OPA's API requires authentication |
| `AGENTWARDEN_OPA_TIMEOUT` | `2.0` | Seconds before failing closed |

Cedar needs `pip install 'agentwarden[cedar]'` (included in the Docker image).

## The evaluation context

Every backend receives the same context. It's the `input` document for OPA, and it's mapped onto
principal, action, resource and context for Cedar (below):

```json
{
  "user":  { "id": "alice", "roles": ["employee", "finance"] },
  "agent": { "id": "inbox-assistant", "owner": "alice", "trust_tier": "standard" },
  "actor_chain": ["inbox-assistant"],
  "delegation": { "depth": 0 },
  "tool":  { "name": "send_email", "scope": "email:send", "risk": "high", "side_effect": "external" },
  "args":  { "to": ["dana@vendor.example"], "body": "..." },
  "risk":  { "score": 0.62, "level": "high", "signals": ["tainted_external_destination"], "detectors": ["taint"] },
  "facts": { "recipients": ["dana@vendor.example"], "external_recipients": ["dana@vendor.example"],
             "urls": [], "domains": ["vendor.example"], "external_domains": ["vendor.example"],
             "path": null, "has_untrusted_context": true, "args_size": 61 },
  "token": { "task": "triage inbox", "scopes": ["email:read", "email:send"] },
  "time":  { "hour": 14, "weekday": "tuesday" }
}
```

## Cedar

Cedar only permits or forbids, while AgentWarden has a third outcome, *needs a human*. Each call
is therefore asked two questions:

| Request | Meaning | Result |
|---|---|---|
| `Action::"call"` | May this call happen at all? | forbid, or no permit → **deny** |
| `Action::"call_unattended"` | May it happen *without a human*? | forbid → **require_approval** |

Approval gates are `forbid` rules on `call_unattended`, and one blanket `permit` says everything
else can run unattended:

```cedar
@id("approve-external-email")
@description("Email leaving the organization needs approval.")
forbid (principal, action == Action::"call_unattended", resource == Tool::"send_email")
when { !context.facts.external_recipients.isEmpty() };
```

The request has this shape:

- **principal** `Agent::"<id>"` with `trust_tier` and `owner`
- **resource** `Tool::"<name>"` with `scope`, `risk` and `side_effect`
- **context**: everything else, as above

Rules are named by `@id` and explained by `@description`. Those show up in decisions, the audit
log and the approver console.

Things that differ from the YAML engine:

- **No floats.** `risk.score` is a Cedar `decimal` (compare with `.greaterThanOrEqual(decimal("0.85"))`),
  and `risk.score_pct` is the same score as an integer 0–100 (`context.risk.score_pct >= 85`), which
  is easier to get right. Fractional numbers in `args` arrive as `decimal` too.
- **No null.** Missing values are left out, so guard optional attributes with `has`
  (`context.facts has path && ...`).
- **Case-sensitive** string comparisons.
- **Evaluation errors fail closed.** Cedar skips a policy that errors at evaluation. For a `forbid`
  that would mean failing open (comparing a decimal with `>=` is enough to do it). AgentWarden
  denies any request whose evaluation reports an error, and the reason says so.
- **Explanations on deny** list the deciding `forbid` rules only. The YAML engine also lists
  approval gates that matched.

## OPA

AgentWarden sends `POST {AGENTWARDEN_OPA_URL}/v1/data/{AGENTWARDEN_OPA_PATH}` with
`{"input": <context>}`. The rule at that path must evaluate to:

```json
{ "decision": "allow" | "deny" | "require_approval", "rules": ["rule-id", ...], "reasons": ["...", ...] }
```

[`policy.rego`](../src/agentwarden/data/policy.rego) builds this from three partial sets
(`deny`, `allow`, `approve`) with the YAML engine's combining algorithm: any deny wins, nothing
allowed means deny, and an allowed call with an approval gate needs a human. Extend it by adding
rules to those sets.

```bash
opa run --server --addr localhost:8181 policy.rego
AGENTWARDEN_POLICY_BACKEND=opa AGENTWARDEN_OPA_URL=http://localhost:8181 agentwarden serve
```

**Fails closed.** Each of these produces `deny`, with the cause in the reason and the audit log:

- OPA is unreachable or slower than `AGENTWARDEN_OPA_TIMEOUT`
- OPA answers non-200 or invalid JSON
- the decision is undefined (wrong path, or the policy isn't loaded)
- the decision is an unknown value or has the wrong shape

Run OPA next to AgentWarden (a sidecar or `localhost`). Use TLS and `AGENTWARDEN_OPA_TOKEN` if it's
reachable over a network: whoever can answer for OPA decides every tool call.

## Choosing

- Stay on **YAML** unless you have a reason not to. It has no extra dependencies, and its policy
  test suites and error messages are the most direct.
- Use **Cedar** to share a policy language with the rest of your authorization (Cedar is
  analyzable: you can prove properties like "untrusted agents never write"), or to manage agent
  permissions in Amazon Verified Permissions.
- Use **OPA** to manage agent policy with the rest of your OPA estate (bundles, decision logs, a
  policy team that writes Rego). Note that every tool call then waits on a network hop.
