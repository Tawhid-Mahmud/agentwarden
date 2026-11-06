# AgentWarden default policy, ported to Rego for Open Policy Agent.
# Same rules and rule IDs as data/policy.yaml; the same test suite passes against both
# (agentwarden policy test --backend opa --opa-url http://localhost:8181 ...).
#
#   opa run --server --addr localhost:8181 policy.rego
#   AGENTWARDEN_POLICY_BACKEND=opa AGENTWARDEN_OPA_URL=http://localhost:8181 agentwarden serve
#
# AgentWarden POSTs the evaluation context as `input` to /v1/data/agentwarden/authz/decision and
# expects {"decision": "allow" | "deny" | "require_approval", "rules": [...], "reasons": [...]}.
# An undefined or malformed decision is treated as deny.
#
# Combining algorithm, as in the YAML engine: any deny wins; nothing allowed means deny; an
# allowed call that matches an approval gate needs a human.

package agentwarden.authz

import rego.v1

side_effecting if input.tool.side_effect in {"write", "external"}

# ------------------------------------------------------------------------------ hard denies
deny contains "deny-critical-risk" if {
	input.risk.score >= 0.85
	not provenance_only
}

# Evidence that only says where the call came from is ambiguous ("reply to the sender"):
# a human decides instead.
provenance_only if {
	some detector in input.risk.detectors
	detector in {"taint", "provenance"}
	not hard_evidence
}

hard_evidence if {
	some detector in input.risk.detectors
	detector in {"injection", "secrets", "llm_judge"}
}

hard_evidence if "tainted_destination_with_data" in input.risk.signals

deny contains "deny-data-to-tainted-destination" if {
	"tainted_destination_with_data" in input.risk.signals
}

deny contains "deny-hijacked-exfiltration" if {
	input.tool.side_effect == "external"
	"tainted_external_destination" in input.risk.signals
	some detector in input.risk.detectors
	detector in {"injection", "llm_judge"}
}

deny contains "deny-secret-exfiltration" if {
	input.tool.side_effect == "external"
	"secret_in_arguments" in input.risk.signals
}

deny contains "deny-untrusted-agents-side-effects" if {
	input.agent.trust_tier == "untrusted"
	side_effecting
}

deny contains "deny-deep-delegation-external" if {
	input.delegation.depth >= 2
	input.tool.side_effect == "external"
}

# ----------------------------------------------------------------------------------- allows
allow contains "allow-read-only-tools" if input.tool.side_effect in {"none", "read"}

allow contains "allow-email" if {
	input.tool.name == "send_email"
	count(input.facts.recipients) > 0
}

allow contains "allow-http" if input.tool.name == "http_request"

allow contains "allow-workspace-writes" if {
	input.tool.name == "write_file"
	startswith(input.facts.path, "/workspace/")
}

allow contains "allow-crm-writes-privileged" if {
	input.tool.name == "update_crm"
	input.agent.trust_tier == "privileged"
}

allow contains "allow-payments-privileged" if {
	input.tool.name == "transfer_funds"
	input.agent.trust_tier == "privileged"
	input.args.amount <= 10000
}

# --------------------------------------------------------------------------- approval gates
approve contains "approve-critical-tools" if input.tool.risk == "critical"

approve contains "approve-external-email" if {
	input.tool.name == "send_email"
	count(input.facts.external_recipients) > 0
}

approve contains "approve-outbound-http-writes" if {
	input.tool.name == "http_request"
	upper(input.args.method) in {"POST", "PUT", "PATCH", "DELETE"}
	count(input.facts.external_domains) > 0
}

approve contains "approve-tainted-destination" if {
	"tainted_external_destination" in input.risk.signals
}

approve contains "approve-after-injection" if {
	side_effecting
	some detector in input.risk.detectors
	detector in {"injection", "provenance"}
}

approve contains "approve-elevated-risk" if {
	input.risk.score >= 0.5
	side_effecting
}

# --------------------------------------------------------------------------------- decision
matched := sort((deny | allow) | approve)

decision := {
	"decision": "deny",
	"rules": matched,
	"reasons": [sprintf("denied by rule '%s'", [id]) | some id in sort(deny)],
} if {
	count(deny) > 0
} else := {
	"decision": "deny",
	"rules": matched,
	"reasons": ["no policy rule allows this request (default deny)"],
} if {
	count(allow) == 0
} else := {
	"decision": "require_approval",
	"rules": matched,
	"reasons": [sprintf("human approval required by rule '%s'", [id]) | some id in sort(approve)],
} if {
	count(approve) > 0
} else := {
	"decision": "allow",
	"rules": matched,
	"reasons": [sprintf("allowed by rule '%s'", [id]) | some id in sort(allow)],
}
