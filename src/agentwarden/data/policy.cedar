// AgentWarden default policy, ported to Cedar (https://www.cedarpolicy.com).
// Same rules and rule IDs as data/policy.yaml, and the same test suite passes against both
// (agentwarden policy test --backend cedar tests/policy/default_policy_cases.yaml).
//
// Request shape (see agentwarden.policy.backends.cedar_request):
//   principal  Agent::"<id>"     { trust_tier, owner }
//   action     Action::"call"             may this call happen at all?
//              Action::"call_unattended"  may it happen without a human?  (forbid = approval)
//   resource   Tool::"<name>"     { scope, risk, side_effect }
//   context    { user, actor_chain, delegation, args, risk, facts, token, time }
//              risk.score is a decimal; risk.score_pct is the same as an integer 0-100.
//
// Cedar skips a policy that errors during evaluation (for a forbid, that would fail open), so
// AgentWarden denies any request whose evaluation reports an error. Guard optional attributes
// with `has`. Unlike the YAML engine, string comparisons here are case-sensitive.

// ------------------------------------------------------------------------------ hard denies
@id("deny-critical-risk")
@description("Risk engine is highly confident this call is malicious or hijacked.")
forbid (principal, action == Action::"call", resource)
when { context.risk.score_pct >= 85 };

@id("deny-hijacked-exfiltration")
@description("An outbound destination came from untrusted content that also contains instructions aimed at the model.")
forbid (principal, action == Action::"call", resource)
when {
  resource.side_effect == "external" &&
  context.risk.signals.contains("tainted_external_destination") &&
  context.risk.detectors.containsAny(["injection", "llm_judge"])
};

@id("deny-secret-exfiltration")
@description("Credentials or keys must never be sent outside the organization.")
forbid (principal, action == Action::"call", resource)
when {
  resource.side_effect == "external" &&
  context.risk.signals.contains("secret_in_arguments")
};

@id("deny-untrusted-agents-side-effects")
@description("Untrusted-tier agents are read-only.")
forbid (principal, action == Action::"call", resource)
when {
  principal has trust_tier && principal.trust_tier == "untrusted" &&
  ["write", "external"].contains(resource.side_effect)
};

@id("deny-deep-delegation-external")
@description("Agents two or more delegation hops away from the user may not act externally.")
forbid (principal, action == Action::"call", resource)
when { context.delegation.depth >= 2 && resource.side_effect == "external" };

// ----------------------------------------------------------------------------------- allows
@id("allow-read-only-tools")
@description("Reading is allowed when the token carries the tool's scope.")
permit (principal, action == Action::"call", resource)
when { ["none", "read"].contains(resource.side_effect) };

@id("allow-email")
@description("Agents may send email (external recipients require approval below).")
permit (principal, action == Action::"call", resource == Tool::"send_email")
when { !context.facts.recipients.isEmpty() };

@id("allow-http")
@description("Outbound HTTP is allowed (writes to external hosts require approval below).")
permit (principal, action == Action::"call", resource == Tool::"http_request");

@id("allow-workspace-writes")
@description("File writes are confined to the shared workspace (paths are normalized).")
permit (principal, action == Action::"call", resource == Tool::"write_file")
when { context.facts has path && context.facts.path like "/workspace/*" };

@id("allow-crm-writes-privileged")
@description("Only privileged agents may modify customer records.")
permit (principal, action == Action::"call", resource == Tool::"update_crm")
when { principal has trust_tier && principal.trust_tier == "privileged" };

@id("allow-payments-privileged")
@description("Only privileged agents may initiate payments, capped at 10,000.")
permit (principal, action == Action::"call", resource == Tool::"transfer_funds")
when {
  principal has trust_tier && principal.trust_tier == "privileged" &&
  context.args has amount && context.args.amount <= 10000
};

// --------------------------------------------------------------------------- approval gates
// A call that is permitted runs unattended unless one of these forbids it.
@id("unattended")
@description("Permitted calls run without a human unless an approval gate applies.")
permit (principal, action == Action::"call_unattended", resource);

@id("approve-critical-tools")
@description("Critical tools always need a human in the loop.")
forbid (principal, action == Action::"call_unattended", resource)
when { resource.risk == "critical" };

@id("approve-external-email")
@description("Email leaving the organization needs approval.")
forbid (principal, action == Action::"call_unattended", resource == Tool::"send_email")
when { !context.facts.external_recipients.isEmpty() };

@id("approve-outbound-http-writes")
@description("Sending data to external hosts needs approval.")
forbid (principal, action == Action::"call_unattended", resource == Tool::"http_request")
when {
  context.args has method &&
  ["POST", "PUT", "PATCH", "DELETE", "post", "put", "patch", "delete"].contains(context.args.method) &&
  !context.facts.external_domains.isEmpty()
};

@id("approve-tainted-destination")
@description("The destination came from content the agent read, not from the user. A human confirms it.")
forbid (principal, action == Action::"call_unattended", resource)
when { context.risk.signals.contains("tainted_external_destination") };

@id("approve-after-injection")
@description("The agent read content with instructions aimed at it, or the action was requested by that content. A human confirms side effects.")
forbid (principal, action == Action::"call_unattended", resource)
when {
  context.risk.detectors.containsAny(["injection", "provenance"]) &&
  ["write", "external"].contains(resource.side_effect)
};

@id("approve-elevated-risk")
@description("Elevated risk score; ask a human before doing anything with side effects.")
forbid (principal, action == Action::"call_unattended", resource)
when {
  context.risk.score_pct >= 50 &&
  ["write", "external"].contains(resource.side_effect)
};
