"""Least-privilege analyzer: compares what agents *may* do with what they *actually* do.

Inspired by cloud IAM "unused access" analyzers. It reads the audit log and the registry and
produces findings such as unused scopes, wildcard grants, dormant agents, high deny rates and
repeated exposure to prompt injection.
"""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from agentwarden.audit import AUTHZ_EVENT, AuditLog
from agentwarden.directory import Directory
from agentwarden.identity.registry import AgentRegistry
from agentwarden.identity.scopes import is_wildcard, scope_covers
from agentwarden.models import Agent, RiskLevel, TrustTier

Severity = Literal["low", "medium", "high"]
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class Finding:
    severity: Severity
    code: str
    agent_id: str
    message: str
    recommendation: str


@dataclass
class AgentUsage:
    agent_id: str
    enabled: bool
    trust_tier: str
    scope_ceiling: list[str]
    used_scopes: list[str]
    unused_scopes: list[str]
    decisions: dict[str, int]
    injection_exposures: int
    last_seen: str | None


@dataclass
class AnalyzerReport:
    generated_at: str
    window_days: int
    agents: list[AgentUsage] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_markdown(self) -> str:
        lines = [
            "# AgentWarden least-privilege report",
            "",
            f"Generated {self.generated_at} · window: last {self.window_days} days",
            "",
            "| Agent | Tier | Enabled | Allow / Approval / Deny | Unused scopes |",
            "|---|---|---|---|---|",
        ]
        for a in self.agents:
            d = a.decisions
            counts = f"{d.get('allow', 0)} / {d.get('require_approval', 0)} / {d.get('deny', 0)}"
            unused = ", ".join(f"`{s}`" for s in a.unused_scopes) or "none"
            enabled = "yes" if a.enabled else "no"
            lines.append(f"| `{a.agent_id}` | {a.trust_tier} | {enabled} | {counts} | {unused} |")
        lines += ["", f"## Findings ({len(self.findings)})", ""]
        if not self.findings:
            lines.append("No findings. Every agent is using what it was granted.")
        for f in self.findings:
            lines.append(f"- **{f.severity.upper()}** `{f.code}` `{f.agent_id}`: {f.message}  ")
            lines.append(f"  _Recommendation:_ {f.recommendation}")
        return "\n".join(lines) + "\n"


class LeastPrivilegeAnalyzer:
    def __init__(
        self,
        registry: AgentRegistry,
        audit: AuditLog,
        directory: Directory,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._registry = registry
        self._audit = audit
        self._directory = directory
        self._clock = clock

    def analyze(self, window_days: int = 30) -> AnalyzerReport:
        now = self._clock()
        since = now - window_days * 86_400
        report = AnalyzerReport(
            generated_at=datetime.fromtimestamp(now, UTC).isoformat(timespec="seconds"),
            window_days=window_days,
        )
        for agent in self._registry.list():
            events = self._audit.query(
                agent_id=agent.id, event_type=AUTHZ_EVENT, since=since, limit=100_000
            )
            decisions = Counter(e.decision or "unknown" for e in events)
            used: set[str] = set()
            exposures = 0
            for event in events:
                tool = self._directory.get_tool(event.tool or "")
                if tool and event.decision == "allow":
                    used.add(tool.scope)
                detectors = event.data.get("risk", {}).get("detectors", [])
                if "injection" in detectors or "llm_judge" in detectors:
                    exposures += 1
            concrete = [s for s in agent.scope_ceiling if not is_wildcard(s)]
            unused = sorted(s for s in concrete if s not in used)
            usage = AgentUsage(
                agent_id=agent.id,
                enabled=agent.enabled,
                trust_tier=agent.trust_tier.value,
                scope_ceiling=list(agent.scope_ceiling),
                used_scopes=sorted(used),
                unused_scopes=unused,
                decisions=dict(decisions),
                injection_exposures=exposures,
                last_seen=events[0].ts.isoformat(timespec="seconds") if events else None,
            )
            report.agents.append(usage)
            report.findings.extend(self._findings(agent, usage, len(events), window_days))
        report.findings.sort(key=lambda f: (_SEVERITY_ORDER[f.severity], f.agent_id, f.code))
        return report

    def _findings(
        self, agent: Agent, usage: AgentUsage, total: int, window_days: int
    ) -> list[Finding]:
        findings: list[Finding] = []

        def add(severity: Severity, code: str, message: str, recommendation: str) -> None:
            findings.append(Finding(severity, code, agent.id, message, recommendation))

        if total == 0:
            if agent.enabled:
                add(
                    "medium",
                    "DORMANT_AGENT",
                    f"no activity in the last {window_days} days.",
                    f"Disable the agent until it is needed (POST /v1/agents/{agent.id}/disable).",
                )
            return findings
        if usage.unused_scopes:
            unused = ", ".join(usage.unused_scopes)
            add(
                "medium",
                "UNUSED_SCOPES",
                f"{len(usage.unused_scopes)} granted scope(s) never used: {unused}.",
                "Remove them from the agent's scope ceiling.",
            )
        for scope in agent.scope_ceiling:
            if is_wildcard(scope):
                matching = [s for s in usage.used_scopes if scope_covers(scope, s)]
                suggestion = ", ".join(matching) if matching else "(no matching scope used)"
                add(
                    "medium",
                    "WILDCARD_SCOPE",
                    f"ceiling contains wildcard `{scope}`.",
                    f"Replace it with the concrete scopes actually used: {suggestion}.",
                )
        denies = usage.decisions.get("deny", 0)
        if total >= 5 and denies / total >= 0.3:
            add(
                "high",
                "HIGH_DENY_RATE",
                f"{denies} of {total} requests denied ({denies / total:.0%}).",
                "Investigate: the agent is misconfigured, probing, or steered by injected content.",
            )
        if usage.injection_exposures:
            add(
                "high",
                "INJECTION_EXPOSURE",
                f"prompt-injection content was present in {usage.injection_exposures} request(s).",
                "Review the agent's data sources and keep its tool access minimal.",
            )
        if agent.trust_tier is TrustTier.PRIVILEGED:
            sensitive = {
                t.scope
                for t in self._directory.tools.values()
                if t.risk.rank >= RiskLevel.HIGH.rank
            }
            if not sensitive & set(usage.used_scopes):
                add(
                    "low",
                    "UNNEEDED_PRIVILEGED_TIER",
                    "privileged tier but no high-risk tool was used.",
                    "Downgrade the agent to the standard tier.",
                )
        return findings
