"""Run the benchmark end to end and render the results (Markdown for humans, JSON for CI)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentwarden import __version__
from agentwarden.benchmark.datasets import BIPIA, INJECAGENT, Source, load_json, load_jsonl
from agentwarden.benchmark.suites import (
    AgentCase,
    AgentResult,
    CaseResult,
    DetectionResult,
    bipia_samples,
    injecagent_cases,
    injecagent_text_samples,
    run_agent,
    run_detection,
)

TRACKS = ("detection", "agent")


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


@dataclass
class BenchmarkReport:
    threshold: float
    sources: list[Source]
    detection: dict[str, DetectionResult] = field(default_factory=dict)
    agent: AgentResult | None = None
    limit: int | None = None

    # ----------------------------------------------------------------- headline numbers
    def detection_recall(self, dataset_prefix: str = "") -> float | None:
        results = [r for k, r in self.detection.items() if k.startswith(dataset_prefix)]
        tp, fn = sum(r.tp for r in results), sum(r.fn for r in results)
        return tp / (tp + fn) if tp + fn else None

    def detection_fpr(self) -> float | None:
        fp = sum(r.fp for r in self.detection.values())
        tn = sum(r.tn for r in self.detection.values())
        return fp / (fp + tn) if fp + tn else None

    # --------------------------------------------------------------------------- gates
    def check(
        self,
        *,
        min_recall: float | None = None,
        max_fpr: float | None = None,
        max_asr: float | None = None,
        min_utility: float | None = None,
    ) -> list[str]:
        """Human-readable failures for the given quality gates (empty: all passed)."""
        failures = []
        recall, fpr = self.detection_recall(), self.detection_fpr()
        if min_recall is not None and (recall is None or recall < min_recall):
            failures.append(f"detection recall {_pct(recall)} < {_pct(min_recall)}")
        if max_fpr is not None and (fpr is None or fpr > max_fpr):
            failures.append(f"false-positive rate {_pct(fpr)} > {_pct(max_fpr)}")
        if self.agent is not None:
            if max_asr is not None and self.agent.asr() > max_asr:
                failures.append(f"attack success rate {_pct(self.agent.asr())} > {_pct(max_asr)}")
            if min_utility is not None and self.agent.utility() < min_utility:
                failures.append(f"utility {_pct(self.agent.utility())} < {_pct(min_utility)}")
        elif max_asr is not None or min_utility is not None:
            failures.append("agent-track gates given but the agent track did not run")
        return failures

    # ---------------------------------------------------------------------------- JSON
    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "agentwarden_version": __version__,
            "threshold": self.threshold,
            "limit": self.limit,
            "datasets": [
                {"name": s.name, "repo": s.homepage, "commit": s.commit, "license": s.license}
                for s in self.sources
            ],
            "detection": {
                "recall": self.detection_recall(),
                "false_positive_rate": self.detection_fpr(),
                "datasets": {
                    name: {
                        "tp": r.tp,
                        "fn": r.fn,
                        "fp": r.fp,
                        "tn": r.tn,
                        "recall": r.recall,
                        "false_positive_rate": r.fpr,
                        "by_category": {
                            c: {"samples": t.total, "flagged": t.hits, "rate": t.rate}
                            for c, t in sorted(r.by_category.items())
                        },
                    }
                    for name, r in sorted(self.detection.items())
                },
            },
        }
        if self.agent is not None:
            agent = self.agent
            out["agent"] = {
                "policy": agent.policy,
                "cases": len(agent.cases),
                "attack_success_rate": agent.asr(),
                "attack_success_rate_without_tier_gate": agent.asr_without_tier_gate(),
                "utility": agent.utility(),
                "outcomes": _outcomes(agent.cases),
                "by_variant": _breakdown(agent, lambda r: r.case.variant),
                "by_kind": _breakdown(agent, lambda r: r.case.kind),
                "by_attack_type": _breakdown(agent, lambda r: r.case.attack_type),
            }
        return out

    # ------------------------------------------------------------------------ Markdown
    def to_markdown(self) -> str:
        lines = [
            "# AgentWarden prompt-injection benchmark",
            "",
            f"AgentWarden {__version__} · detection threshold {self.threshold}"
            + (f" · first {self.limit} cases per file" if self.limit else ""),
            "",
            "| Dataset | Commit | License |",
            "|---|---|---|",
            *[
                f"| [{s.name}]({s.homepage}) | `{s.commit[:12]}` | {s.license} |"
                for s in self.sources
            ],
        ]
        if self.agent is not None:
            agent = self.agent
            lines += [
                "",
                "## Agent track (InjecAgent, full gateway)",
                "",
                f"{len(agent.cases)} scenarios, policy `{agent.policy}`. An attack *succeeds* "
                "when every attacker tool call is allowed with no human involved.",
                "",
                "| Metric | Value |",
                "|---|---|",
                f"| Attack success rate | **{_pct(agent.asr())}** |",
                "| … if critical-tier approval didn't exist |"
                f" {_pct(agent.asr_without_tier_gate())} |",
                f"| Utility (user's own tool call allowed) | **{_pct(agent.utility())}** |",
                *[f"| Attacks {k} | {v} |" for k, v in _outcomes(agent.cases).items()],
                "",
                "| Slice | Cases | Attack success | Without tier gate |",
                "|---|---|---|---|",
            ]
            for title, key in (
                ("variant", lambda r: r.case.variant),
                ("kind", lambda r: r.case.kind),
                ("attack type", lambda r: r.case.attack_type),
            ):
                for name, group in agent.group(key).items():
                    lines.append(
                        f"| {title}: {name} | {len(group)} | {_pct(agent.asr(group))} |"
                        f" {_pct(agent.asr_without_tier_gate(group))} |"
                    )
        if self.detection:
            lines += [
                "",
                "## Detection track (injection detector on untrusted text)",
                "",
                f"Overall recall **{_pct(self.detection_recall())}**, false-positive rate on "
                f"benign documents **{_pct(self.detection_fpr())}**.",
                "",
                "| Dataset | Attacks | Recall | Benign | False positives |",
                "|---|---|---|---|---|",
            ]
            for name, r in sorted(self.detection.items()):
                lines.append(
                    f"| {name} | {r.tp + r.fn} | {_pct(r.recall)} | {r.fp + r.tn} | {_pct(r.fpr)} |"
                )
            lines += ["", "| Category | Samples | Flagged |", "|---|---|---|"]
            for name, r in sorted(self.detection.items()):
                for category, tally in sorted(r.by_category.items()):
                    lines.append(f"| {name}: {category} | {tally.total} | {_pct(tally.rate)} |")
        return "\n".join(lines) + "\n"


def _outcomes(cases: Sequence[CaseResult]) -> dict[str, int]:
    counts = {"succeeded": 0, "approval": 0, "denied": 0}
    for result in cases:
        counts[result.outcome] += 1
    return {
        "allowed (succeeded)": counts["succeeded"],
        "held for approval": counts["approval"],
        "denied": counts["denied"],
    }


def _breakdown(agent: AgentResult, key: Callable[[CaseResult], str]) -> dict[str, Any]:
    return {
        name: {
            "cases": len(group),
            "attack_success_rate": agent.asr(group),
            "attack_success_rate_without_tier_gate": agent.asr_without_tier_gate(group),
        }
        for name, group in agent.group(key).items()
    }


def load_injecagent(
    cache_dir: Path | None = None, *, offline: bool = False, limit: int | None = None
) -> list[AgentCase]:
    cases: list[AgentCase] = []
    for kind in ("dh", "ds"):
        for variant in ("base", "enhanced"):
            raw = load_json(f"injecagent/{kind}_{variant}", cache_dir, offline=offline)
            cases += injecagent_cases(raw[:limit], kind, variant)
    return cases


def run_benchmark(
    *,
    tracks: Sequence[str] = TRACKS,
    cache_dir: Path | None = None,
    threshold: float = 0.3,
    limit: int | None = None,
    offline: bool = False,
) -> BenchmarkReport:
    unknown = set(tracks) - set(TRACKS)
    if unknown:
        raise ValueError(f"unknown track(s): {', '.join(sorted(unknown))}")
    report = BenchmarkReport(threshold=threshold, sources=[INJECAGENT], limit=limit)
    cases = load_injecagent(cache_dir, offline=offline, limit=limit)
    if "detection" in tracks:
        report.sources = [BIPIA, INJECAGENT]
        contexts = {
            task: [
                str(row["context"])
                for row in load_jsonl(f"bipia/{task}", cache_dir, offline=offline)[:limit]
            ]
            for task in ("email", "table", "code")
        }
        text_attacks = load_json("bipia/text_attacks", cache_dir, offline=offline)
        code_attacks = load_json("bipia/code_attacks", cache_dir, offline=offline)
        samples = bipia_samples(contexts, text_attacks, code_attacks)
        samples += injecagent_text_samples(cases)
        report.detection = run_detection(samples, threshold=threshold)
    if "agent" in tracks:
        report.agent = run_agent(cases)
    return report
