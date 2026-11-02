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
    BenignOutcome,
    BenignResult,
    CaseResult,
    DetectionResult,
    benign_cases,
    bipia_samples,
    injecagent_cases,
    injecagent_text_samples,
    run_agent,
    run_benign,
    run_detection,
)

TRACKS = ("detection", "agent")
SPLITS = ("all", "dev", "test")


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{100 * value:.1f}%"


@dataclass
class BenchmarkReport:
    threshold: float
    sources: list[Source]
    detection: dict[str, DetectionResult] = field(default_factory=dict)
    agent: AgentResult | None = None
    benign: BenignResult | None = None
    limit: int | None = None
    split: str = "all"

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
        max_false_alarms: float | None = None,
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
        if max_false_alarms is not None:
            rate = self.benign.false_alarm_rate() if self.benign else None
            if rate is None or rate > max_false_alarms:
                failures.append(
                    f"benign-action false alarms {_pct(rate)} > {_pct(max_false_alarms)}"
                )
        return failures

    # ---------------------------------------------------------------------------- JSON
    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "agentwarden_version": __version__,
            "threshold": self.threshold,
            "limit": self.limit,
            "split": self.split,
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
        if self.benign is not None:
            benign = self.benign
            out["benign_actions"] = {
                "cases": len(benign.outcomes),
                "false_alarm_rate": benign.false_alarm_rate(),
                "allowed_rate": benign.allowed_rate(),
                "by_phrasing_and_document": {
                    name: {"cases": len(group), "false_alarm_rate": benign.false_alarm_rate(group)}
                    for name, group in _benign_groups(benign).items()
                },
            }
        return out

    # ------------------------------------------------------------------------ Markdown
    def to_markdown(self) -> str:
        lines = [
            "# AgentWarden prompt-injection benchmark",
            "",
            f"AgentWarden {__version__} · detection threshold {self.threshold}"
            + (f" · {self.split} split" if self.split != "all" else "")
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
        if self.benign is not None:
            benign = self.benign
            lines += [
                "",
                "### Benign actions (false alarms)",
                "",
                f"{len(benign.outcomes)} calls the user explicitly asked for, made after reading"
                " a document. A *false alarm* is a call the risk engine holds or denies"
                " (critical-tier approval doesn't count)."
                f" Overall: **{_pct(benign.false_alarm_rate())}**.",
                "",
                "| Phrasing / document | Calls | False alarms |",
                "|---|---|---|",
                *[
                    f"| {name} | {len(group)} | {_pct(benign.false_alarm_rate(group))} |"
                    for name, group in _benign_groups(benign).items()
                ],
            ]
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


def _benign_groups(benign: BenignResult) -> dict[str, list[BenignOutcome]]:
    labels = {"bipia": "real email (BIPIA)", "work": "work email with requests"}
    return benign.group(lambda o: f"{o.case.phrasing}, {labels[o.case.document_source]}")


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
    cache_dir: Path | None = None,
    *,
    offline: bool = False,
    limit: int | None = None,
    split: str = "all",
) -> list[AgentCase]:
    cases: list[AgentCase] = []
    for kind in ("dh", "ds"):
        for variant in ("base", "enhanced"):
            raw = load_json(f"injecagent/{kind}_{variant}", cache_dir, offline=offline)
            cases += injecagent_cases(raw[:limit], kind, variant)
    return [c for c in cases if split == "all" or c.split == split]


def run_benchmark(
    *,
    tracks: Sequence[str] = TRACKS,
    cache_dir: Path | None = None,
    threshold: float = 0.3,
    limit: int | None = None,
    offline: bool = False,
    split: str = "all",
) -> BenchmarkReport:
    """Run the benchmark. ``split="dev"`` uses BIPIA's training files and the dev half of
    InjecAgent (for developing detectors); ``"test"`` the held-out halves; ``"all"`` (the
    reported numbers) BIPIA's test files and all of InjecAgent."""
    unknown = set(tracks) - set(TRACKS)
    if unknown:
        raise ValueError(f"unknown track(s): {', '.join(sorted(unknown))}")
    if split not in SPLITS:
        raise ValueError(f"unknown split {split!r}; use one of {', '.join(SPLITS)}")
    report = BenchmarkReport(threshold=threshold, sources=[INJECAGENT], limit=limit, split=split)
    cases = load_injecagent(cache_dir, offline=offline, limit=limit, split=split)
    bipia = "bipia-train" if split == "dev" else "bipia"
    if "detection" in tracks:
        report.sources = [BIPIA, INJECAGENT]
        contexts = {
            task: [
                str(row["context"])
                for row in load_jsonl(f"{bipia}/{task}", cache_dir, offline=offline)[:limit]
            ]
            for task in ("email", "table", "code")
        }
        text_attacks = load_json(f"{bipia}/text_attacks", cache_dir, offline=offline)
        code_attacks = load_json(f"{bipia}/code_attacks", cache_dir, offline=offline)
        samples = bipia_samples(contexts, text_attacks, code_attacks)
        samples += injecagent_text_samples(cases)
        report.detection = run_detection(samples, threshold=threshold)
    if "agent" in tracks:
        report.agent = run_agent(cases)
        emails = [
            str(row["context"])
            for row in load_jsonl(f"{bipia}/email", cache_dir, offline=offline)[:limit]
        ]
        report.benign = run_benign(benign_cases(emails))
        if BIPIA not in report.sources:
            report.sources = [BIPIA, INJECAGENT]
    return report
