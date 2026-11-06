"""Combines detector signals into one risk score."""

from __future__ import annotations

import logging
import math
import time
from collections.abc import Callable, Iterable, Sequence

from agentwarden.models import RiskAssessment, RiskLevel, RiskSignal
from agentwarden.risk.detectors import (
    ActivitySource,
    BehaviorAnomalyDetector,
    DetectionContext,
    Detector,
    ExfiltrationDetector,
    InjectionDetector,
    SecretDetector,
    TaintFlowDetector,
)
from agentwarden.risk.provenance import ActionProvenanceDetector

log = logging.getLogger(__name__)

#: Weight of the signal emitted when a detector crashes. High enough that, under the default
#: policy, side-effecting calls need approval: a detector failure is not a free pass.
DETECTOR_ERROR_WEIGHT = 0.5


#: Corroborating signals from the *same* detector are correlated, so they only get partial credit.
CORROBORATION_FACTOR = 0.5


def noisy_or(weights: Iterable[float]) -> float:
    """P(at least one signal is a true positive), treating signals as independent."""
    return 1.0 - math.prod(1.0 - w for w in weights)


def detector_score(weights: Sequence[float]) -> float:
    """Combine one detector's signals: the strongest counts fully, the rest are discounted."""
    if not weights:
        return 0.0
    ordered = sorted(weights, reverse=True)
    return noisy_or([ordered[0], *(w * CORROBORATION_FACTOR for w in ordered[1:])])


#: Detectors whose evidence can come purely from the content the agent has read.
CONTEXT_DETECTORS = frozenset({"injection", "provenance", "llm_judge"})
#: Ceiling for evidence that only says "the context is poisoned". A poisoned context means the
#: agent *may* be compromised, which calls for a human (approval) rather than a hard deny.
#: Denies need call-level evidence too, such as a tainted destination or secrets in the arguments.
CONTEXT_ONLY_CAP = 0.75


def _context_only(signals: Sequence[RiskSignal]) -> bool:
    return all((s.location or "").startswith("context:") for s in signals)


def combine(signals: Iterable[RiskSignal]) -> float:
    """Per-detector aggregation, then noisy-OR across (roughly independent) detectors."""
    by_detector: dict[str, list[RiskSignal]] = {}
    for signal in signals:
        by_detector.setdefault(signal.detector, []).append(signal)
    scores = []
    for detector, group in by_detector.items():
        score = detector_score([s.weight for s in group])
        if detector in CONTEXT_DETECTORS and _context_only(group):
            score = min(score, CONTEXT_ONLY_CAP)
        scores.append(score)
    return noisy_or(scores)


def strongest_per_name(signals: Iterable[RiskSignal]) -> list[RiskSignal]:
    """Keep one signal per name (the heaviest) so repeated evidence isn't double counted."""
    best: dict[str, RiskSignal] = {}
    for signal in signals:
        current = best.get(signal.name)
        if current is None or signal.weight > current.weight:
            best[signal.name] = signal
    return sorted(best.values(), key=lambda s: (-s.weight, s.name))


class RiskEngine:
    def __init__(self, detectors: Sequence[Detector]) -> None:
        self.detectors = list(detectors)

    @classmethod
    def default(
        cls,
        activity: ActivitySource | None = None,
        clock: Callable[[], float] = time.time,
        extra: Sequence[Detector] = (),
    ) -> RiskEngine:
        detectors: list[Detector] = [
            InjectionDetector(),
            ActionProvenanceDetector(),
            TaintFlowDetector(),
            SecretDetector(),
            ExfiltrationDetector(),
        ]
        if activity is not None:
            detectors.append(BehaviorAnomalyDetector(activity, clock=clock))
        detectors.extend(extra)
        return cls(detectors)

    def assess(self, ctx: DetectionContext) -> RiskAssessment:
        collected: list[RiskSignal] = []
        for detector in self.detectors:
            try:
                collected.extend(detector.inspect(ctx))
            except Exception:  # a broken detector must not break authorization
                log.exception("detector %s failed", detector.name)
                collected.append(
                    RiskSignal(
                        detector=detector.name,
                        name="detector_error",
                        weight=DETECTOR_ERROR_WEIGHT,
                        evidence=f"detector {detector.name!r} raised an exception",
                    )
                )
        signals = strongest_per_name(collected)
        score = round(combine(signals), 3)
        return RiskAssessment(score=score, level=RiskLevel.from_score(score), signals=signals)
