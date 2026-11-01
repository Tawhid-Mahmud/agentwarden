"""Detector evaluation against a labeled corpus (``agentwarden eval``).

Obfuscated samples are *generated* from readable YAML (see :func:`obfuscate`) so the corpus
file itself never contains invisible characters.
"""

from __future__ import annotations

import base64
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentwarden.errors import ConfigurationError
from agentwarden.models import ContextSegment, RiskLevel, SideEffect, Tool
from agentwarden.risk.detectors import DetectionContext, Detector, InjectionDetector
from agentwarden.risk.text import compute_facts

Technique = Literal["unicode_tags", "zero_width", "fullwidth", "homoglyph", "base64", "bidi"]

_HOMOGLYPHS = str.maketrans(
    {"a": chr(0x0430), "e": chr(0x0435), "o": chr(0x043E), "i": chr(0x0456), "c": chr(0x0441)}
)
_ZWSP, _RLO, _PDF, _IDEOGRAPHIC_SPACE = chr(0x200B), chr(0x202E), chr(0x202C), chr(0x3000)


def obfuscate(technique: Technique, payload: str) -> str:
    """Apply a smuggling technique an attacker might use to hide ``payload``."""
    if technique == "unicode_tags":
        return "".join(chr(0xE0000 + ord(c)) for c in payload if 0x20 <= ord(c) <= 0x7E)
    if technique == "zero_width":
        return " ".join(
            _ZWSP.join(word[i : i + 2] for i in range(0, len(word), 2))
            for word in payload.split(" ")
        )
    if technique == "fullwidth":
        return "".join(
            chr(ord(c) + 0xFEE0)
            if 0x21 <= ord(c) <= 0x7E
            else _IDEOGRAPHIC_SPACE
            if c == " "
            else c
            for c in payload
        )
    if technique == "homoglyph":
        return payload.translate(_HOMOGLYPHS)
    if technique == "base64":
        return "ref: " + base64.b64encode(payload.encode()).decode()
    return f"{_RLO}{payload}{_PDF}"  # bidi


class HiddenPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    technique: Technique
    payload: str


class CorpusSample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    label: Literal["malicious", "benign"]
    text: str = ""
    hidden: HiddenPayload | None = None
    notes: str = ""

    def render(self) -> str:
        if self.hidden is None:
            return self.text
        return f"{self.text} {obfuscate(self.hidden.technique, self.hidden.payload)}".strip()


class Corpus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    description: str = ""
    samples: list[CorpusSample] = Field(min_length=1)


@dataclass(frozen=True)
class SampleResult:
    id: str
    label: str
    flagged: bool
    top_signal: str | None
    top_weight: float

    @property
    def correct(self) -> bool:
        return self.flagged == (self.label == "malicious")


@dataclass
class EvalReport:
    threshold: float
    results: list[SampleResult] = field(default_factory=list)

    def _count(self, label: str, flagged: bool) -> int:
        return sum(1 for r in self.results if r.label == label and r.flagged is flagged)

    @property
    def tp(self) -> int:
        return self._count("malicious", True)

    @property
    def fn(self) -> int:
        return self._count("malicious", False)

    @property
    def fp(self) -> int:
        return self._count("benign", True)

    @property
    def tn(self) -> int:
        return self._count("benign", False)

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def summary(self) -> dict[str, float | int]:
        return {
            "samples": len(self.results),
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "precision": round(self.precision, 3),
            "recall": round(self.recall, 3),
            "fpr": round(self.fpr, 3),
            "f1": round(self.f1, 3),
        }


def load_corpus(path: str | Path) -> Corpus:
    try:
        return Corpus.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")))
    except FileNotFoundError as exc:
        raise ConfigurationError(f"corpus not found: {path}") from exc
    except (yaml.YAMLError, ValidationError) as exc:
        raise ConfigurationError(f"invalid corpus {path}: {exc}") from exc


_EVAL_TOOL = Tool(
    name="send_email", scope="email:send", risk=RiskLevel.HIGH, side_effect=SideEffect.EXTERNAL
)


def evaluate(
    corpus: Corpus, threshold: float = 0.3, detectors: Sequence[Detector] | None = None
) -> EvalReport:
    """Score each sample as untrusted context for an external-sink call.

    A sample is *flagged* when any detector signal reaches ``threshold``.
    """
    detectors = list(detectors) if detectors is not None else [InjectionDetector()]
    report = EvalReport(threshold=threshold)
    for sample in corpus.samples:
        segment = ContextSegment(source=f"corpus:{sample.id}", content=sample.render())
        ctx = DetectionContext(
            tool=_EVAL_TOOL,
            args={},
            strings=(),
            facts=compute_facts({}, [segment], lambda _d: False),
            segments=(segment,),
        )
        signals = [s for d in detectors for s in d.inspect(ctx)]
        top = max(signals, key=lambda s: s.weight, default=None)
        weight = top.weight if top else 0.0
        report.results.append(
            SampleResult(
                id=sample.id,
                label=sample.label,
                flagged=weight >= threshold,
                top_signal=top.name if top else None,
                top_weight=weight,
            )
        )
    return report
