"""Heuristic risk detectors.

Each detector inspects one tool call in context and returns zero or more
:class:`~agentwarden.models.RiskSignal` objects with a weight between 0 and 1 and human-readable
evidence. Weights are scaled by how dangerous the *sink* is: the same injected instruction
matters more when the agent is about to send data out than when it only reads.

Detection is a *signal*, not a guarantee. AgentWarden's primary controls are deterministic
(scopes, policy, approvals). See docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import parse_qsl, urlsplit

from agentwarden.models import ContextSegment, RiskLevel, RiskSignal, SideEffect, Tool
from agentwarden.risk.text import (
    BIDI_CONTROLS,
    RECIPIENT_KEYS,
    CallFacts,
    count_in_word_zero_width,
    decode_base64_candidates,
    decode_tag_characters,
    email_domain,
    find_encoded_blobs,
    has_tag_characters,
    normalize,
    reveal_hidden,
    url_host,
)

SINK_FACTOR = {
    SideEffect.NONE: 0.5,
    SideEffect.READ: 0.5,
    SideEffect.WRITE: 0.8,
    SideEffect.EXTERNAL: 1.0,
}


@dataclass(frozen=True)
class DetectionContext:
    """Everything a detector may look at for one tool call."""

    tool: Tool
    args: Mapping[str, Any]
    strings: tuple[tuple[str, str], ...]
    facts: CallFacts
    user_prompt: str = ""
    segments: tuple[ContextSegment, ...] = ()
    agent_id: str = ""
    user_id: str = ""
    is_trusted_domain: Callable[[str], bool] = field(default=lambda _d: False)

    @property
    def sink_factor(self) -> float:
        return SINK_FACTOR[self.tool.side_effect]

    @property
    def untrusted_segments(self) -> tuple[ContextSegment, ...]:
        return tuple(s for s in self.segments if not s.trusted)

    @property
    def trusted_text(self) -> str:
        parts = [self.user_prompt, *(s.content for s in self.segments if s.trusted)]
        return "\n".join(parts)


class Detector(Protocol):
    name: str

    def inspect(self, ctx: DetectionContext) -> list[RiskSignal]: ...


def _snippet(text: str, start: int, end: int, width: int = 60) -> str:
    lo, hi = max(0, start - 15), min(len(text), end + width)
    return ("…" if lo else "") + text[lo:hi].strip() + ("…" if hi < len(text) else "")


# =========================================================================== prompt injection
@dataclass(frozen=True)
class InjectionPattern:
    name: str
    weight: float
    regex: re.Pattern[str]


def _p(name: str, weight: float, pattern: str) -> InjectionPattern:
    return InjectionPattern(name, weight, re.compile(pattern, re.IGNORECASE))


#: Patterns run on :func:`normalize`-d text (casefolded, de-obfuscated, whitespace-collapsed).
INJECTION_PATTERNS: tuple[InjectionPattern, ...] = (
    _p(
        "instruction_override",
        0.6,
        r"\b(ignore|disregard|forget|override|bypass|skip)\b[^.\n]{0,40}?"
        r"\b(previous|prior|above|earlier|preceding|all|any|your|the|existing|original)\b"
        r"[^.\n]{0,40}?\b(instructions?|prompts?|rules|directions|guidelines|directives|"
        r"constraints|guardrails)\b",
    ),
    _p(
        "role_hijack",
        0.45,
        r"\b(you are now (an? |the |in |my |no longer |free |dan\b|unrestricted|jailbroken)|"
        r"from now on,? you|you will now act|new (system )?instructions?\s*:|"
        r"system override|act as (an? )?(unrestricted|unfiltered|jailbroken)|developer mode|"
        r"dan mode)",
    ),
    _p(
        "system_prompt_probe",
        0.35,
        r"\b(reveal|print|show|repeat|output|leak|disclose)\b[^.\n]{0,30}"
        r"\b(system prompt|hidden instructions|initial instructions|your instructions)\b",
    ),
    _p(
        "agent_addressing",
        0.4,
        r"(\b(ai|llm|gpt|assistant|agent|chatbot|language model)s?\b[^.\n]{0,20}"
        r"\b(reading|processing|summari[sz]ing|parsing|analy[sz]ing) this\b"
        r"|\bif you are an? (ai|llm|language model|assistant|agent)\b"
        r"|\b(attention|note to|message for|instructions for|important for) (the |all )?"
        r"(ai|llm|assistant|agent|model)s?\b)",
    ),
    _p(
        "concealment",
        0.5,
        r"(\b(do not|don't|never)\b[^.\n]{0,20}\b(tell|inform|mention|reveal|alert|notify)\b"
        r"[^.\n]{0,20}\b(the )?(user|human|owner|anyone)\b"
        r"|\bwithout (the user'?s? |their )?(knowledge|knowing|telling)\b"
        r"|\bkeep this (secret|hidden|confidential) from\b)",
    ),
    _p(
        "action_directive",
        0.2,
        r"\b(forward|send|email|transfer|wire|upload|post|exfiltrate)\b[^.\n]{0,60}"
        r"\b(to|at)\b[^.\n]{0,10}(https?://|[\w.+-]+@[\w-]+\.)",
    ),
    _p("markdown_exfil", 0.5, r"!\[[^\]]{0,100}\]\(\s*https?://[^)\s]+[?&][^)\s=]+=[^)\s]*\)"),
    _p(
        "hidden_html",
        0.3,
        r"<!--[^>]{0,2000}?\b(instruction|assistant|ai|ignore|system|agent)\b[^>]{0,2000}?-->"
        r"|style\s*=\s*[\"'][^\"']*(display\s*:\s*none|font-size\s*:\s*0|visibility\s*:\s*hidden"
        r"|color\s*:\s*(white|#fff\b|#ffffff))",
    ),
)

#: Weak, common-in-benign-text patterns don't count as "injection present" on their own.
_WEAK_PATTERNS = frozenset({"action_directive"})


def scan_text(text: str) -> list[tuple[InjectionPattern, str]]:
    """Return every pattern that matches ``text`` with a short evidence snippet."""
    norm = normalize(text)
    hits = []
    for pattern in INJECTION_PATTERNS:
        match = pattern.regex.search(norm)
        if match:
            hits.append((pattern, _snippet(norm, match.start(), match.end())))
    return hits


class InjectionDetector:
    """Finds instructions aimed at the model inside *untrusted* content and in arguments.

    Besides plain phrasing it de-obfuscates common smuggling tricks: Unicode tag characters,
    zero-width characters inside words, bidi overrides, homoglyphs, full-width letters and
    base64-encoded instructions.
    """

    name = "injection"

    def inspect(self, ctx: DetectionContext) -> list[RiskSignal]:
        factor = ctx.sink_factor
        signals: list[RiskSignal] = []
        for segment in ctx.untrusted_segments:
            signals.extend(self._scan_segment(segment, factor))

        # Agents copying injected text into files/emails spread the attack (stored injection).
        if ctx.tool.side_effect in (SideEffect.WRITE, SideEffect.EXTERNAL):
            for path, value in ctx.strings:
                strong = [(p, s) for p, s in scan_text(value) if p.name not in _WEAK_PATTERNS]
                if strong:
                    top, snippet = max(strong, key=lambda h: h[0].weight)
                    signals.append(
                        RiskSignal(
                            detector=self.name,
                            name="injection_in_arguments",
                            weight=round(top.weight * 0.7 * factor, 3),
                            evidence=f"{top.name}: {snippet}",
                            location=path,
                        )
                    )
                    break
        return signals

    def _scan_segment(self, segment: ContextSegment, factor: float) -> list[RiskSignal]:
        text, where = segment.content, f"context:{segment.source}"
        signals: list[RiskSignal] = []

        def emit(name: str, weight: float, evidence: str) -> None:
            signals.append(
                RiskSignal(
                    detector=self.name,
                    name=name,
                    weight=round(min(1.0, weight * factor), 3),
                    evidence=evidence,
                    location=where,
                )
            )

        for pattern, snippet in scan_text(text):
            emit(pattern.name, pattern.weight, snippet)

        if has_tag_characters(text):
            hidden = decode_tag_characters(text)
            emit("unicode_tag_smuggling", 0.7, f"hidden ASCII payload: {hidden[:120]!r}")
            for pattern, snippet in scan_text(hidden):
                emit(pattern.name, pattern.weight, f"(decoded from tag characters) {snippet}")

        if any(c in BIDI_CONTROLS for c in text):
            emit(
                "bidi_control_characters",
                0.4,
                "text contains bidirectional override/isolate controls",
            )

        zero_width = count_in_word_zero_width(text)
        if zero_width >= 2:
            emit("zero_width_obfuscation", 0.35, f"{zero_width} zero-width characters inside words")

        for decoded in decode_base64_candidates(text):
            inner = [(p, s) for p, s in scan_text(decoded) if p.name not in _WEAK_PATTERNS]
            if inner:
                top, snippet = max(inner, key=lambda h: h[0].weight)
                emit("encoded_instructions", max(0.5, top.weight), f"base64 decodes to: {snippet}")
                break
        return signals


# =========================================================================== taint flow
class TaintFlowDetector:
    """Flags outbound destinations that came from untrusted content instead of the user.

    If the user asked "summarize my inbox" and the agent then emails ``x@evil.example``, an
    address that appears *only* in an email body the agent read, the destination was almost
    certainly chosen by that content. This works no matter how the injection was phrased.
    """

    name = "taint"

    def inspect(self, ctx: DetectionContext) -> list[RiskSignal]:
        if ctx.tool.side_effect not in (SideEffect.WRITE, SideEffect.EXTERNAL):
            return []
        untrusted = ctx.untrusted_segments
        if not untrusted:
            return []
        revealed = {s.source: normalize(reveal_hidden(s.content)) for s in untrusted}
        untrusted_text = "\n".join(revealed.values())
        trusted_text = normalize(ctx.trusted_text)

        def source_of(value: str) -> str:
            v = value.casefold()
            return next((src for src, text in revealed.items() if v in text), "untrusted context")

        signals: list[RiskSignal] = []
        seen: set[str] = set()
        chosen_by: dict[str, str] = {}  # external destination -> the content that chose it
        destinations: list[tuple[str, str]] = [(r, email_domain(r)) for r in ctx.facts.recipients]
        for url in ctx.facts.urls:
            host = url_host(url)
            if host:
                destinations.append((host, host))
        for value, domain in destinations:
            key = value.casefold()
            if key in seen or key not in untrusted_text or key in trusted_text:
                continue
            seen.add(key)
            external = not ctx.is_trusted_domain(domain)
            if external:
                chosen_by[value] = source_of(value)
            signals.append(
                RiskSignal(
                    detector=self.name,
                    name="tainted_external_destination"
                    if external
                    else "tainted_internal_destination",
                    weight=0.7 if external else 0.15,
                    evidence=(
                        f"{value!r} appears in untrusted content but not in the user's request"
                    ),
                    location=f"context:{source_of(value)}",
                )
            )

        signals.extend(self._data_to_tainted_destination(ctx, chosen_by, trusted_text))

        path = ctx.facts.path
        if path and path.casefold() in untrusted_text and path.casefold() not in trusted_text:
            signals.append(
                RiskSignal(
                    detector=self.name,
                    name="tainted_path",
                    weight=0.3,
                    evidence=f"target path {path!r} was taken from untrusted content",
                    location=f"context:{source_of(path)}",
                )
            )
        return signals

    #: Lines shorter than this are too common ("Thanks,", "Hi Alice") to show where data came from.
    MIN_DATA_LINE = 16

    def _data_to_tainted_destination(
        self, ctx: DetectionContext, chosen_by: Mapping[str, str], trusted_text: str
    ) -> list[RiskSignal]:
        """Data from one source going to a destination another source chose: exfiltration.

        Replying to the sender of an email is ambiguous (a human should decide). Sending the
        payroll file to an address that only appeared in an email is not: the content picked
        where *other* data the agent read should go.
        """
        if not chosen_by:
            return []
        payload = normalize(
            " ".join(
                v
                for path, v in ctx.strings
                if path.split(".")[1:2] != [] and path.split(".")[1] not in RECIPIENT_KEYS
            )
        )
        if not payload:
            return []
        for segment in ctx.untrusted_segments:
            if segment.source in chosen_by.values():
                continue  # quoting the email that asked is not moving other data
            for line in reveal_hidden(segment.content).splitlines():
                piece = normalize(line)
                if len(piece) < self.MIN_DATA_LINE or piece in trusted_text or piece not in payload:
                    continue
                destination = next(iter(chosen_by))
                return [
                    RiskSignal(
                        detector=self.name,
                        name="tainted_destination_with_data",
                        weight=0.8,
                        evidence=(
                            f"data from {segment.source} is going to {destination!r}, which came "
                            f"from {chosen_by[destination]}"
                        ),
                        location="arguments",
                    )
                ]
        return []


# =========================================================================== secrets
@dataclass(frozen=True)
class SecretPattern:
    kind: str
    regex: re.Pattern[str]


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretPattern(
        "github_token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b"),
    ),
    SecretPattern("private_key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    SecretPattern("anthropic_api_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    SecretPattern("sk_api_key", re.compile(r"\bsk-(?!ant-)[A-Za-z0-9_-]{32,}")),
    SecretPattern("stripe_live_key", re.compile(r"\b[rs]k_live_[A-Za-z0-9]{20,}\b")),
    SecretPattern("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    SecretPattern("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    SecretPattern(
        "jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
    ),
    SecretPattern(
        "credential_assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)"
            r"\b\s*[:=]\s*['\"]?[^\s'\",;]{8,}"
        ),
    ),
)


def find_secrets(text: str) -> list[tuple[str, str]]:
    """Return ``(kind, redacted_preview)`` for each secret found in ``text``."""
    found = []
    for pattern in SECRET_PATTERNS:
        for match in pattern.regex.finditer(text):
            value = match.group(0)
            found.append((pattern.kind, value[:4] + "…" + f"[{len(value)} chars]"))
    return found


def redact(text: str) -> str:
    """Replace every detected secret with ``[REDACTED:<kind>]``."""
    for pattern in SECRET_PATTERNS:
        text = pattern.regex.sub(f"[REDACTED:{pattern.kind}]", text)
    return text


def redact_obj(obj: Any) -> Any:
    """Recursively redact secrets in strings inside dicts/lists."""
    if isinstance(obj, str):
        return redact(obj)
    if isinstance(obj, Mapping):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [redact_obj(v) for v in obj]
    return obj


SECRET_WEIGHTS = {
    SideEffect.EXTERNAL: 0.8,
    SideEffect.WRITE: 0.4,
    SideEffect.READ: 0.2,
    SideEffect.NONE: 0.2,
}


class SecretDetector:
    """Detects credentials in tool-call arguments (leaks, exfiltration)."""

    name = "secrets"

    def inspect(self, ctx: DetectionContext) -> list[RiskSignal]:
        weight = SECRET_WEIGHTS[ctx.tool.side_effect]
        for path, value in ctx.strings:
            secrets = find_secrets(value)
            if secrets:
                kinds = ", ".join(sorted({k for k, _ in secrets}))
                return [
                    RiskSignal(
                        detector=self.name,
                        name="secret_in_arguments",
                        weight=weight,
                        evidence=f"{kinds} detected ({secrets[0][1]})",
                        location=path,
                    )
                ]
        return []


# =========================================================================== exfiltration
class ExfiltrationDetector:
    """Signals for data leaving the organization through an external side-effect tool."""

    name = "exfiltration"

    def inspect(self, ctx: DetectionContext) -> list[RiskSignal]:
        if ctx.tool.side_effect is not SideEffect.EXTERNAL:
            return []
        facts = ctx.facts
        signals: list[RiskSignal] = []

        def emit(name: str, weight: float, evidence: str, location: str | None = None) -> None:
            signals.append(
                RiskSignal(
                    detector=self.name,
                    name=name,
                    weight=weight,
                    evidence=evidence,
                    location=location,
                )
            )

        if facts.external_recipients:
            emit(
                "external_recipient",
                0.25,
                "recipients outside the organization: " + ", ".join(facts.external_recipients[:5]),
            )
        if len(facts.recipients) > 10:
            emit("bulk_recipients", 0.3, f"{len(facts.recipients)} recipients")
        if facts.external_domains:
            emit(
                "external_destination",
                0.1,
                "external hosts: " + ", ".join(facts.external_domains[:5]),
            )
        for url in facts.urls:
            try:
                query = parse_qsl(urlsplit(url).query, keep_blank_values=True)
            except ValueError:
                continue
            long_values = [v for _, v in query if len(v) >= 64]
            if long_values:
                emit(
                    "data_in_url",
                    0.45,
                    f"URL carries {len(long_values[0])} chars of data in its query string",
                    url[:120],
                )
                break
        for path, value in ctx.strings:
            if find_encoded_blobs(value):
                emit("encoded_payload", 0.3, "large base64/hex blob in outbound arguments", path)
                break
        if facts.args_size > 20_000:
            emit("large_payload", 0.15, f"{facts.args_size} bytes of arguments sent externally")
        return signals


# =========================================================================== behavior
class ActivitySource(Protocol):
    """Read-only view of past decisions (implemented by the audit log)."""

    def decision_counts(self, agent_id: str, since: float) -> dict[str, int]: ...

    def has_allowed(self, agent_id: str, tool: str) -> bool: ...


class BehaviorAnomalyDetector:
    """Simple behavioral baselines: velocity, probing and first use of a sensitive tool."""

    name = "anomaly"

    def __init__(
        self,
        activity: ActivitySource,
        clock: Callable[[], float] = time.time,
        velocity_limit: int = 30,
        denial_limit: int = 3,
    ) -> None:
        self._activity = activity
        self._clock = clock
        self._velocity_limit = velocity_limit
        self._denial_limit = denial_limit

    def inspect(self, ctx: DetectionContext) -> list[RiskSignal]:
        now = self._clock()
        signals: list[RiskSignal] = []
        minute = self._activity.decision_counts(ctx.agent_id, now - 60)
        total = sum(minute.values())
        if total > self._velocity_limit:
            signals.append(
                RiskSignal(
                    detector=self.name,
                    name="high_velocity",
                    weight=0.35,
                    evidence=f"{total} authorization requests in the last minute",
                )
            )
        recent = self._activity.decision_counts(ctx.agent_id, now - 600)
        denies = recent.get("deny", 0)
        if denies >= self._denial_limit:
            signals.append(
                RiskSignal(
                    detector=self.name,
                    name="repeated_denials",
                    weight=0.3,
                    evidence=f"{denies} denied requests in the last 10 minutes",
                )
            )
        if ctx.tool.risk.rank >= RiskLevel.HIGH.rank and not self._activity.has_allowed(
            ctx.agent_id, ctx.tool.name
        ):
            signals.append(
                RiskSignal(
                    detector=self.name,
                    name="novel_sensitive_tool",
                    weight=0.15,
                    evidence=(
                        f"first use of {ctx.tool.risk.value}-risk tool {ctx.tool.name!r}"
                        " by this agent"
                    ),
                )
            )
        return signals
