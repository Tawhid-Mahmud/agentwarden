"""Text utilities for detectors: normalization, de-obfuscation and entity extraction."""

from __future__ import annotations

import base64
import binascii
import json
import posixpath
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlsplit

from agentwarden.models import ContextSegment

# --------------------------------------------------------------------------- invisible text
#: Characters that render as nothing and can split words to dodge filters.
ZERO_WIDTH = frozenset(
    chr(c)
    for c in (
        0x200B,
        0x200C,
        0x200D,
        0x2060,
        0x2061,
        0x2062,
        0x2063,
        0x2064,
        0xFEFF,
        0x180E,
        0x00AD,
    )
)
#: Explicit bidirectional embeddings/overrides/isolates ("Trojan Source"-style reordering).
BIDI_CONTROLS = frozenset(
    chr(c) for c in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)
)
TAG_BLOCK = range(0xE0000, 0xE0080)

# Minimal confusables map: Cyrillic/Greek/Armenian letters that look like Latin ones.
# Written as code points so the source itself contains no ambiguous characters.
_CONFUSABLES = str.maketrans(
    {
        0x0430: "a", 0x0435: "e", 0x043E: "o", 0x0440: "p", 0x0441: "c", 0x0443: "y",
        0x0445: "x", 0x0456: "i", 0x0458: "j", 0x0455: "s", 0x0501: "d", 0x04BB: "h",
        0x04CF: "l", 0x0261: "g", 0x0578: "n", 0x057D: "u", 0x03B1: "a", 0x03B5: "e",
        0x03B9: "i", 0x03BA: "k", 0x03BD: "v", 0x03BF: "o", 0x03C1: "p", 0x03C4: "t",
        0x03C5: "u", 0x03C7: "x",
    }
)  # fmt: skip

_WS_RE = re.compile(r"\s+")


def has_tag_characters(text: str) -> bool:
    return any(ord(c) in TAG_BLOCK for c in text)


def decode_tag_characters(text: str) -> str:
    """Recover the ASCII payload hidden in Unicode *tag* characters (U+E0020..U+E007E).

    Tag characters mirror printable ASCII but render invisibly, which makes them a channel for
    "ASCII smuggling" of instructions that humans can't see and models can read.
    """
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def count_in_word_zero_width(text: str) -> int:
    """Count zero-width characters sandwiched between letters, e.g. ``ig\\u200bnore``."""
    count = 0
    for i in range(1, len(text) - 1):
        if text[i] in ZERO_WIDTH and text[i - 1].isalpha() and text[i + 1].isalpha():
            count += 1
    return count


def strip_invisible(text: str) -> str:
    return "".join(
        c
        for c in text
        if c not in ZERO_WIDTH and c not in BIDI_CONTROLS and ord(c) not in TAG_BLOCK
    )


def normalize(text: str) -> str:
    """Canonical form for pattern matching.

    NFKC folds full-width and stylized letters (U+FF41..U+FF5A etc.), invisible characters are
    removed, common Cyrillic/Greek homoglyphs are mapped to Latin, whitespace is collapsed and
    the result is casefolded.
    """
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text).translate(_CONFUSABLES)
    return _WS_RE.sub(" ", text).casefold()


# --------------------------------------------------------------------------- encoded payloads
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{40,}={0,2}")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{64,}\b")


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c.isprintable() or c in "\n\r\t") / len(text)


def decode_base64_candidates(text: str, limit: int = 10) -> list[str]:
    """Decode base64 blobs in ``text`` that turn out to be readable text."""
    decoded: list[str] = []
    for match in _B64_RE.finditer(text):
        blob = match.group(0)
        padded = blob + "=" * (-len(blob) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                raw = decoder(padded)
            except (binascii.Error, ValueError):
                continue
            candidate = raw.decode("utf-8", errors="replace")
            if _printable_ratio(candidate) >= 0.9:
                decoded.append(candidate)
                break
        if len(decoded) >= limit:
            break
    return decoded


def reveal_hidden(text: str) -> str:
    """``text`` plus any payload hidden in tag characters or base64, for content matching."""
    parts = [text]
    if has_tag_characters(text):
        parts.append(decode_tag_characters(text))
    parts.extend(decode_base64_candidates(text, limit=5))
    return "\n".join(parts)


def find_encoded_blobs(text: str) -> list[str]:
    return [m.group(0) for m in _B64_RE.finditer(text) if len(m.group(0)) >= 200] + [
        m.group(0) for m in _HEX_RE.finditer(text) if len(m.group(0)) >= 128
    ]


# --------------------------------------------------------------------------- entities
EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b"
)
URL_RE = re.compile(r"\bhttps?://[^\s<>\"'`)\]]+", re.IGNORECASE)

RECIPIENT_KEYS = frozenset({"to", "cc", "bcc", "recipient", "recipients", "reply_to", "email"})
PATH_KEYS = ("path", "file", "filename", "filepath")


def flatten_strings(obj: Any, prefix: str = "args", max_items: int = 2000) -> list[tuple[str, str]]:
    """Return ``(path, value)`` for every string inside ``obj`` (depth-first, bounded)."""
    out: list[tuple[str, str]] = []
    stack: list[tuple[str, Any, int]] = [(prefix, obj, 0)]
    while stack and len(out) < max_items:
        path, value, depth = stack.pop()
        if isinstance(value, str):
            out.append((path, value))
        elif depth < 12 and isinstance(value, Mapping):
            stack.extend((f"{path}.{k}", v, depth + 1) for k, v in reversed(list(value.items())))
        elif depth < 12 and isinstance(value, list | tuple):
            stack.extend((f"{path}.{i}", v, depth + 1) for i, v in reversed(list(enumerate(value))))
    return out


def url_host(url: str) -> str | None:
    try:
        host = urlsplit(url).hostname
    except ValueError:
        return None
    return host.rstrip(".").lower() if host else None


def email_domain(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower()


def normalize_path(raw: str) -> str:
    """Canonicalize a file path the way an attacker can't easily dodge."""
    path = unquote(unquote(raw)).replace("\\", "/")
    path = unicodedata.normalize("NFKC", path)
    return posixpath.normpath(path) if path else path


def _dedupe(items: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(items))


@dataclass(frozen=True)
class CallFacts:
    """Derived, policy-friendly facts about a tool call's arguments."""

    recipients: tuple[str, ...] = ()
    external_recipients: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    external_domains: tuple[str, ...] = ()
    path: str | None = None
    has_untrusted_context: bool = False
    args_size: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "recipients": list(self.recipients),
            "external_recipients": list(self.external_recipients),
            "urls": list(self.urls),
            "domains": list(self.domains),
            "external_domains": list(self.external_domains),
            "path": self.path,
            "has_untrusted_context": self.has_untrusted_context,
            "args_size": self.args_size,
        }


def compute_facts(
    args: Mapping[str, Any],
    segments: Iterable[ContextSegment],
    is_trusted_domain: Callable[[str], bool],
) -> CallFacts:
    strings = flatten_strings(args)
    recipients: list[str] = []
    urls: list[str] = []
    for path, value in strings:
        key = path.split(".")[-1]
        if key.isdigit() and path.count(".") >= 2:  # list element: look at the parent key
            key = path.split(".")[-2]
        if key.lower() in RECIPIENT_KEYS:
            recipients.extend(m.lower() for m in EMAIL_RE.findall(value))
        urls.extend(m.rstrip(".,;:") for m in URL_RE.findall(value))
    domains = [h for h in (url_host(u) for u in urls) if h]
    raw_path = next((args[k] for k in PATH_KEYS if isinstance(args.get(k), str)), None)
    return CallFacts(
        recipients=_dedupe(recipients),
        external_recipients=_dedupe(
            r for r in recipients if not is_trusted_domain(email_domain(r))
        ),
        urls=_dedupe(urls),
        domains=_dedupe(domains),
        external_domains=_dedupe(d for d in domains if not is_trusted_domain(d)),
        path=normalize_path(raw_path) if raw_path is not None else None,
        has_untrusted_context=any(not s.trusted for s in segments),
        args_size=len(json.dumps(args, default=str)),
    )
