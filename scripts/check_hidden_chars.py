#!/usr/bin/env python3
"""Fail if text files contain invisible or bidirectional control characters.

AgentWarden *detects* Unicode smuggling (tag characters, zero-width and bidi controls), so the
repository itself must never contain them ("Trojan Source", CVE-2021-42574). Test payloads are
generated at runtime from code points instead.

Usage: python scripts/check_hidden_chars.py [paths...]   (defaults to the repository root)
"""

from __future__ import annotations

import sys
import unicodedata
from pathlib import Path

SUFFIXES = {".py", ".yaml", ".yml", ".md", ".toml", ".txt", ".cfg", ".json", ".sh", ""}
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".mypy_cache", ".ruff_cache", ".pytest_cache"}


def is_hidden(ch: str) -> bool:
    category = unicodedata.category(ch)
    if category == "Cc":
        return ch not in "\t\n\r"
    return category in {"Cf", "Co", "Cs"} or 0xE0000 <= ord(ch) <= 0xE007F


def scan(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return []
    problems = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for ch in line:
            if is_hidden(ch):
                problems.append(
                    f"{path}:{lineno}: U+{ord(ch):04X} {unicodedata.name(ch, 'UNKNOWN')}"
                )
    return problems


def main(argv: list[str]) -> int:
    roots = [Path(a) for a in argv] or [Path(__file__).resolve().parent.parent]
    problems: list[str] = []
    for root in roots:
        files = [root] if root.is_file() else root.rglob("*")
        for path in files:
            if path.is_file() and path.suffix in SUFFIXES and not SKIP_DIRS & set(path.parts):
                problems.extend(scan(path))
    for problem in problems:
        print(problem)
    print(f"{len(problems)} hidden character(s) found")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
