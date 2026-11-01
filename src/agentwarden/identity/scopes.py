"""Scope algebra.

Scopes are colon-separated segments such as ``email:send`` or ``files:read:reports``. A ``*``
segment matches exactly one segment, or *all remaining* segments when it is the last one, so
``files:*`` covers ``files:read`` and ``files:read:reports``.

Wildcards are allowed in *ceilings and entitlements* (what an agent or user may hold), but never
in *requested* scopes: a token always carries concrete scopes, which keeps least privilege explicit.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

from agentwarden.errors import InvalidRequestError
from agentwarden.models import SCOPE_PATTERN

_SCOPE_RE = re.compile(SCOPE_PATTERN)


def validate_scope(scope: str, *, allow_wildcards: bool = True) -> str:
    """Return ``scope`` if well-formed, otherwise raise :class:`InvalidRequestError`."""
    if not isinstance(scope, str) or not _SCOPE_RE.fullmatch(scope):
        raise InvalidRequestError(f"invalid scope {scope!r}: expected e.g. 'email:send'")
    segments = scope.split(":")
    if any("*" in seg and seg != "*" for seg in segments):
        raise InvalidRequestError(f"invalid scope {scope!r}: '*' must be a whole segment")
    if not allow_wildcards and "*" in segments:
        raise InvalidRequestError(
            f"wildcard scope {scope!r} cannot be requested; ask for concrete scopes"
        )
    return scope


def is_wildcard(scope: str) -> bool:
    return "*" in scope.split(":")


def scope_covers(pattern: str, scope: str) -> bool:
    """True if holding ``pattern`` grants ``scope``."""
    p_segs = pattern.split(":")
    s_segs = scope.split(":")
    for i, seg in enumerate(p_segs):
        if i >= len(s_segs):
            return False
        if seg == "*":
            if i == len(p_segs) - 1:
                return True
            continue
        if seg != s_segs[i]:
            return False
    return len(p_segs) == len(s_segs)


def covered_by_any(scope: str, patterns: Iterable[str]) -> bool:
    return any(scope_covers(p, scope) for p in patterns)


def dedupe(scopes: Iterable[str]) -> list[str]:
    """Remove duplicates while keeping first-seen order."""
    return list(dict.fromkeys(scopes))


def attenuate(requested: Sequence[str], *ceilings: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split ``requested`` into (granted, denied).

    A scope is granted only if *every* ceiling covers it. For a token this means it is the
    intersection of what was requested, what the user is entitled to, and the agent's ceiling.
    """
    ceiling_lists = [list(c) for c in ceilings]
    granted: list[str] = []
    denied: list[str] = []
    for scope in dedupe(requested):
        if all(covered_by_any(scope, ceiling) for ceiling in ceiling_lists):
            granted.append(scope)
        else:
            denied.append(scope)
    return granted, denied
