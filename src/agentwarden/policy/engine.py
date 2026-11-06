"""Policy evaluation.

Semantics worth knowing when writing policies:

* Field paths resolve against the request context (see :func:`base_context` for its shape).
* A comparison on a **missing** field is ``false``, including the negated operators (``ne``,
  ``not_in``, ``not_contains``). Use ``exists`` / ``empty`` to test for presence explicitly.
* String comparisons are **case-insensitive** (casefolded) for every operator except ``regex``,
  which is applied as written (use ``(?i)`` to ignore case).
* String operators applied to a **list** field require *every* element to match, and an empty
  list never matches. ``in`` with a list field means "subset of", and ``not_in`` means
  "disjoint from".
"""

from __future__ import annotations

import copy
import fnmatch
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from agentwarden.errors import PolicyError
from agentwarden.models import Decision
from agentwarden.policy.model import Condition, Policy, Rule


class _Missing:
    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return "<missing>"


MISSING: Any = _Missing()


def base_context() -> dict[str, Any]:
    """The skeleton every evaluation context has. The gateway fills in the values."""
    return {
        "user": {"id": None, "roles": []},
        "agent": {"id": None, "owner": None, "trust_tier": None},
        "actor_chain": [],
        "delegation": {"depth": 0},
        "tool": {"name": None, "scope": None, "risk": None, "side_effect": None},
        "args": {},
        "risk": {"score": 0.0, "level": "low", "signals": [], "detectors": []},
        "facts": {
            "recipients": [],
            "external_recipients": [],
            "urls": [],
            "domains": [],
            "external_domains": [],
            "path": None,
            "has_untrusted_context": False,
            "args_size": 0,
        },
        "token": {"task": None, "scopes": []},
        "time": {"hour": None, "weekday": None},
    }


def deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def resolve(context: Mapping[str, Any], path: str) -> Any:
    current: Any = context
    for part in path.split("."):
        if isinstance(current, Mapping) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return MISSING
    return current


def _fold(value: Any) -> Any:
    return value.casefold() if isinstance(value, str) else value


def _is_number(value: Any) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool)


def _string_match(op: str, actual: Any, expected: str, cond: Condition) -> bool:
    if isinstance(actual, list):
        return bool(actual) and all(_string_match(op, item, expected, cond) for item in actual)
    if not isinstance(actual, str):
        return False
    if op == "regex":
        if cond.regex is None:  # pragma: no cover - compiled during validation
            raise PolicyError("regex condition was not compiled")
        return cond.regex.search(actual) is not None
    a, e = actual.casefold(), expected.casefold()
    if op == "starts_with":
        return a.startswith(e)
    if op == "ends_with":
        return a.endswith(e)
    return fnmatch.fnmatchcase(a, e)  # glob


def _apply(cond: Condition, actual: Any) -> bool:
    op, expected = cond.op, cond.value
    if op == "exists":
        return (actual is not MISSING and actual is not None) is expected
    if op == "empty":
        is_empty = (
            actual is MISSING
            or actual is None
            or (isinstance(actual, str | list | dict | tuple) and len(actual) == 0)
        )
        return is_empty is expected
    if actual is MISSING or actual is None:
        return False
    if op in ("starts_with", "ends_with", "glob", "regex"):
        return _string_match(op, actual, expected, cond)
    if op in ("gt", "gte", "lt", "lte"):
        if not _is_number(actual):
            return False
        number, bound = float(actual), float(expected)
        if op == "gt":
            return number > bound
        if op == "gte":
            return number >= bound
        if op == "lt":
            return number < bound
        return number <= bound
    if op in ("eq", "ne"):
        if isinstance(actual, list) and isinstance(expected, list):
            equal = [_fold(x) for x in actual] == [_fold(x) for x in expected]
        else:
            equal = _fold(actual) == _fold(expected)
        return equal if op == "eq" else not equal
    if op in ("in", "not_in"):
        allowed = {_fold(x) for x in expected if isinstance(x, str | int | float)}
        items = actual if isinstance(actual, list) else [actual]
        folded = [_fold(x) for x in items]
        if op == "in":
            return bool(folded) and all(x in allowed for x in folded)
        return all(x not in allowed for x in folded)
    if op in ("contains", "not_contains"):
        if isinstance(actual, list):
            found = _fold(expected) in [_fold(x) for x in actual]
        elif isinstance(actual, str) and isinstance(expected, str):
            found = expected.casefold() in actual.casefold()
        else:
            return False
        return found if op == "contains" else not found
    raise PolicyError(f"unsupported operator {op!r}")  # pragma: no cover - schema prevents this


def evaluate_condition(cond: Condition, context: Mapping[str, Any]) -> bool:
    if cond.all_ is not None:
        return all(evaluate_condition(c, context) for c in cond.all_)
    if cond.any_ is not None:
        return any(evaluate_condition(c, context) for c in cond.any_)
    if cond.not_ is not None:
        return not evaluate_condition(cond.not_, context)
    if cond.field is None:  # pragma: no cover - guaranteed by schema validation
        raise PolicyError("leaf condition without a field")
    return _apply(cond, resolve(context, cond.field))


def _target_matches(patterns: list[str], value: Any) -> bool:
    if not isinstance(value, str):
        return patterns == ["*"]
    return any(fnmatch.fnmatchcase(value, p) for p in patterns)


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    matched_rules: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)


def _reason(rule: Rule, verb: str) -> str:
    detail = f": {rule.description}" if rule.description else ""
    return f"{verb} by rule '{rule.id}'{detail}"


class PolicyEngine:
    """The built-in YAML policy engine (the ``yaml`` backend)."""

    name = "yaml"

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def close(self) -> None:
        pass

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> PolicyEngine:
        try:
            return cls(Policy.model_validate(raw))
        except ValidationError as exc:
            raise PolicyError(f"invalid policy: {exc}") from exc

    @classmethod
    def from_file(cls, path: str | Path) -> PolicyEngine:
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise PolicyError(f"policy file not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise PolicyError(f"policy file is not valid YAML: {exc}") from exc
        if not isinstance(raw, Mapping):
            raise PolicyError("policy file must contain a mapping")
        return cls.from_dict(raw)

    def matching_rules(self, context: Mapping[str, Any]) -> list[Rule]:
        matched = []
        for rule in self.policy.rules:
            if not _target_matches(rule.agents, resolve(context, "agent.id")):
                continue
            if not _target_matches(rule.users, resolve(context, "user.id")):
                continue
            if not _target_matches(rule.tools, resolve(context, "tool.name")):
                continue
            if all(evaluate_condition(c, context) for c in rule.when):
                matched.append(rule)
        return matched

    def evaluate(self, context: Mapping[str, Any]) -> PolicyDecision:
        matched = self.matching_rules(context)
        ids = [r.id for r in matched]
        denies = [r for r in matched if r.effect is Decision.DENY]
        if denies:
            return PolicyDecision(Decision.DENY, ids, [_reason(r, "denied") for r in denies])
        allows = [r for r in matched if r.effect is Decision.ALLOW]
        if not allows:
            return PolicyDecision(
                Decision.DENY, ids, ["no policy rule allows this request (default deny)"]
            )
        approvals = [r for r in matched if r.effect is Decision.REQUIRE_APPROVAL]
        if approvals:
            return PolicyDecision(
                Decision.REQUIRE_APPROVAL,
                ids,
                [_reason(r, "human approval required") for r in approvals],
            )
        return PolicyDecision(Decision.ALLOW, ids, [_reason(r, "allowed") for r in allows])
