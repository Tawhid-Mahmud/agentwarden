from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from agentwarden.config import DEFAULT_POLICY_PATH
from agentwarden.errors import PolicyError
from agentwarden.models import Decision
from agentwarden.policy import PolicyEngine, base_context
from agentwarden.policy.engine import deep_merge, evaluate_condition, resolve
from agentwarden.policy.model import Condition
from agentwarden.policy.testing import run_suite

SUITE = Path(__file__).parent / "policy" / "default_policy_cases.yaml"


def ctx(**overrides: Any) -> dict[str, Any]:
    return deep_merge(base_context(), overrides)


def cond(**kwargs: Any) -> Condition:
    return Condition.model_validate(kwargs)


def engine(*rules: dict[str, Any]) -> PolicyEngine:
    return PolicyEngine.from_dict({"version": 1, "rules": list(rules)})


ALLOW_ALL = {"id": "allow-all", "effect": "allow"}


# ----------------------------------------------------------------------------- operators
@pytest.mark.parametrize(
    ("condition", "context", "expected"),
    [
        ({"field": "agent.id", "op": "eq", "value": "Bot"}, {"agent": {"id": "bot"}}, True),
        ({"field": "agent.id", "op": "ne", "value": "bot"}, {"agent": {"id": "bot"}}, False),
        ({"field": "args.n", "op": "gt", "value": 3}, {"args": {"n": 4}}, True),
        ({"field": "args.n", "op": "lte", "value": 3}, {"args": {"n": 4}}, False),
        ({"field": "args.n", "op": "gte", "value": 3}, {"args": {"n": "4"}}, False),
        ({"field": "args.n", "op": "lt", "value": 1}, {"args": {"n": True}}, False),
        (
            {"field": "args.to", "op": "ends_with", "value": "@acme.example"},
            {"args": {"to": ["a@ACME.example", "b@acme.example"]}},
            True,
        ),
        (
            {"field": "args.to", "op": "ends_with", "value": "@acme.example"},
            {"args": {"to": ["a@acme.example", "x@evil.example"]}},
            False,
        ),
        (
            {"field": "args.to", "op": "ends_with", "value": "@acme.example"},
            {"args": {"to": []}},
            False,
        ),
        (
            {"field": "args.p", "op": "starts_with", "value": "/workspace/"},
            {"args": {"p": "/workspace/a"}},
            True,
        ),
        (
            {"field": "args.p", "op": "glob", "value": "/workspace/*.md"},
            {"args": {"p": "/workspace/x.md"}},
            True,
        ),
        ({"field": "args.p", "op": "regex", "value": "^/tmp/"}, {"args": {"p": "/TMP/x"}}, False),
        (
            {"field": "args.p", "op": "regex", "value": "(?i)^/tmp/"},
            {"args": {"p": "/TMP/x"}},
            True,
        ),
        ({"field": "args.m", "op": "in", "value": ["GET", "HEAD"]}, {"args": {"m": "get"}}, True),
        (
            {"field": "args.m", "op": "in", "value": ["GET"]},
            {"args": {"m": ["GET", "POST"]}},
            False,
        ),
        (
            {"field": "args.m", "op": "not_in", "value": ["POST"]},
            {"args": {"m": ["GET", "HEAD"]}},
            True,
        ),
        (
            {"field": "risk.signals", "op": "contains", "value": "x"},
            {"risk": {"signals": ["x", "y"]}},
            True,
        ),
        (
            {"field": "args.body", "op": "contains", "value": "SECRET"},
            {"args": {"body": "a secret"}},
            True,
        ),
        (
            {"field": "args.body", "op": "not_contains", "value": "z"},
            {"args": {"body": "abc"}},
            True,
        ),
        ({"field": "args.body", "op": "contains", "value": "z"}, {"args": {"body": 5}}, False),
        ({"field": "args.x", "op": "exists", "value": True}, {"args": {"x": 0}}, True),
        ({"field": "args.x", "op": "exists", "value": False}, {"args": {}}, True),
        ({"field": "args.x", "op": "empty", "value": True}, {"args": {"x": []}}, True),
        ({"field": "args.x", "op": "empty", "value": False}, {"args": {"x": "y"}}, True),
        (
            {"field": "actor_chain.1", "op": "eq", "value": "root"},
            {"actor_chain": ["a", "root"]},
            True,
        ),
    ],
)
def test_operators(condition: dict[str, Any], context: dict[str, Any], expected: bool) -> None:
    assert evaluate_condition(cond(**condition), ctx(**context)) is expected


@pytest.mark.parametrize(
    "op", ["eq", "ne", "in", "not_in", "contains", "not_contains", "gt", "glob"]
)
def test_missing_fields_never_satisfy_comparisons(op: str) -> None:
    value: Any = ["x"] if op in ("in", "not_in") else (1 if op == "gt" else "x")
    assert evaluate_condition(cond(field="args.nope", op=op, value=value), ctx()) is False


def test_combinators() -> None:
    c = cond(
        any=[
            {
                "all": [
                    {"field": "a", "op": "eq", "value": 1},
                    {"field": "b", "op": "eq", "value": 2},
                ]
            },
            {"not": {"field": "c", "op": "exists", "value": True}},
        ]
    )
    assert evaluate_condition(c, {"a": 1, "b": 2, "c": 1})
    assert evaluate_condition(c, {"a": 1, "b": 3})
    assert not evaluate_condition(c, {"a": 1, "b": 3, "c": 0})


def test_resolve_handles_lists_and_missing() -> None:
    from agentwarden.policy.engine import MISSING

    data = {"a": {"b": [{"c": 1}]}}
    assert resolve(data, "a.b.0.c") == 1
    assert resolve(data, "a.b.5.c") is MISSING
    assert resolve(data, "a.x") is MISSING


# ----------------------------------------------------------------------------- validation
@pytest.mark.parametrize(
    "bad",
    [
        {"field": "args.x", "op": "in", "value": "not-a-list"},
        {"field": "args.x", "op": "gt", "value": "3"},
        {"field": "args.x", "op": "gt", "value": True},
        {"field": "args.x", "op": "exists", "value": "yes"},
        {"field": "args.x", "op": "regex", "value": "(unclosed"},
        {"field": "args.x", "op": "glob", "value": 3},
        {"field": "Args X", "op": "eq", "value": 1},
        {"op": "eq", "value": 1},
        {"field": "args.x", "op": "teleport", "value": 1},
        {"all": []},
        {
            "all": [{"field": "a", "op": "eq", "value": 1}],
            "any": [{"field": "a", "op": "eq", "value": 1}],
        },
        {"field": "args.x", "all": [{"field": "a", "op": "eq", "value": 1}]},
    ],
)
def test_invalid_conditions_rejected(bad: dict[str, Any]) -> None:
    with pytest.raises(PolicyError):
        engine({**ALLOW_ALL, "when": [bad]})


def test_policy_level_validation() -> None:
    with pytest.raises(PolicyError, match="duplicate rule id"):
        engine(ALLOW_ALL, ALLOW_ALL)
    with pytest.raises(PolicyError, match="no allow rules"):
        engine({"id": "d", "effect": "deny"})
    with pytest.raises(PolicyError):
        PolicyEngine.from_dict({"version": 1, "default_effect": "allow", "rules": [ALLOW_ALL]})
    with pytest.raises(PolicyError):
        PolicyEngine.from_dict({"version": 1, "rules": [{**ALLOW_ALL, "unknown": 1}]})


def test_policy_file_errors(tmp_path: Path) -> None:
    with pytest.raises(PolicyError, match="not found"):
        PolicyEngine.from_file(tmp_path / "missing.yaml")
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules: [unclosed")
    with pytest.raises(PolicyError, match="not valid YAML"):
        PolicyEngine.from_file(bad)
    scalar = tmp_path / "scalar.yaml"
    scalar.write_text("just a string")
    with pytest.raises(PolicyError, match="mapping"):
        PolicyEngine.from_file(scalar)


# ----------------------------------------------------------------------------- precedence
def test_default_deny_when_nothing_matches() -> None:
    e = engine({"id": "allow-docs", "effect": "allow", "tools": ["search_docs"]})
    result = e.evaluate(ctx(tool={"name": "send_email"}))
    assert result.decision is Decision.DENY
    assert "default deny" in result.reasons[0]


def test_deny_overrides_allow_and_approval() -> None:
    e = engine(
        ALLOW_ALL,
        {"id": "approve", "effect": "require_approval"},
        {"id": "deny", "effect": "deny", "description": "nope"},
    )
    result = e.evaluate(ctx())
    assert result.decision is Decision.DENY
    assert result.reasons == ["denied by rule 'deny': nope"]
    assert result.matched_rules == ["allow-all", "approve", "deny"]


def test_approval_requires_an_allow() -> None:
    approve = {"id": "approve", "effect": "require_approval"}
    assert engine(ALLOW_ALL, approve).evaluate(ctx()).decision is Decision.REQUIRE_APPROVAL
    only_approve = engine({"id": "allow-other", "effect": "allow", "tools": ["x"]}, approve)
    assert only_approve.evaluate(ctx(tool={"name": "y"})).decision is Decision.DENY


def test_targets_use_globs() -> None:
    e = engine(
        {
            "id": "a",
            "effect": "allow",
            "agents": ["inbox-*"],
            "users": ["alice"],
            "tools": ["read_*"],
        }
    )
    ok = ctx(agent={"id": "inbox-assistant"}, user={"id": "alice"}, tool={"name": "read_file"})
    assert e.evaluate(ok).decision is Decision.ALLOW
    assert e.evaluate(deep_merge(ok, {"user": {"id": "bob"}})).decision is Decision.DENY
    assert e.evaluate(deep_merge(ok, {"agent": {"id": "research-agent"}})).decision is Decision.DENY


# ----------------------------------------------------------------------------- policy tests
def test_default_policy_loads() -> None:
    policy = PolicyEngine.from_file(DEFAULT_POLICY_PATH).policy
    assert policy.default_effect == "deny"
    assert any(r.id == "deny-hijacked-exfiltration" for r in policy.rules)


def test_default_policy_suite_passes() -> None:
    results = run_suite(SUITE)
    failures = [f"{r.name}: {r.message}" for r in results if not r.passed]
    assert not failures, failures
    assert len(results) >= 20


def test_suite_reports_failures(tmp_path: Path) -> None:
    suite = tmp_path / "suite.yaml"
    suite.write_text(
        f"policy: {DEFAULT_POLICY_PATH}\n"
        "cases:\n"
        "  - name: wrong expectation\n"
        "    input: {tool: {name: search_docs, side_effect: read}}\n"
        "    expect: deny\n"
        "  - name: wrong rule\n"
        "    input: {tool: {name: search_docs, side_effect: read}}\n"
        "    expect: allow\n"
        "    expect_rules: [allow-email]\n"
    )
    first, second = run_suite(suite)
    assert not first.passed and "expected deny, got allow" in first.message
    assert not second.passed and "allow-email" in second.message


def test_suite_needs_a_policy(tmp_path: Path) -> None:
    suite = tmp_path / "suite.yaml"
    suite.write_text("cases:\n  - {name: x, expect: allow}\n")
    with pytest.raises(PolicyError, match="no policy given"):
        run_suite(suite)
    with pytest.raises(PolicyError, match="not found"):
        run_suite(tmp_path / "nope.yaml")
