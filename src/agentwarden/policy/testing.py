"""Policy-as-code unit tests.

A suite is a YAML file of cases. Each case gives a (partial) evaluation context and the expected
decision. Missing context fields are filled from :func:`base_context`, so cases stay short::

    policy: ../../src/agentwarden/data/policy.yaml   # optional, relative to this file
    cases:
      - name: internal email is allowed
        input:
          agent: { id: inbox-assistant, trust_tier: standard }
          tool: { name: send_email, risk: high, side_effect: external }
          facts: { recipients: [bob@acme.example] }
        expect: allow
        expect_rules: [allow-email]   # optional: these rules must have matched

Run with ``agentwarden policy test path/to/suite.yaml``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentwarden.errors import PolicyError
from agentwarden.models import Decision
from agentwarden.policy.backends import DEFAULT_OPA_PATH, load_backend
from agentwarden.policy.engine import base_context, deep_merge


class PolicyTestCase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    input: dict[str, Any] = Field(default_factory=dict)
    expect: Decision
    expect_rules: list[str] = Field(default_factory=list)


class PolicyTestSuite(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy: str | None = None
    cases: list[PolicyTestCase] = Field(min_length=1)


@dataclass(frozen=True)
class CaseResult:
    name: str
    passed: bool
    expected: Decision
    actual: Decision
    matched_rules: list[str]
    message: str = ""


def load_suite(path: str | Path) -> PolicyTestSuite:
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return PolicyTestSuite.model_validate(raw)
    except FileNotFoundError as exc:
        raise PolicyError(f"policy test suite not found: {path}") from exc
    except (yaml.YAMLError, ValidationError) as exc:
        raise PolicyError(f"invalid policy test suite {path}: {exc}") from exc


def run_suite(
    path: str | Path,
    policy_path: str | Path | None = None,
    *,
    backend: str = "yaml",
    opa_url: str | None = None,
    opa_path: str = DEFAULT_OPA_PATH,
) -> list[CaseResult]:
    """Run every case in the suite against a policy backend.

    ``policy_path`` overrides the suite's own ``policy`` key. With ``backend="cedar"`` and no
    override, the ``.cedar`` file next to the suite's YAML policy is used (same stem), so one
    suite can check a policy and its Cedar port. With ``backend="opa"``, cases go to the OPA
    server at ``opa_url``.
    """
    path = Path(path)
    suite = load_suite(path)
    if policy_path is None and backend != "opa":
        if suite.policy is None:
            raise PolicyError(f"{path}: no policy given (use --policy or a 'policy' key)")
        policy_path = (path.parent / suite.policy).resolve()
        if backend == "cedar":
            policy_path = Path(policy_path).with_suffix(".cedar")
    engine = load_backend(backend, policy_path=policy_path, opa_url=opa_url, opa_path=opa_path)

    results = []
    for case in suite.cases:
        context = deep_merge(base_context(), case.input)
        outcome = engine.evaluate(context)
        missing = [r for r in case.expect_rules if r not in outcome.matched_rules]
        passed = outcome.decision is case.expect and not missing
        message = ""
        if outcome.decision is not case.expect:
            message = f"expected {case.expect.value}, got {outcome.decision.value}"
        elif missing:
            message = f"expected rules did not match: {', '.join(missing)}"
        results.append(
            CaseResult(
                name=case.name,
                passed=passed,
                expected=case.expect,
                actual=outcome.decision,
                matched_rules=outcome.matched_rules,
                message=message,
            )
        )
    return results
