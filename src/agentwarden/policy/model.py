"""Policy document schema.

A policy is a list of rules. Each rule has an ``effect`` (``allow``, ``deny`` or
``require_approval``), optional *targets* (agent, user and tool globs), and ``when``
conditions that are ANDed together. Conditions can be nested with ``all``, ``any`` and ``not``.

Combining algorithm (see :mod:`agentwarden.policy.engine`):

1. any matching ``deny`` rule → **deny**
2. no matching ``allow`` rule → **deny** (default deny, not configurable)
3. a matching ``allow`` *and* a matching ``require_approval`` rule → **require approval**
4. otherwise → **allow**

``require_approval`` rules are an extra gate on top of what is allowed. They never grant access
on their own, so a human approval cannot unlock something policy does not permit.
"""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

from agentwarden.models import Decision

Operator = Literal[
    "eq",
    "ne",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "starts_with",
    "ends_with",
    "glob",
    "regex",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "empty",
]

_FIELD_RE = re.compile(r"^[a-z_][a-z0-9_]*(\.[A-Za-z0-9_-]+)*$")
_LIST_OPS = {"in", "not_in"}
_NUMERIC_OPS = {"gt", "gte", "lt", "lte"}
_BOOL_OPS = {"exists", "empty"}
_STRING_OPS = {"starts_with", "ends_with", "glob", "regex"}


class Condition(BaseModel):
    """Either a leaf ``{field, op, value}`` or exactly one of ``all`` / ``any`` / ``not``."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    field: str | None = None
    op: Operator | None = None
    value: Any = None
    all_: list[Condition] | None = Field(default=None, alias="all")
    any_: list[Condition] | None = Field(default=None, alias="any")
    not_: Condition | None = Field(default=None, alias="not")

    _regex: re.Pattern[str] | None = PrivateAttr(default=None)

    @model_validator(mode="after")
    def _validate_shape(self) -> Condition:
        forms = [
            self.op is not None,
            self.all_ is not None,
            self.any_ is not None,
            self.not_ is not None,
        ]
        if sum(forms) != 1:
            raise ValueError(
                "a condition must be exactly one of: {field, op, value} | all | any | not"
            )
        if self.op is None:
            if self.field is not None or self.value is not None:
                raise ValueError("'field'/'value' are only valid on leaf conditions")
            for group in (self.all_, self.any_):
                if group is not None and not group:
                    raise ValueError("'all'/'any' need at least one condition")
            return self

        if self.field is None or not _FIELD_RE.fullmatch(self.field):
            raise ValueError(f"invalid field path {self.field!r} (expected e.g. 'args.to')")
        op, value = self.op, self.value
        if op in _LIST_OPS and not isinstance(value, list):
            raise ValueError(f"operator '{op}' needs a list value")
        if op in _NUMERIC_OPS and (isinstance(value, bool) or not isinstance(value, int | float)):
            raise ValueError(f"operator '{op}' needs a numeric value")
        if op in _BOOL_OPS and not isinstance(value, bool):
            raise ValueError(f"operator '{op}' needs a boolean value (true/false)")
        if op in _STRING_OPS and not isinstance(value, str):
            raise ValueError(f"operator '{op}' needs a string value")
        if op == "regex":
            try:
                self._regex = re.compile(value)
            except re.error as exc:
                raise ValueError(f"invalid regex {value!r}: {exc}") from exc
        return self

    @property
    def regex(self) -> re.Pattern[str] | None:
        return self._regex


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,79}$")
    description: str = ""
    effect: Decision
    agents: list[str] = Field(default_factory=lambda: ["*"], min_length=1)
    users: list[str] = Field(default_factory=lambda: ["*"], min_length=1)
    tools: list[str] = Field(default_factory=lambda: ["*"], min_length=1)
    when: list[Condition] = Field(default_factory=list)


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: Literal[1] = 1
    description: str = ""
    #: Fixed to "deny". It is a field only so policies state it explicitly.
    default_effect: Literal["deny"] = "deny"
    rules: list[Rule] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ids(self) -> Policy:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)
        if not any(rule.effect is Decision.ALLOW for rule in self.rules):
            raise ValueError("policy has no allow rules, so it would deny everything")
        return self


Condition.model_rebuild()
