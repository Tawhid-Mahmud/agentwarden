"""Policy backends: the built-in YAML engine, Open Policy Agent (Rego) and Cedar.

Every backend gets the same evaluation context (see :func:`~agentwarden.policy.base_context`)
and returns a :class:`~agentwarden.policy.PolicyDecision`: ``allow``, ``deny`` or
``require_approval``, the rules that decided, and human-readable reasons. The gateway's
deterministic checks (token, scopes, kill switch, known tool) run before any backend, so a backend
can only make decisions stricter, never grant what a token doesn't carry.

Every backend **fails closed**. An unreachable OPA, an undefined decision, a malformed answer, or
a Cedar policy that errors during evaluation all produce ``deny``.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

import httpx

from agentwarden.errors import PolicyError
from agentwarden.models import Decision
from agentwarden.policy.engine import PolicyDecision, PolicyEngine

BACKENDS = ("yaml", "opa", "cedar")
DEFAULT_OPA_PATH = "agentwarden/authz/decision"


class PolicyBackend(Protocol):
    name: str

    def evaluate(self, context: Mapping[str, Any]) -> PolicyDecision: ...

    def close(self) -> None: ...


def _deny(reason: str, rules: list[str] | None = None) -> PolicyDecision:
    return PolicyDecision(Decision.DENY, rules or [], [reason])


# ======================================================================================= OPA
class OpaPolicy:
    """Asks an OPA server (usually a sidecar) through its Data API.

    ``POST {url}/v1/data/{path}`` with ``{"input": context}``. The rule at ``path`` must evaluate
    to ``{"decision": "allow" | "deny" | "require_approval", "rules": [...], "reasons": [...]}``.
    ``data/policy.rego`` is the default policy ported to Rego.
    """

    name = "opa"

    def __init__(
        self,
        url: str,
        path: str = DEFAULT_OPA_PATH,
        *,
        token: str | None = None,
        timeout: float = 2.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise PolicyError(f"OPA URL must be http(s): {url!r}")
        self.endpoint = f"{url.rstrip('/')}/v1/data/{path.strip('/')}"
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        self._client = httpx.Client(
            headers=headers, timeout=timeout, transport=transport, follow_redirects=False
        )

    def evaluate(self, context: Mapping[str, Any]) -> PolicyDecision:
        try:
            response = self._client.post(self.endpoint, json={"input": context})
        except httpx.HTTPError as exc:
            return _deny(f"policy backend unavailable (OPA: {type(exc).__name__}); failing closed")
        if response.status_code != 200:
            return _deny(f"policy backend error (OPA HTTP {response.status_code}); failing closed")
        try:
            body = response.json()
        except json.JSONDecodeError:
            return _deny("OPA returned invalid JSON; failing closed")
        result = body.get("result") if isinstance(body, dict) else None
        if result is None:
            return _deny(f"OPA has no decision at {self.endpoint} (undefined); failing closed")
        return self._parse(result)

    @staticmethod
    def _parse(result: Any) -> PolicyDecision:
        if not isinstance(result, dict):
            return _deny("OPA decision must be an object; failing closed")
        try:
            decision = Decision(str(result.get("decision")))
        except ValueError:
            return _deny(
                f"OPA returned unknown decision {result.get('decision')!r}; failing closed"
            )
        rules = result.get("rules", [])
        reasons = result.get("reasons", [])
        if not (
            isinstance(rules, list)
            and isinstance(reasons, list)
            and all(isinstance(x, str) for x in [*rules, *reasons])
        ):
            return _deny("OPA decision has malformed rules/reasons; failing closed")
        return PolicyDecision(decision, list(rules), list(reasons) or [f"{decision.value} by OPA"])

    def close(self) -> None:
        self._client.close()


# ===================================================================================== Cedar
CALL = 'Action::"call"'
UNATTENDED = 'Action::"call_unattended"'


def _cedar_value(value: Any) -> Any:
    """Cedar has no null or floats: drop ``None``, and pass fractions as ``decimal``."""
    if isinstance(value, bool | str):
        return value
    if isinstance(value, int):
        return value if -(2**63) <= value < 2**63 else str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            return str(value)
        return {"__extn": {"fn": "decimal", "arg": f"{value:.4f}"}}
    if isinstance(value, Mapping):
        return {str(k): _cedar_value(v) for k, v in value.items() if v is not None}
    if isinstance(value, list | tuple | set):
        return [_cedar_value(v) for v in value if v is not None]
    return str(value)


def cedar_request(context: Mapping[str, Any], action: str) -> tuple[dict[str, Any], list[Any]]:
    """The Cedar request and entities for one evaluation context.

    * principal ``Agent::"<id>"`` with ``trust_tier`` and ``owner``
    * action ``Action::"call"`` (may this happen at all?) or ``Action::"call_unattended"`` (may it
      happen without a human?)
    * resource ``Tool::"<name>"`` with ``scope``, ``risk`` and ``side_effect``
    * context: everything else (``user``, ``actor_chain``, ``delegation``, ``args``, ``risk``,
      ``facts``, ``token``, ``time``). ``risk.score`` is a ``decimal``; ``risk.score_pct`` is the
      same score as an integer percentage, which is easier to compare against.
    """
    agent = context.get("agent") or {}
    tool = context.get("tool") or {}
    risk = dict(context.get("risk") or {})
    score = float(risk.get("score") or 0.0)
    risk["score_pct"] = math.floor(score * 100 + 1e-9)
    rest = {
        k: v for k, v in context.items() if k not in ("agent", "tool", "risk") and v is not None
    }
    rest["risk"] = risk
    agent_id, tool_name = str(agent.get("id") or "unknown"), str(tool.get("name") or "unknown")
    entities = [
        {
            "uid": {"type": "Agent", "id": agent_id},
            "attrs": _cedar_value({k: agent.get(k) for k in ("trust_tier", "owner")}),
            "parents": [],
        },
        {
            "uid": {"type": "Tool", "id": tool_name},
            "attrs": _cedar_value({k: tool.get(k) for k in ("scope", "risk", "side_effect")}),
            "parents": [],
        },
    ]
    request = {
        "principal": f"Agent::{json.dumps(agent_id)}",
        "action": action,
        "resource": f"Tool::{json.dumps(tool_name)}",
        "context": _cedar_value(rest),
    }
    return request, entities


class CedarPolicy:
    """Evaluates Cedar policies in-process (``pip install 'agentwarden[cedar]'``).

    Cedar only permits or forbids, so a call is asked twice: ``call`` (permit/forbid it at all)
    and, if permitted, ``call_unattended`` (forbid it without a human = ``require_approval``).
    Rules are named by their ``@id("...")`` annotation and explained by ``@description``.
    ``data/policy.cedar`` is the default policy ported to Cedar.
    """

    name = "cedar"

    def __init__(self, policies: str) -> None:
        try:
            import cedarpy
        except ImportError as exc:  # pragma: no cover - depends on the environment
            raise PolicyError(
                "the Cedar backend needs cedarpy: pip install 'agentwarden[cedar]'"
            ) from exc
        self._cedar = cedarpy
        try:
            parsed = json.loads(cedarpy.policies_to_json_str(policies))
        except Exception as exc:  # cedarpy raises plain exceptions for parse errors
            raise PolicyError(f"invalid Cedar policies: {exc}") from exc
        self._policies = policies
        self._names: dict[str, str] = {}
        self._descriptions: dict[str, str] = {}
        for pid, policy in parsed.get("staticPolicies", {}).items():
            annotations = policy.get("annotations") or {}
            self._names[pid] = annotations.get("id") or pid
            if annotations.get("description"):
                self._descriptions[pid] = annotations["description"]

    @classmethod
    def from_file(cls, path: str | Path) -> CedarPolicy:
        try:
            return cls(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise PolicyError(f"Cedar policy file not found: {path}") from exc

    @property
    def rule_count(self) -> int:
        return len(self._names)

    def close(self) -> None:
        pass

    def _ask(self, context: Mapping[str, Any], action: str) -> tuple[bool, list[str], list[str]]:
        request, entities = cedar_request(context, action)
        result = self._cedar.is_authorized(request, self._policies, entities)
        return (
            bool(result.allowed),
            list(result.diagnostics.reasons),
            list(result.diagnostics.errors),
        )

    def _reason(self, pid: str, verb: str) -> str:
        detail = self._descriptions.get(pid)
        return f"{verb} by rule '{self._names.get(pid, pid)}'" + (f": {detail}" if detail else "")

    def evaluate(self, context: Mapping[str, Any]) -> PolicyDecision:
        allowed, reasons, errors = self._ask(context, CALL)
        if errors:  # Cedar skips a policy that errors: for a forbid, that would fail open
            return _deny(f"Cedar policy evaluation error ({errors[0]}); failing closed")
        names = [self._names.get(p, p) for p in reasons]
        if not allowed:
            if not reasons:
                # Nothing permits it. Like the YAML engine, still report which gates matched.
                unattended, gates, _ = self._ask(context, UNATTENDED)
                matched = [] if unattended else [self._names.get(p, p) for p in gates]
                return _deny("no policy permits this request (default deny)", matched)
            return PolicyDecision(
                Decision.DENY, names, [self._reason(p, "denied") for p in reasons]
            )
        unattended, gates, errors = self._ask(context, UNATTENDED)
        if errors:
            return _deny(f"Cedar policy evaluation error ({errors[0]}); failing closed")
        if not unattended:
            gate_names = [self._names.get(p, p) for p in gates]
            return PolicyDecision(
                Decision.REQUIRE_APPROVAL,
                names + gate_names,
                [self._reason(p, "human approval required") for p in gates]
                or ["human approval required (no policy permits this call unattended)"],
            )
        return PolicyDecision(Decision.ALLOW, names, [self._reason(p, "allowed") for p in reasons])


# ===================================================================================== setup
def load_backend(
    backend: str,
    *,
    policy_path: str | Path | None = None,
    opa_url: str | None = None,
    opa_path: str = DEFAULT_OPA_PATH,
    opa_token: str | None = None,
    opa_timeout: float = 2.0,
) -> PolicyEngine | OpaPolicy | CedarPolicy:
    if backend == "yaml":
        if policy_path is None:
            raise PolicyError("the YAML backend needs a policy file")
        return PolicyEngine.from_file(policy_path)
    if backend == "cedar":
        if policy_path is None:
            raise PolicyError("the Cedar backend needs a .cedar policy file")
        return CedarPolicy.from_file(policy_path)
    if backend == "opa":
        if not opa_url:
            raise PolicyError("the OPA backend needs AGENTWARDEN_OPA_URL")
        return OpaPolicy(opa_url, opa_path, token=opa_token, timeout=opa_timeout)
    raise PolicyError(f"unknown policy backend {backend!r}; use one of {', '.join(BACKENDS)}")
