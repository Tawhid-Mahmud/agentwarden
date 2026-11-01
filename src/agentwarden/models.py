"""Core domain models shared by every AgentWarden component."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

SCOPE_PATTERN = r"^[a-z][a-z0-9_-]*(:[a-z0-9_*-]+)+$"
AGENT_ID_PATTERN = r"^[a-z0-9][a-z0-9_-]{1,63}$"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]

    @classmethod
    def from_score(cls, score: float) -> RiskLevel:
        """Map a 0..1 risk score onto a coarse level."""
        if score >= 0.85:
            return cls.CRITICAL
        if score >= 0.6:
            return cls.HIGH
        if score >= 0.3:
            return cls.MEDIUM
        return cls.LOW


_RISK_RANK = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2, RiskLevel.CRITICAL: 3}


class SideEffect(StrEnum):
    """What a tool can do to the world. ``external`` means data can leave the organization."""

    NONE = "none"
    READ = "read"
    WRITE = "write"
    EXTERNAL = "external"


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


class TrustTier(StrEnum):
    UNTRUSTED = "untrusted"
    STANDARD = "standard"
    PRIVILEGED = "privileged"


class Tool(BaseModel):
    """A capability an agent can invoke, and the scope required to invoke it."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]{0,63}$")
    scope: str = Field(pattern=SCOPE_PATTERN)
    risk: RiskLevel = RiskLevel.LOW
    side_effect: SideEffect = SideEffect.NONE
    description: str = ""


class User(BaseModel):
    """A human principal that agents act on behalf of."""

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,63}$")
    name: str = ""
    roles: list[str] = Field(default_factory=list)
    entitlements: list[str] = Field(default_factory=list)
    api_key_sha256: str | None = Field(default=None, exclude=True, repr=False)


class Agent(BaseModel):
    """A non-human identity. ``scope_ceiling`` is the maximum it may ever be granted."""

    id: str = Field(pattern=AGENT_ID_PATTERN)
    name: str = Field(min_length=1, max_length=120)
    owner: str = Field(min_length=1, max_length=64)
    description: str = Field(default="", max_length=1000)
    scope_ceiling: list[str] = Field(min_length=1, max_length=100)
    trust_tier: TrustTier = TrustTier.STANDARD
    enabled: bool = True
    created_at: datetime | None = None


class ContextSegment(BaseModel):
    """A piece of content the agent has seen. Untrusted unless explicitly marked otherwise.

    Agents should report tool outputs, retrieved documents and web pages here so the gateway can
    reason about the *provenance* of the data that ends up in tool-call arguments.
    """

    source: str = Field(min_length=1, max_length=200)
    content: str = Field(max_length=200_000)
    trusted: bool = False


class AuthorizeRequest(BaseModel):
    """An agent asking: "may I call ``tool`` with ``args`` right now?"."""

    tool: str = Field(min_length=1, max_length=64)
    args: dict[str, Any] = Field(default_factory=dict)
    user_prompt: str | None = Field(default=None, max_length=100_000)
    context: list[ContextSegment] = Field(default_factory=list, max_length=100)
    approval_id: str | None = Field(default=None, max_length=64)


class RiskSignal(BaseModel):
    """One piece of evidence produced by a detector."""

    detector: str
    name: str
    weight: float = Field(ge=0.0, le=1.0)
    evidence: str = ""
    location: str | None = None


class RiskAssessment(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    level: RiskLevel
    signals: list[RiskSignal] = Field(default_factory=list)

    @property
    def signal_names(self) -> list[str]:
        return sorted({s.name for s in self.signals})


class AuthorizationResult(BaseModel):
    decision_id: str
    decision: Decision
    tool: str
    reasons: list[str]
    matched_rules: list[str] = Field(default_factory=list)
    risk: RiskAssessment
    approval_id: str | None = None
    user_id: str | None = None
    agent_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


class TokenRequest(BaseModel):
    agent_id: str = Field(pattern=AGENT_ID_PATTERN)
    scopes: list[str] = Field(min_length=1, max_length=50)
    task: str | None = Field(default=None, max_length=500)
    ttl_seconds: int | None = Field(default=None, ge=30, le=86_400)


class DelegationRequest(BaseModel):
    sub_agent_id: str = Field(pattern=AGENT_ID_PATTERN)
    scopes: list[str] = Field(min_length=1, max_length=50)
    ttl_seconds: int | None = Field(default=None, ge=30, le=86_400)


class IssuedToken(BaseModel):
    access_token: str = Field(repr=False)
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105
    expires_in: int
    expires_at: datetime
    scope: list[str]
    denied_scopes: list[str] = Field(default_factory=list)
    jti: str
    actor_chain: list[str]


class AuditEvent(BaseModel):
    seq: int
    ts: datetime
    event_type: str
    user_id: str | None = None
    agent_id: str | None = None
    tool: str | None = None
    decision: str | None = None
    data: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    hash: str
