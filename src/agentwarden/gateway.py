"""The AgentWarden gateway: the policy enforcement point for agent tool calls.

``authorize`` runs these steps in order. Every outcome, including failures, is audited.

1. **Authenticate**: verify the agent token (signature, claims, revocation).
2. **Continuous checks**: every agent in the actor chain is registered and enabled; the user still
   exists; the tool is known; the token carries the tool's scope, and that scope is still within
   the user's entitlements and the agent's *current* ceiling.
3. **Risk**: detectors score the call with the context the agent saw.
4. **Policy**: deny-by-default evaluation over identity, tool, arguments, facts and risk.
5. **Approval**: ``require_approval`` decisions create (or consume) a bound, single-use approval.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from agentwarden.analyzer import AnalyzerReport, LeastPrivilegeAnalyzer
from agentwarden.approvals import ApprovalQueue, ApprovalRequest, preview_args
from agentwarden.audit import AUTHZ_EVENT, AuditLog, canonical_json
from agentwarden.config import Settings
from agentwarden.directory import Directory
from agentwarden.errors import AgentWardenError, AuthenticationError, InvalidRequestError
from agentwarden.identity import (
    AgentRegistry,
    KeyManager,
    KeyRing,
    RevocationList,
    TokenClaims,
    TokenService,
)
from agentwarden.identity.keys import SigningKeys
from agentwarden.identity.oidc import OidcVerifier
from agentwarden.identity.scopes import covered_by_any
from agentwarden.models import (
    Agent,
    AuthorizationResult,
    AuthorizeRequest,
    Decision,
    DelegationRequest,
    IssuedToken,
    RiskAssessment,
    RiskLevel,
    TokenRequest,
    Tool,
    User,
)
from agentwarden.policy import PolicyEngine
from agentwarden.risk import DetectionContext, Detector, RiskEngine, compute_facts, flatten_strings
from agentwarden.risk.text import CallFacts
from agentwarden.storage import Database

_NO_RISK = RiskAssessment(score=0.0, level=RiskLevel.LOW, signals=[])


def _new_decision_id() -> str:
    return "dec_" + secrets.token_hex(8)


@dataclass
class _Outcome:
    decision: Decision
    reasons: list[str]
    matched_rules: list[str]
    risk: RiskAssessment
    approval_id: str | None = None


class Gateway:
    def __init__(
        self,
        *,
        settings: Settings,
        db: Database,
        directory: Directory,
        registry: AgentRegistry,
        revocations: RevocationList,
        keys: SigningKeys,
        tokens: TokenService,
        policy: PolicyEngine,
        risk: RiskEngine,
        approvals: ApprovalQueue,
        audit: AuditLog,
        clock: Callable[[], float] = time.time,
        oidc: OidcVerifier | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.directory = directory
        self.registry = registry
        self.revocations = revocations
        self.keys = keys
        self.tokens = tokens
        self.policy = policy
        self.risk = risk
        self.approvals = approvals
        self.audit = audit
        self.oidc = oidc
        self._clock = clock

    @classmethod
    def build(
        cls,
        settings: Settings | None = None,
        *,
        clock: Callable[[], float] = time.time,
        extra_detectors: Sequence[Detector] = (),
        oidc: OidcVerifier | None = None,
    ) -> Gateway:
        """Wire up a gateway from settings (defaults: environment variables)."""
        settings = settings or Settings.from_env()
        db = Database(settings.db_path)
        directory = Directory.load(settings.directory_path)
        registry = AgentRegistry(db)
        registry.seed(directory.seed_agents)
        revocations = RevocationList(db, clock=clock)
        keys: SigningKeys
        if settings.signing_key_dir is not None:
            keys = KeyRing.open(
                settings.signing_key_dir, grace_seconds=settings.key_grace_seconds, clock=clock
            )
        else:
            keys = KeyManager.load_or_generate(settings.signing_key_path)
        audit = AuditLog(db, keys=keys, clock=clock)
        detectors = list(extra_detectors)
        if settings.llm_judge_enabled:
            from agentwarden.risk.llm_judge import ClaudeInjectionJudge

            detectors.append(ClaudeInjectionJudge(model=settings.llm_judge_model))
        return cls(
            settings=settings,
            db=db,
            directory=directory,
            registry=registry,
            revocations=revocations,
            keys=keys,
            tokens=TokenService(keys, settings, revocations, clock=clock),
            policy=PolicyEngine.from_file(settings.policy_path),
            risk=RiskEngine.default(activity=audit, clock=clock, extra=detectors),
            approvals=ApprovalQueue(db, ttl=settings.approval_ttl, clock=clock),
            audit=audit,
            clock=clock,
            oidc=oidc or cls._oidc_from(settings, clock),
        )

    @staticmethod
    def _oidc_from(settings: Settings, clock: Callable[[], float]) -> OidcVerifier | None:
        if not settings.oidc_issuer or not settings.oidc_audience:
            return None
        return OidcVerifier(
            issuer=settings.oidc_issuer,
            audience=settings.oidc_audience,
            jwks_url=settings.oidc_jwks_url,
            clock_skew=settings.clock_skew_seconds,
            clock=clock,
        )

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> Gateway:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # =================================================================== tokens
    def issue_token(self, user: User, request: TokenRequest) -> IssuedToken:
        agent = self.registry.require(request.agent_id)
        try:
            issued = self.tokens.issue(
                user=user,
                agent=agent,
                scopes=request.scopes,
                task=request.task,
                ttl=request.ttl_seconds,
            )
        except AgentWardenError as exc:
            self.audit.append(
                "token.denied",
                user_id=user.id,
                agent_id=agent.id,
                data={"reason": str(exc), "requested": request.scopes},
            )
            raise
        self.audit.append(
            "token.issued",
            user_id=user.id,
            agent_id=agent.id,
            data={
                "jti": issued.jti,
                "scopes": issued.scope,
                "denied_scopes": issued.denied_scopes,
                "task": request.task,
                "expires_at": issued.expires_at.isoformat(),
            },
        )
        return issued

    def authenticate_identity(self, id_token: str) -> User:
        """Resolve an IdP ID token to a directory user (OIDC sign-in)."""
        if self.oidc is None:
            raise AuthenticationError(
                "OIDC sign-in is not configured (set AGENTWARDEN_OIDC_ISSUER)"
            )
        claim = self.settings.oidc_user_claim
        try:
            identity = self.oidc.verify(id_token, require_verified_email=claim == "email")
        except AuthenticationError as exc:
            self.audit.append("auth.failed", data={"reason": str(exc), "operation": "oidc"})
            raise
        value = identity.email if claim == "email" else identity.subject
        user = self.directory.find_by_identity(claim=claim, value=value)
        if user is None:
            self.audit.append(
                "auth.failed",
                data={
                    "reason": "no directory user for this identity",
                    "operation": "oidc",
                    "issuer": identity.issuer,
                    "subject": identity.subject,
                },
            )
            raise AuthenticationError("signed in, but this identity has no AgentWarden user")
        return user

    def exchange_token(self, id_token: str, request: TokenRequest) -> IssuedToken:
        """RFC 8693 token exchange: an IdP ID token becomes a scoped agent token."""
        user = self.authenticate_identity(id_token)
        issued = self.issue_token(user, request)
        self.audit.append(
            "token.exchanged",
            user_id=user.id,
            agent_id=request.agent_id,
            data={"jti": issued.jti, "idp": self.oidc.issuer if self.oidc else None},
        )
        return issued

    def delegate_token(self, parent_token: str, request: DelegationRequest) -> IssuedToken:
        parent = self._verify(parent_token, context="token.delegate")
        disabled = self._disabled_agent(parent)
        if disabled:
            raise AuthenticationError(f"agent {disabled!r} in the delegation chain is disabled")
        sub_agent = self.registry.require(request.sub_agent_id)
        try:
            issued = self.tokens.delegate(
                parent=parent, sub_agent=sub_agent, scopes=request.scopes, ttl=request.ttl_seconds
            )
        except AgentWardenError as exc:
            self.audit.append(
                "token.delegation_denied",
                user_id=parent.user_id,
                agent_id=parent.agent_id,
                data={"reason": str(exc), "sub_agent": sub_agent.id, "requested": request.scopes},
            )
            raise
        self.audit.append(
            "token.delegated",
            user_id=parent.user_id,
            agent_id=parent.agent_id,
            data={
                "jti": issued.jti,
                "parent_jti": parent.jti,
                "sub_agent": sub_agent.id,
                "scopes": issued.scope,
                "denied_scopes": issued.denied_scopes,
                "actor_chain": issued.actor_chain,
            },
        )
        return issued

    def revoke_token(self, token: str, reason: str = "revoked by holder") -> TokenClaims:
        claims = self._verify(token, context="token.revoke")
        self.tokens.revoke(claims, reason)
        self.audit.append(
            "token.revoked",
            user_id=claims.user_id,
            agent_id=claims.agent_id,
            data={"jti": claims.jti, "reason": reason},
        )
        return claims

    def revoke_jti(self, jti: str, reason: str = "", actor: str = "admin") -> None:
        # Unknown expiry: keep the entry for the longest possible token lifetime.
        self.revocations.revoke_token(jti, self._clock() + self.settings.max_token_ttl, reason)
        self.audit.append("token.revoked", data={"jti": jti, "reason": reason, "by": actor})

    def revoke_subject(self, subject: str, reason: str = "", actor: str = "admin") -> float:
        if not subject.startswith(("user:", "agent:")):
            raise InvalidRequestError("subject must look like 'user:<id>' or 'agent:<id>'")
        cutoff = self.revocations.revoke_subject(subject, reason)
        self.audit.append(
            "subject.revoked", data={"subject": subject, "reason": reason, "by": actor}
        )
        return cutoff

    # =================================================================== agents
    def register_agent(self, agent: Agent, actor: str = "admin") -> Agent:
        if self.directory.get_user(agent.owner) is None:
            raise InvalidRequestError(f"owner {agent.owner!r} is not a known user")
        created = self.registry.register(agent)
        self.audit.append(
            "agent.registered",
            agent_id=created.id,
            data={
                "by": actor,
                "scope_ceiling": created.scope_ceiling,
                "trust_tier": created.trust_tier.value,
            },
        )
        return created

    def set_agent_enabled(
        self, agent_id: str, enabled: bool, actor: str = "admin", reason: str = ""
    ) -> Agent:
        agent = self.registry.set_enabled(agent_id, enabled)
        if not enabled:
            # Kill switch: also invalidate every outstanding token, so re-enabling later
            # doesn't resurrect credentials that may have leaked.
            self.revocations.revoke_subject(f"agent:{agent_id}", reason or "agent disabled")
        self.audit.append(
            "agent.enabled" if enabled else "agent.disabled",
            agent_id=agent_id,
            data={"by": actor, "reason": reason},
        )
        return agent

    # ===================================================================== keys
    def _ring(self) -> KeyRing:
        if not isinstance(self.keys, KeyRing):
            raise InvalidRequestError(
                "key rotation needs a key ring (set AGENTWARDEN_SIGNING_KEY_DIR)"
            )
        return self.keys

    def rotate_keys(self, actor: str = "admin") -> list[dict[str, Any]]:
        """Start signing with a new key; the old one keeps verifying until its grace period ends."""
        ring = self._ring()
        previous = ring.kid
        new = ring.rotate()
        self.audit.append(
            "keys.rotated", data={"by": actor, "new_kid": new.kid, "retired_kid": previous}
        )
        return self.key_status()

    def prune_keys(self, actor: str = "admin") -> list[str]:
        pruned = self._ring().prune()
        if pruned:
            self.audit.append("keys.pruned", data={"by": actor, "kids": pruned})
        return pruned

    def key_status(self) -> list[dict[str, Any]]:
        if not isinstance(self.keys, KeyRing):
            return [{"kid": self.keys.kid, "status": "active", "rotatable": False}]
        grace = self.keys.grace_seconds
        return [
            {
                "kid": e.kid,
                "status": e.status,
                "created_at": datetime.fromtimestamp(e.created_at, UTC).isoformat(
                    timespec="seconds"
                ),
                "verifies_tokens_until": (
                    datetime.fromtimestamp(e.retired_at + grace, UTC).isoformat(timespec="seconds")
                    if e.status == "retired" and e.retired_at is not None
                    else None
                ),
            }
            for e in self.keys.entries()
        ]

    def set_agent_scopes(self, agent_id: str, scopes: Sequence[str], actor: str = "admin") -> Agent:
        agent = self.registry.set_scope_ceiling(agent_id, scopes)
        self.audit.append(
            "agent.scopes_changed",
            agent_id=agent_id,
            data={"by": actor, "scope_ceiling": agent.scope_ceiling},
        )
        return agent

    # ================================================================ approvals
    def approve(self, approval_id: str, reviewer: User, note: str = "") -> ApprovalRequest:
        request = self.approvals.approve(approval_id, reviewer, note)
        self.audit.append(
            "approval.approved",
            user_id=request.user_id,
            agent_id=request.agent_id,
            tool=request.tool,
            data={"approval_id": approval_id, "reviewer": reviewer.id, "note": note},
        )
        return request

    def deny_approval(self, approval_id: str, reviewer: User, note: str = "") -> ApprovalRequest:
        request = self.approvals.deny(approval_id, reviewer, note)
        self.audit.append(
            "approval.denied",
            user_id=request.user_id,
            agent_id=request.agent_id,
            tool=request.tool,
            data={"approval_id": approval_id, "reviewer": reviewer.id, "note": note},
        )
        return request

    # ================================================================ reporting
    def analyze(self, window_days: int = 30) -> AnalyzerReport:
        return LeastPrivilegeAnalyzer(
            self.registry, self.audit, self.directory, clock=self._clock
        ).analyze(window_days)

    # ============================================================ authorization
    def authorize(self, token: str, request: AuthorizeRequest) -> AuthorizationResult:
        claims = self._verify(token, context="authorize", tool=request.tool)
        decision_id = _new_decision_id()
        outcome, tool, facts = self._decide(claims, request, decision_id)
        result = AuthorizationResult(
            decision_id=decision_id,
            decision=outcome.decision,
            tool=request.tool,
            reasons=outcome.reasons,
            matched_rules=outcome.matched_rules,
            risk=outcome.risk,
            approval_id=outcome.approval_id,
            user_id=claims.user_id,
            agent_id=claims.agent_id,
        )
        self.audit.append(
            AUTHZ_EVENT,
            user_id=claims.user_id,
            agent_id=claims.agent_id,
            tool=request.tool,
            decision=outcome.decision.value,
            data={
                "decision_id": decision_id,
                "actor_chain": list(claims.actor_chain),
                "token_jti": claims.jti,
                "task": claims.task,
                "scope": tool.scope if tool else None,
                "reasons": outcome.reasons,
                "matched_rules": outcome.matched_rules,
                "approval_id": outcome.approval_id,
                "risk": {
                    "score": outcome.risk.score,
                    "level": outcome.risk.level.value,
                    "signals": outcome.risk.signal_names,
                    "detectors": sorted({s.detector for s in outcome.risk.signals}),
                },
                "args": preview_args(request.args),
                "args_sha256": hashlib.sha256(canonical_json(request.args).encode()).hexdigest(),
                "facts": facts.as_dict() if facts else None,
                "context_sources": [s.source for s in request.context],
            },
        )
        return result

    def _decide(
        self, claims: TokenClaims, request: AuthorizeRequest, decision_id: str
    ) -> tuple[_Outcome, Tool | None, CallFacts | None]:
        def deny(
            reason: str, tool: Tool | None = None
        ) -> tuple[_Outcome, Tool | None, CallFacts | None]:
            return _Outcome(Decision.DENY, [reason], [], _NO_RISK), tool, None

        disabled = self._disabled_agent(claims)
        if disabled:
            return deny(f"agent {disabled!r} is disabled or unregistered (kill switch)")
        user = self.directory.get_user(claims.user_id)
        if user is None:
            return deny(f"user {claims.user_id!r} no longer exists")
        tool = self.directory.get_tool(request.tool)
        if tool is None:
            return deny(f"unknown tool {request.tool!r} (default deny)")
        if not covered_by_any(tool.scope, claims.scopes):
            return deny(
                f"token does not grant scope {tool.scope!r} required by {tool.name!r}", tool
            )
        agent = self.registry.require(claims.agent_id)
        if not covered_by_any(tool.scope, agent.scope_ceiling):
            return deny(f"scope {tool.scope!r} was removed from agent {agent.id!r}'s ceiling", tool)
        if not covered_by_any(tool.scope, user.entitlements):
            return deny(f"user {user.id!r} is no longer entitled to {tool.scope!r}", tool)

        segments = tuple(request.context)
        facts = compute_facts(request.args, segments, self.directory.is_trusted_domain)
        risk = self.risk.assess(
            DetectionContext(
                tool=tool,
                args=request.args,
                strings=tuple(flatten_strings(request.args)),
                facts=facts,
                user_prompt=request.user_prompt or "",
                segments=segments,
                agent_id=agent.id,
                user_id=user.id,
                is_trusted_domain=self.directory.is_trusted_domain,
            )
        )
        policy = self.policy.evaluate(
            self._policy_context(claims, user, agent, tool, request, facts, risk)
        )
        outcome = _Outcome(policy.decision, list(policy.reasons), policy.matched_rules, risk)
        if outcome.decision is Decision.REQUIRE_APPROVAL:
            self._resolve_approval(outcome, claims, tool, request, decision_id)
        return outcome, tool, facts

    def _resolve_approval(
        self,
        outcome: _Outcome,
        claims: TokenClaims,
        tool: Tool,
        request: AuthorizeRequest,
        decision_id: str,
    ) -> None:
        if request.approval_id:
            check = self.approvals.check(
                request.approval_id,
                user_id=claims.user_id,
                actor_chain=claims.actor_chain,
                tool=tool.name,
                args=request.args,
            )
            reviewer = check.request.reviewer if check.request else None
            if check.outcome == "consumed":
                outcome.decision = Decision.ALLOW
                outcome.approval_id = request.approval_id
                outcome.reasons.append(f"approved by {reviewer} ({request.approval_id})")
                return
            if check.outcome == "pending":
                outcome.approval_id = request.approval_id
                outcome.reasons.append("awaiting human approval")
                return
            if check.outcome in ("denied", "mismatch", "used"):
                message = {
                    "denied": f"approval {request.approval_id} was denied by {reviewer}",
                    "mismatch": "approval does not match this exact call (args or actors changed)",
                    "used": "approval has already been used (replay attempt)",
                }[check.outcome]
                outcome.decision = Decision.DENY
                outcome.reasons.append(message)
                if check.outcome != "denied":
                    self.audit.append(
                        "approval.misuse",
                        user_id=claims.user_id,
                        agent_id=claims.agent_id,
                        tool=tool.name,
                        data={"approval_id": request.approval_id, "outcome": check.outcome},
                    )
                return
            outcome.reasons.append(
                f"approval {request.approval_id} is {check.outcome}; requesting a new one"
            )
        approval = self.approvals.create(
            decision_id=decision_id,
            user_id=claims.user_id,
            actor_chain=claims.actor_chain,
            tool=tool.name,
            args=request.args,
            reasons=outcome.reasons,
            risk_score=outcome.risk.score,
        )
        outcome.approval_id = approval.id
        self.audit.append(
            "approval.requested",
            user_id=claims.user_id,
            agent_id=claims.agent_id,
            tool=tool.name,
            data={"approval_id": approval.id, "decision_id": decision_id},
        )

    # ================================================================== helpers
    def _verify(self, token: str, *, context: str, tool: str | None = None) -> TokenClaims:
        try:
            return self.tokens.verify(token)
        except AuthenticationError as exc:
            self.audit.append(
                "auth.failed", tool=tool, data={"reason": str(exc), "operation": context}
            )
            raise

    def _disabled_agent(self, claims: TokenClaims) -> str | None:
        for agent_id in claims.actor_chain:
            agent = self.registry.get(agent_id)
            if agent is None or not agent.enabled:
                return agent_id
        return None

    def _policy_context(
        self,
        claims: TokenClaims,
        user: User,
        agent: Agent,
        tool: Tool,
        request: AuthorizeRequest,
        facts: CallFacts,
        risk: RiskAssessment,
    ) -> dict[str, Any]:
        now = datetime.fromtimestamp(self._clock(), UTC)
        return {
            "user": {"id": user.id, "roles": list(user.roles)},
            "agent": {"id": agent.id, "owner": agent.owner, "trust_tier": agent.trust_tier.value},
            "actor_chain": list(claims.actor_chain),
            "delegation": {"depth": claims.depth},
            "tool": {
                "name": tool.name,
                "scope": tool.scope,
                "risk": tool.risk.value,
                "side_effect": tool.side_effect.value,
            },
            "args": request.args,
            "risk": {
                "score": risk.score,
                "level": risk.level.value,
                "signals": risk.signal_names,
                "detectors": sorted({s.detector for s in risk.signals}),
            },
            "facts": facts.as_dict(),
            "token": {"task": claims.task, "scopes": list(claims.scopes)},
            "time": {"hour": now.hour, "weekday": now.strftime("%A").lower()},
        }
