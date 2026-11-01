"""Delegated agent tokens.

A token says: *agent A (possibly acting through sub-agents) acts on behalf of user U, with these
scopes, for this task, until this time.* The claim layout follows OAuth 2.0 Token Exchange
(RFC 8693): ``sub`` is the user, and ``act`` is the acting party, nested once per delegation hop::

    {
      "sub": "user:alice",
      "act": {"sub": "agent:summarizer", "act": {"sub": "agent:inbox-assistant"}},
      "scope": "docs:read",
      "dep": 1,
      "anc": ["<parent jti>"]
    }

Security properties:

* Signed with Ed25519 (``EdDSA``). Verification accepts *only* ``EdDSA`` and only the gateway's
  ``kid``, which rules out ``alg=none`` and HMAC/RSA key-confusion attacks.
* Granted scopes are always concrete and are the intersection of request, user entitlements,
  and agent ceiling. Delegation can only narrow scopes and can never outlive its parent.
* Revoking a token also revokes everything delegated from it, because ancestors (``anc``) are
  checked on every verification.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

import jwt
from pydantic import BaseModel, ConfigDict

from agentwarden.config import Settings
from agentwarden.errors import AuthenticationError, DelegationError, PermissionDeniedError
from agentwarden.identity.keys import SigningKeys
from agentwarden.identity.registry import RevocationList
from agentwarden.identity.scopes import attenuate, covered_by_any, dedupe, validate_scope
from agentwarden.models import Agent, IssuedToken, User

ALGORITHM = "EdDSA"
# JWT "typ" header value (RFC 9068), not a secret.
TOKEN_TYPE = "at+jwt"  # noqa: S105  # nosec B105
_REQUIRED_CLAIMS = ("iss", "aud", "sub", "act", "scope", "iat", "exp", "jti", "dep")


class TokenClaims(BaseModel):
    """Verified, typed view of an agent token."""

    model_config = ConfigDict(frozen=True)

    jti: str
    user_id: str
    #: Agent ids from the acting agent (first) to the root agent the user delegated to (last).
    actor_chain: tuple[str, ...]
    scopes: tuple[str, ...]
    roles: tuple[str, ...] = ()
    task: str | None = None
    depth: int = 0
    ancestors: tuple[str, ...] = ()
    issued_at: float
    expires_at: float

    @property
    def agent_id(self) -> str:
        return self.actor_chain[0]

    @property
    def root_agent_id(self) -> str:
        return self.actor_chain[-1]


def _build_act(chain: Sequence[str]) -> dict[str, Any]:
    """Nest ``act`` claims: chain[0] is the outermost (current) actor."""
    act: dict[str, Any] | None = None
    for agent_id in reversed(chain):
        node: dict[str, Any] = {"sub": f"agent:{agent_id}"}
        if act is not None:
            node["act"] = act
        act = node
    if act is None:
        raise ValueError("actor chain cannot be empty")
    return act


def _parse_act(act: Any, max_depth: int) -> tuple[str, ...]:
    chain: list[str] = []
    node = act
    while node is not None:
        if not isinstance(node, dict) or not isinstance(node.get("sub"), str):
            raise AuthenticationError("malformed act claim")
        sub = node["sub"]
        if not sub.startswith("agent:") or len(sub) <= len("agent:"):
            raise AuthenticationError("act.sub must identify an agent")
        chain.append(sub.removeprefix("agent:"))
        if len(chain) > max_depth + 1:
            raise AuthenticationError("delegation chain too deep")
        node = node.get("act")
    return tuple(chain)


class TokenService:
    def __init__(
        self,
        keys: SigningKeys,
        settings: Settings,
        revocations: RevocationList,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._keys = keys
        self._settings = settings
        self._revocations = revocations
        self._clock = clock

    # ------------------------------------------------------------------ issuance
    def issue(
        self,
        *,
        user: User,
        agent: Agent,
        scopes: Sequence[str],
        task: str | None = None,
        ttl: int | None = None,
    ) -> IssuedToken:
        """Mint a token for ``agent`` acting on behalf of ``user``."""
        if not agent.enabled:
            raise PermissionDeniedError(f"agent {agent.id!r} is disabled")
        requested = dedupe(validate_scope(s, allow_wildcards=False) for s in scopes)
        granted, denied = attenuate(requested, user.entitlements, agent.scope_ceiling)
        if not granted:
            raise PermissionDeniedError(
                "none of the requested scopes are within both the user's entitlements and "
                f"the agent's scope ceiling (requested: {', '.join(requested)})"
            )
        now = self._clock()
        expires_at = now + self._ttl(ttl)
        jti = uuid.uuid4().hex
        claims = self._base_claims(user.id, [agent.id], granted, list(user.roles), task, now)
        claims.update({"exp": expires_at, "jti": jti, "dep": 0, "anc": []})
        return self._encode(claims, granted, denied, [agent.id], expires_at, now)

    def delegate(
        self,
        *,
        parent: TokenClaims,
        sub_agent: Agent,
        scopes: Sequence[str],
        ttl: int | None = None,
    ) -> IssuedToken:
        """Derive a narrower token for ``sub_agent`` from a verified ``parent`` token."""
        if parent.depth + 1 > self._settings.max_delegation_depth:
            raise DelegationError(
                f"delegation depth limit ({self._settings.max_delegation_depth}) reached"
            )
        if sub_agent.id in parent.actor_chain:
            raise DelegationError("delegation cycle: agent already in the actor chain")
        if not sub_agent.enabled:
            raise PermissionDeniedError(f"agent {sub_agent.id!r} is disabled")
        requested = dedupe(validate_scope(s, allow_wildcards=False) for s in scopes)
        escalation = [s for s in requested if not covered_by_any(s, parent.scopes)]
        if escalation:
            raise DelegationError(
                "cannot delegate scopes the parent token does not hold: " + ", ".join(escalation)
            )
        granted, denied = attenuate(requested, parent.scopes, sub_agent.scope_ceiling)
        if not granted:
            raise DelegationError("no requested scope is within the sub-agent's scope ceiling")
        now = self._clock()
        expires_at = min(now + self._ttl(ttl), parent.expires_at)
        chain = [sub_agent.id, *parent.actor_chain]
        jti = uuid.uuid4().hex
        claims = self._base_claims(
            parent.user_id, chain, granted, list(parent.roles), parent.task, now
        )
        claims.update(
            {
                "exp": expires_at,
                "jti": jti,
                "dep": parent.depth + 1,
                "anc": [parent.jti, *parent.ancestors],
            }
        )
        return self._encode(claims, granted, denied, chain, expires_at, now)

    # -------------------------------------------------------------- verification
    def verify(self, token: str) -> TokenClaims:
        """Verify signature, registered claims, structure and revocation status."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthenticationError("malformed token") from exc
        if header.get("alg") != ALGORITHM:
            raise AuthenticationError("unsupported token algorithm")
        kid = header.get("kid")
        verification_key = self._keys.verification_key(kid) if isinstance(kid, str) else None
        if verification_key is None:
            raise AuthenticationError("token signed by an unknown key")
        try:
            payload = jwt.decode(
                token,
                verification_key,
                algorithms=[ALGORITHM],
                audience=self._settings.audience,
                issuer=self._settings.issuer,
                options={
                    "require": list(_REQUIRED_CLAIMS),
                    # Time claims are checked below against the injectable clock.
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError(f"invalid token: {exc}") from exc

        claims = self._parse(payload)
        now = self._clock()
        skew = self._settings.clock_skew_seconds
        if claims.expires_at <= now - skew:
            raise AuthenticationError("token expired")
        if claims.issued_at > now + skew:
            raise AuthenticationError("token issued in the future")
        if self._revocations.any_revoked([claims.jti, *claims.ancestors]):
            raise AuthenticationError("token revoked")
        subjects = [f"user:{claims.user_id}", *(f"agent:{a}" for a in claims.actor_chain)]
        for subject in subjects:
            cutoff = self._revocations.subject_cutoff(subject)
            if cutoff is not None and claims.issued_at <= cutoff:
                raise AuthenticationError(f"all tokens for {subject} have been revoked")
        return claims

    def revoke(self, claims: TokenClaims, reason: str = "") -> None:
        self._revocations.revoke_token(claims.jti, claims.expires_at, reason)

    # ------------------------------------------------------------------ helpers
    def _ttl(self, ttl: int | None) -> int:
        ttl = self._settings.default_token_ttl if ttl is None else ttl
        return max(30, min(ttl, self._settings.max_token_ttl))

    def _base_claims(
        self,
        user_id: str,
        chain: Sequence[str],
        scopes: Sequence[str],
        roles: list[str],
        task: str | None,
        now: float,
    ) -> dict[str, Any]:
        claims: dict[str, Any] = {
            "iss": self._settings.issuer,
            "aud": self._settings.audience,
            "sub": f"user:{user_id}",
            "act": _build_act(chain),
            "scope": " ".join(scopes),
            "roles": roles,
            "iat": now,
        }
        if task:
            claims["task"] = task
        return claims

    def _encode(
        self,
        claims: dict[str, Any],
        granted: list[str],
        denied: list[str],
        chain: list[str],
        expires_at: float,
        now: float,
    ) -> IssuedToken:
        token = jwt.encode(
            claims,
            self._keys.private_key,
            algorithm=ALGORITHM,
            headers={"kid": self._keys.kid, "typ": TOKEN_TYPE},
        )
        return IssuedToken(
            access_token=token,
            expires_in=max(0, int(expires_at - now)),
            expires_at=datetime.fromtimestamp(expires_at, UTC),
            scope=granted,
            denied_scopes=denied,
            jti=claims["jti"],
            actor_chain=chain,
        )

    def _parse(self, payload: dict[str, Any]) -> TokenClaims:
        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub.startswith("user:"):
            raise AuthenticationError("sub must identify a user")
        chain = _parse_act(payload.get("act"), self._settings.max_delegation_depth)
        depth = payload.get("dep")
        if not isinstance(depth, int) or depth != len(chain) - 1:
            raise AuthenticationError("delegation depth does not match actor chain")
        ancestors = payload.get("anc", [])
        if not isinstance(ancestors, list) or len(ancestors) != depth:
            raise AuthenticationError("ancestor list does not match delegation depth")
        scope = payload.get("scope")
        if not isinstance(scope, str) or not scope.strip():
            raise AuthenticationError("token has no scopes")
        iat, exp = payload.get("iat"), payload.get("exp")
        if not isinstance(iat, int | float) or not isinstance(exp, int | float):
            raise AuthenticationError("iat/exp must be numeric")
        return TokenClaims(
            jti=str(payload["jti"]),
            user_id=sub.removeprefix("user:"),
            actor_chain=chain,
            scopes=tuple(scope.split()),
            roles=tuple(str(r) for r in payload.get("roles", [])),
            task=payload.get("task"),
            depth=depth,
            ancestors=tuple(str(a) for a in ancestors),
            issued_at=float(iat),
            expires_at=float(exp),
        )
