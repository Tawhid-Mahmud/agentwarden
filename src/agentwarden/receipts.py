"""Authorization receipts: let tools enforce AgentWarden decisions themselves.

When AgentWarden allows a call it returns a **receipt**: a short-lived JWT, signed with the same
Ed25519 keys as agent tokens, that says *this exact call* was authorized::

    {"iss": "...", "aud": "tool:send_email", "sub": "user:alice",
     "act": {"sub": "agent:inbox-assistant"}, "tool": "send_email",
     "args_sha256": "<sha256 of the canonical JSON arguments>",
     "decision_id": "dec_...", "iat": ..., "exp": iat + 60, "jti": "..."}

A tool that verifies receipts (:class:`ReceiptVerifier`) can't be called by an agent that skipped
AgentWarden, used a decision for a different tool, changed the arguments after approval, or
replays an old receipt. The SDK's ``@guard(pass_receipt=True)`` hands receipts to tool code, and
the MCP proxy attaches them to forwarded calls as ``_meta["agentwarden/receipt"]``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Callable, Mapping, Sequence
from typing import Any

import httpx
import jwt
from pydantic import BaseModel, ConfigDict

from agentwarden.errors import AuthenticationError, PermissionDeniedError
from agentwarden.identity.keys import SigningKeys, public_key_from_jwk

RECEIPT_TYPE = "aw-receipt+jwt"
MCP_META_KEY = "agentwarden/receipt"
HTTP_HEADER = "X-AgentWarden-Receipt"


def args_digest(args: Mapping[str, Any]) -> str:
    """SHA-256 of the arguments as canonical JSON (sorted keys, compact, UTF-8)."""
    canonical = json.dumps(
        args, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _act(chain: Sequence[str]) -> dict[str, Any]:
    node: dict[str, Any] | None = None
    for agent_id in reversed(chain):
        node = {"sub": f"agent:{agent_id}", **({"act": node} if node else {})}
    return node or {}


def issue_receipt(
    keys: SigningKeys,
    *,
    issuer: str,
    user_id: str,
    actor_chain: Sequence[str],
    tool: str,
    args: Mapping[str, Any],
    decision_id: str,
    ttl: int,
    now: float,
) -> str:
    claims = {
        "iss": issuer,
        "aud": f"tool:{tool}",
        "sub": f"user:{user_id}",
        "act": _act(actor_chain),
        "tool": tool,
        "args_sha256": args_digest(args),
        "decision_id": decision_id,
        "iat": now,
        "exp": now + ttl,
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(
        claims, keys.private_key, algorithm="EdDSA", headers={"kid": keys.kid, "typ": RECEIPT_TYPE}
    )


class ReceiptClaims(BaseModel):
    model_config = ConfigDict(frozen=True)

    tool: str
    user_id: str
    agent_id: str
    decision_id: str
    jti: str
    expires_at: float


class ReceiptVerifier:
    """Tool-side verification of AgentWarden receipts.

    Give it AgentWarden's public keys, either as a JWKS document (``jwks``) or a URL to fetch them
    from (``jwks_url``, normally ``https://<agentwarden>/.well-known/jwks.json``). Unknown key ids
    trigger one rate-limited refetch, so signing-key rotation needs no change on the tool side.
    """

    def __init__(
        self,
        *,
        issuer: str,
        jwks: Mapping[str, Any] | None = None,
        jwks_url: str | None = None,
        http: httpx.Client | None = None,
        clock: Callable[[], float] = time.time,
        leeway: float = 5.0,
        replay_cache_size: int = 100_000,
        min_refresh_interval: float = 30.0,
    ) -> None:
        if jwks is None and jwks_url is None:
            raise ValueError("give jwks or jwks_url")
        self._issuer = issuer
        self._jwks_url = jwks_url
        self._http = http
        self._clock = clock
        self._leeway = leeway
        self._keys: dict[str, Any] = {}
        self._last_fetch = -1e18
        self._min_refresh = min_refresh_interval
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._seen_max = replay_cache_size
        self._lock = threading.Lock()
        if jwks is not None:
            self._load(jwks)

    def _load(self, jwks: Mapping[str, Any]) -> None:
        """Keep the Ed25519 keys; AgentWarden signs with nothing else, so other keys are ignored."""
        keys = {}
        for entry in jwks.get("keys", []):
            if (
                isinstance(entry, Mapping)
                and isinstance(entry.get("kid"), str)
                and entry.get("kty") == "OKP"
                and entry.get("crv") == "Ed25519"
                and isinstance(entry.get("x"), str)
            ):
                keys[entry["kid"]] = public_key_from_jwk(dict(entry))
        self._keys = keys

    def _refresh(self) -> None:
        if self._jwks_url is None or self._clock() - self._last_fetch < self._min_refresh:
            return
        self._last_fetch = self._clock()
        client = self._http or httpx.Client(timeout=5.0)
        try:
            response = client.get(self._jwks_url)
            response.raise_for_status()
            self._load(response.json())
        except (httpx.HTTPError, ValueError) as exc:
            raise AuthenticationError(f"could not fetch AgentWarden keys: {exc}") from exc

    def verify(self, receipt: str | None, *, tool: str, args: Mapping[str, Any]) -> ReceiptClaims:
        """Raise unless ``receipt`` authorizes calling ``tool`` with exactly ``args``, once."""
        if not receipt:
            raise PermissionDeniedError(f"{tool!r} requires an AgentWarden receipt")
        try:
            header = jwt.get_unverified_header(receipt)
        except jwt.PyJWTError as exc:
            raise AuthenticationError("malformed receipt") from exc
        if header.get("alg") != "EdDSA" or header.get("typ") != RECEIPT_TYPE:
            raise AuthenticationError("not an AgentWarden receipt")
        kid = header.get("kid")
        with self._lock:
            if kid not in self._keys:
                self._refresh()
            key = self._keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            raise AuthenticationError("receipt signed by an unknown key")
        try:
            claims = jwt.decode(
                receipt,
                key,
                algorithms=["EdDSA"],
                audience=f"tool:{tool}",
                issuer=self._issuer,
                options={
                    "require": ["exp", "iat", "jti", "args_sha256"],
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise AuthenticationError(f"invalid receipt: {exc}") from exc
        now = self._clock()
        if float(claims["exp"]) <= now - self._leeway:
            raise AuthenticationError("receipt expired")
        if claims.get("tool") != tool:
            raise PermissionDeniedError("receipt is for a different tool")
        if not hmac.compare_digest(str(claims["args_sha256"]), args_digest(args)):
            raise PermissionDeniedError("arguments differ from the ones AgentWarden authorized")
        jti = str(claims["jti"])
        with self._lock:
            for stale in [j for j, exp in self._seen.items() if exp < now - self._leeway]:
                del self._seen[stale]
            if jti in self._seen:
                raise PermissionDeniedError("receipt already used (replay)")
            self._seen[jti] = float(claims["exp"])
            while len(self._seen) > self._seen_max:
                self._seen.popitem(last=False)
        act = claims.get("act") or {}
        return ReceiptClaims(
            tool=tool,
            user_id=str(claims.get("sub", "")).removeprefix("user:"),
            agent_id=str(act.get("sub", "")).removeprefix("agent:"),
            decision_id=str(claims.get("decision_id", "")),
            jti=jti,
            expires_at=float(claims["exp"]),
        )
