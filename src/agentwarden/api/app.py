"""FastAPI application exposing the gateway over HTTP.

Authentication schemes:

* **Agents** send their delegated token: ``Authorization: Bearer <jwt>``.
* **Users** (token issuance, approvals) send ``X-API-Key: <key>``. Demo stand-in for OIDC.
* **Admins** send ``X-Admin-Key``. Admin routes are disabled unless
  ``AGENTWARDEN_ADMIN_KEY`` is set.
"""

from __future__ import annotations

import hmac
import json
import math
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from importlib import resources
from typing import Annotated, Any, Literal
from urllib.parse import parse_qs

from fastapi import Depends, FastAPI, Header, Query, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field, ValidationError

from agentwarden import __version__
from agentwarden.approvals import APPROVER_ROLE, ApprovalRequest, ApprovalStatus
from agentwarden.audit import GENESIS_HASH, AuditIntegrityError
from agentwarden.config import Settings
from agentwarden.errors import (
    AgentWardenError,
    ApprovalError,
    AuthenticationError,
    ConfigurationError,
    InvalidRequestError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitedError,
)
from agentwarden.gateway import Gateway
from agentwarden.identity.dpop import DpopError, DpopPresentation
from agentwarden.models import (
    Agent,
    AuditEvent,
    AuthorizationResult,
    AuthorizeRequest,
    DelegationRequest,
    IssuedToken,
    TokenRequest,
    User,
)
from agentwarden.ratelimit import RateLimiter
from agentwarden.siem.export import format_event

_STATUS = {
    AuthenticationError: 401,
    PermissionDeniedError: 403,
    NotFoundError: 404,
    ApprovalError: 409,
    RateLimitedError: 429,
    InvalidRequestError: 400,
    ConfigurationError: 500,
}
_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


class ReviewBody(BaseModel):
    note: str = Field(default="", max_length=1000)


class ScopesBody(BaseModel):
    scopes: list[str] = Field(min_length=1, max_length=100)


class ReasonBody(BaseModel):
    reason: str = Field(default="", max_length=500)


class RevokeBody(BaseModel):
    jti: str | None = Field(default=None, max_length=64)
    subject: str | None = Field(default=None, max_length=100)
    reason: str = Field(default="", max_length=500)


# OAuth URNs from RFC 8693, not secrets.
#: Endpoints that mint credentials or check them: stricter per-IP limits apply.
SENSITIVE_PATHS = frozenset({"/v1/tokens", "/v1/token/exchange", "/v1/tokens/delegate", "/v1/me"})

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105  # nosec B105
ISSUED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"  # noqa: S105  # nosec B105
SUBJECT_TOKEN_TYPES = {
    "urn:ietf:params:oauth:token-type:id_token",
    "urn:ietf:params:oauth:token-type:jwt",
}


async def _read_params(request: Request) -> dict[str, str]:
    """Read a form-encoded or JSON body into single-valued string parameters."""
    body = await request.body()
    if len(body) > 64 * 1024:
        return {}
    if request.headers.get("content-type", "").startswith("application/json"):
        try:
            data = json.loads(body or b"{}")
        except json.JSONDecodeError:
            return {}
        return {str(k): str(v) for k, v in data.items()} if isinstance(data, dict) else {}
    parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=False)
    return {k: v[0] for k, v in parsed.items() if v}


#: The console renders attacker-influenced text (tool arguments, injected content). The policy
#: forbids inline script and every non-same-origin load, so even a rendering bug can't run code.
CONSOLE_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; "
    "frame-ancestors 'none'"
)
#: Fonts bundled with the console (Geist, SIL Open Font License; see console/fonts/OFL-Geist.txt).
CONSOLE_FONTS = frozenset({"Geist-Variable.woff2", "GeistMono-Variable.woff2"})


def _console_asset(name: str, media_type: str, cache: str = "no-cache") -> Response:
    content = (resources.files("agentwarden.api") / "console" / name).read_bytes()
    return Response(
        content,
        media_type=media_type,
        headers={"Content-Security-Policy": CONSOLE_CSP, "Cache-Control": cache},
    )


def _error_status(exc: AgentWardenError) -> int:
    for cls in type(exc).__mro__:
        if cls in _STATUS:
            return _STATUS[cls]
    return 500


def get_gateway(request: Request) -> Gateway:
    gateway: Gateway = request.app.state.gateway
    return gateway


GatewayDep = Annotated[Gateway, Depends(get_gateway)]


def request_url(request: Request, gateway: Gateway) -> str:
    """The URL a DPoP proof must name: the public URL when configured, else what we received."""
    if gateway.settings.public_url:
        return gateway.settings.public_url + request.url.path
    return str(request.url.replace(query="", fragment=""))


def dpop_presentation(request: Request, gateway: Gateway, scheme: str) -> DpopPresentation | None:
    proof = request.headers.get("dpop")
    if not proof and scheme.lower() != "dpop":
        return None
    return DpopPresentation(
        proof=proof, method=request.method, url=request_url(request, gateway), scheme=scheme
    )


@dataclass(frozen=True)
class AgentCredential:
    token: str
    dpop: DpopPresentation | None


def agent_credential(
    request: Request,
    gateway: GatewayDep,
    authorization: Annotated[str | None, Header()] = None,
) -> AgentCredential:
    """``Authorization: Bearer <token>``, or ``DPoP <token>`` plus a proof for bound tokens."""
    if not authorization:
        raise AuthenticationError("missing Authorization: Bearer <agent token>")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() not in ("bearer", "dpop") or not token.strip():
        raise AuthenticationError("expected Authorization: Bearer|DPoP <agent token>")
    return AgentCredential(token.strip(), dpop_presentation(request, gateway, scheme))


def current_user(
    gateway: GatewayDep,
    x_api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> User:
    """A human user: an IdP ID token (``Authorization: Bearer``) or, if enabled, an API key."""
    if authorization and gateway.oidc is not None:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            return gateway.authenticate_identity(token.strip())
    if x_api_key and gateway.settings.api_keys_enabled:
        user = gateway.directory.authenticate_api_key(x_api_key)
        if user is not None:
            return user
    accepted = [
        *(["Authorization: Bearer <ID token>"] if gateway.oidc is not None else []),
        *(["X-API-Key"] if gateway.settings.api_keys_enabled else []),
    ]
    raise AuthenticationError(f"sign in with {' or '.join(accepted)}")


def require_admin(
    gateway: GatewayDep, x_admin_key: Annotated[str | None, Header(alias="X-Admin-Key")] = None
) -> str:
    configured = gateway.settings.admin_key
    if configured is None:
        raise PermissionDeniedError("admin API is disabled (set AGENTWARDEN_ADMIN_KEY)")
    if not x_admin_key or not hmac.compare_digest(x_admin_key.encode(), configured.encode()):
        raise AuthenticationError("missing or invalid X-Admin-Key")
    return "admin"


TokenDep = Annotated[AgentCredential, Depends(agent_credential)]
UserDep = Annotated[User, Depends(current_user)]
AdminDep = Annotated[str, Depends(require_admin)]


def require_approver(user: UserDep) -> User:
    if APPROVER_ROLE not in user.roles:
        raise PermissionDeniedError(f"the '{APPROVER_ROLE}' role is required")
    return user


ApproverDep = Annotated[User, Depends(require_approver)]


def create_app(gateway: Gateway | None = None, settings: Settings | None = None) -> FastAPI:
    owns_gateway = gateway is None

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        yield
        if owns_gateway:  # close what we created; callers manage gateways they pass in
            app.state.gateway.close()

    app = FastAPI(
        lifespan=lifespan,
        title="AgentWarden",
        version=__version__,
        summary="Identity & access management for AI agents.",
        description=(
            "Delegated agent credentials, deny-by-default tool authorization, "
            "prompt-injection-aware risk scoring, human approvals and a tamper-evident audit log."
        ),
    )
    app.state.gateway = gateway or Gateway.build(settings)

    @app.exception_handler(AgentWardenError)
    async def _handle(_: Request, exc: AgentWardenError) -> JSONResponse:
        status = _error_status(exc)
        headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
        if isinstance(exc, DpopError):
            challenge = (
                f'DPoP algs="ES256 EdDSA", error="invalid_dpop_proof", error_description="{exc}"'
            )
            headers = {"WWW-Authenticate": challenge}
        if isinstance(exc, RateLimitedError):
            headers = {"Retry-After": str(math.ceil(exc.retry_after))}
        return JSONResponse(
            status_code=status,
            content={"error": type(exc).__name__, "detail": str(exc)},
            headers=headers,
        )

    settings_ = app.state.gateway.settings
    ip_limiter = RateLimiter(settings_.rate_limit_per_ip)
    sensitive_limiter = RateLimiter(settings_.rate_limit_sensitive_per_ip)
    failure_limiter = RateLimiter(settings_.rate_limit_auth_failures_per_ip)

    def client_ip(request: Request) -> str:
        if settings_.trust_proxy_headers:
            forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            if forwarded:
                return forwarded
        return request.client.host if request.client else "unknown"

    def too_many(retry_after: float, why: str) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={"error": "RateLimitedError", "detail": why},
            headers={"Retry-After": str(math.ceil(retry_after))},
        )

    @app.middleware("http")
    async def _rate_limit(request: Request, call_next: Any) -> Response:
        path = request.url.path
        if not path.startswith("/v1/"):
            passthrough: Response = await call_next(request)
            return passthrough
        ip = client_ip(request)
        locked = failure_limiter.peek(ip)
        if locked is not None:
            return too_many(locked, "too many failed sign-ins from this address; try again later")
        retry = ip_limiter.hit(ip)
        if retry is None and path in SENSITIVE_PATHS:
            retry = sensitive_limiter.hit(ip)
        if retry is not None:
            return too_many(retry, "too many requests from this address")
        response: Response = await call_next(request)
        if response.status_code == 401 or (
            path == "/v1/token/exchange" and response.status_code == 400
        ):
            failure_limiter.hit(ip)
        return response

    @app.middleware("http")
    async def _security_headers(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    # ---------------------------------------------------------------- public
    @app.get("/healthz", tags=["meta"])
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/.well-known/jwks.json", tags=["meta"])
    def jwks(gateway: GatewayDep) -> dict[str, Any]:
        return gateway.keys.jwks()

    # ---------------------------------------------------------------- tokens
    @app.post("/v1/tokens", tags=["tokens"])
    def issue(
        body: TokenRequest, user: UserDep, gateway: GatewayDep, request: Request, response: Response
    ) -> IssuedToken:
        """A user delegates scoped, short-lived authority to one of their agents.

        Send a ``DPoP`` proof header (made with the *agent's* key) to bind the token to that key.
        """
        response.headers.update(_NO_STORE)
        jkt = gateway.dpop_thumbprint(dpop_presentation(request, gateway, "DPoP"))
        return gateway.issue_token(user, body, jkt=jkt)

    @app.post("/v1/token/exchange", tags=["tokens"], response_model=None)
    async def token_exchange(request: Request, gateway: GatewayDep) -> JSONResponse:
        """RFC 8693 token exchange: trade an IdP ID token for a scoped agent token.

        Form-encoded (standard) or JSON. Parameters: ``grant_type`` (token-exchange),
        ``subject_token`` (the ID token), ``subject_token_type`` (id_token or jwt),
        ``scope`` (space-separated) and the agent as ``audience=agent:<id>`` or ``agent_id``.
        Optional: ``task``, ``ttl_seconds``.
        """
        params = await _read_params(request)

        def oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
            return JSONResponse(
                {"error": error, "error_description": description},
                status_code=status,
                headers=_NO_STORE,
            )

        if params.get("grant_type") != TOKEN_EXCHANGE_GRANT:
            return oauth_error(
                "unsupported_grant_type", f"grant_type must be {TOKEN_EXCHANGE_GRANT}"
            )
        if params.get("subject_token_type") not in SUBJECT_TOKEN_TYPES:
            return oauth_error("invalid_request", "subject_token_type must be an id_token or jwt")
        subject_token = params.get("subject_token")
        if not subject_token:
            return oauth_error("invalid_request", "subject_token is required")
        audience = params.get("audience", "")
        agent_id = params.get("agent_id") or (
            audience.removeprefix("agent:") if audience.startswith("agent:") else ""
        )
        scopes = params.get("scope", "").split()
        if not agent_id:
            return oauth_error(
                "invalid_target", "name the agent with audience=agent:<id> or agent_id"
            )
        if not scopes:
            return oauth_error("invalid_scope", "request at least one scope")
        try:
            ttl = int(params["ttl_seconds"]) if params.get("ttl_seconds") else None
            token_request = TokenRequest(
                agent_id=agent_id, scopes=scopes, task=params.get("task"), ttl_seconds=ttl
            )
        except (ValueError, ValidationError) as exc:
            return oauth_error("invalid_request", str(exc).splitlines()[0])
        try:
            jkt = gateway.dpop_thumbprint(dpop_presentation(request, gateway, "DPoP"))
        except DpopError as exc:
            return oauth_error("invalid_dpop_proof", str(exc))
        try:
            issued = gateway.exchange_token(subject_token, token_request, jkt=jkt)
        except AuthenticationError as exc:
            return oauth_error("invalid_grant", str(exc))
        except NotFoundError as exc:
            return oauth_error("invalid_target", str(exc))
        except (PermissionDeniedError, InvalidRequestError) as exc:
            return oauth_error("invalid_scope", str(exc))
        return JSONResponse(
            {
                "access_token": issued.access_token,
                "issued_token_type": ISSUED_TOKEN_TYPE,
                "token_type": issued.token_type,
                "expires_in": issued.expires_in,
                "scope": " ".join(issued.scope),
                "denied_scopes": issued.denied_scopes,
                "actor_chain": issued.actor_chain,
            },
            headers=_NO_STORE,
        )

    @app.post("/v1/tokens/delegate", tags=["tokens"])
    def delegate(
        body: DelegationRequest, credential: TokenDep, gateway: GatewayDep, response: Response
    ) -> IssuedToken:
        """An agent hands a narrower token to a sub-agent (bound to ``dpop_jkt`` if given)."""
        response.headers.update(_NO_STORE)
        return gateway.delegate_token(credential.token, body, dpop=credential.dpop)

    @app.post("/v1/tokens/revoke", tags=["tokens"], status_code=204)
    def revoke_own(credential: TokenDep, gateway: GatewayDep) -> Response:
        """Revoke the presented token (and everything delegated from it)."""
        gateway.revoke_token(credential.token, dpop=credential.dpop)
        return Response(status_code=204)

    # --------------------------------------------------------- authorization
    @app.post("/v1/authorize", tags=["authorization"])
    def authorize(
        body: AuthorizeRequest, credential: TokenDep, gateway: GatewayDep
    ) -> AuthorizationResult:
        """Ask whether a tool call is allowed. Always 200 for a decision; 401 for bad tokens."""
        return gateway.authorize(credential.token, body, dpop=credential.dpop)

    # ------------------------------------------------------------- approvals
    @app.get("/v1/me", tags=["approvals"])
    def me(user: UserDep) -> dict[str, Any]:
        """Who is signed in (used by the approver console)."""
        return {
            "id": user.id,
            "name": user.name or user.id,
            "email": user.email,
            "roles": user.roles,
            "approver": APPROVER_ROLE in user.roles,
        }

    @app.get("/v1/approvals", tags=["approvals"])
    def list_approvals(
        _: ApproverDep,
        gateway: GatewayDep,
        status: ApprovalStatus | None = None,
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
    ) -> list[ApprovalRequest]:
        return gateway.approvals.list(status)[:limit]

    @app.get("/v1/approvals/{approval_id}", tags=["approvals"])
    def get_approval(approval_id: str, user: UserDep, gateway: GatewayDep) -> ApprovalRequest:
        request = gateway.approvals.get(approval_id)
        if APPROVER_ROLE not in user.roles and request.user_id != user.id:
            raise NotFoundError(f"unknown approval {approval_id!r}")
        return request

    @app.post("/v1/approvals/{approval_id}/approve", tags=["approvals"])
    def approve(
        approval_id: str, body: ReviewBody, user: ApproverDep, gateway: GatewayDep
    ) -> ApprovalRequest:
        return gateway.approve(approval_id, user, body.note)

    @app.post("/v1/approvals/{approval_id}/deny", tags=["approvals"])
    def deny(
        approval_id: str, body: ReviewBody, user: ApproverDep, gateway: GatewayDep
    ) -> ApprovalRequest:
        return gateway.deny_approval(approval_id, user, body.note)

    # --------------------------------------------------------------- console
    @app.get("/console", include_in_schema=False, response_model=None)
    def console_page() -> Response:
        return _console_asset("index.html", "text/html; charset=utf-8")

    @app.get("/console/", include_in_schema=False, response_model=None)
    def console_slash() -> RedirectResponse:
        return RedirectResponse("/console")

    @app.get("/console/app.js", include_in_schema=False, response_model=None)
    def console_js() -> Response:
        return _console_asset("app.js", "text/javascript; charset=utf-8")

    @app.get("/console/app.css", include_in_schema=False, response_model=None)
    def console_css() -> Response:
        return _console_asset("app.css", "text/css; charset=utf-8")

    @app.get("/console/fonts/{name}", include_in_schema=False, response_model=None)
    def console_font(name: str) -> Response:
        if name not in CONSOLE_FONTS:  # an allowlist, so no path tricks
            return JSONResponse({"error": "NotFound", "detail": "no such font"}, status_code=404)
        return _console_asset("fonts/" + name, "font/woff2", "public, max-age=86400")

    # ----------------------------------------------------------------- admin
    @app.get("/v1/agents", tags=["admin"])
    def list_agents(_: AdminDep, gateway: GatewayDep) -> list[Agent]:
        return gateway.registry.list()

    @app.post("/v1/agents", tags=["admin"], status_code=201)
    def register_agent(body: Agent, actor: AdminDep, gateway: GatewayDep) -> Agent:
        return gateway.register_agent(body, actor)

    @app.get("/v1/agents/{agent_id}", tags=["admin"])
    def get_agent(agent_id: str, _: AdminDep, gateway: GatewayDep) -> Agent:
        return gateway.registry.require(agent_id)

    @app.post("/v1/agents/{agent_id}/disable", tags=["admin"])
    def disable_agent(
        agent_id: str, body: ReasonBody, actor: AdminDep, gateway: GatewayDep
    ) -> Agent:
        """Kill switch: disables the agent and revokes all of its outstanding tokens."""
        return gateway.set_agent_enabled(agent_id, False, actor, body.reason)

    @app.post("/v1/agents/{agent_id}/enable", tags=["admin"])
    def enable_agent(
        agent_id: str, body: ReasonBody, actor: AdminDep, gateway: GatewayDep
    ) -> Agent:
        return gateway.set_agent_enabled(agent_id, True, actor, body.reason)

    @app.put("/v1/agents/{agent_id}/scopes", tags=["admin"])
    def set_scopes(agent_id: str, body: ScopesBody, actor: AdminDep, gateway: GatewayDep) -> Agent:
        return gateway.set_agent_scopes(agent_id, body.scopes, actor)

    @app.post("/v1/admin/revoke", tags=["admin"], status_code=204)
    def admin_revoke(body: RevokeBody, actor: AdminDep, gateway: GatewayDep) -> Response:
        if bool(body.jti) == bool(body.subject):
            raise InvalidRequestError("provide exactly one of 'jti' or 'subject'")
        if body.jti:
            gateway.revoke_jti(body.jti, body.reason, actor)
        else:
            gateway.revoke_subject(str(body.subject), body.reason, actor)
        return Response(status_code=204)

    @app.get("/v1/admin/keys", tags=["admin"])
    def list_keys(_: AdminDep, gateway: GatewayDep) -> list[dict[str, Any]]:
        """Signing keys and their lifecycle (no private material)."""
        return gateway.key_status()

    @app.post("/v1/admin/keys/rotate", tags=["admin"])
    def rotate_keys(actor: AdminDep, gateway: GatewayDep) -> list[dict[str, Any]]:
        """Start signing with a new key. Outstanding tokens stay valid until they expire."""
        return gateway.rotate_keys(actor)

    @app.post("/v1/admin/keys/prune", tags=["admin"])
    def prune_keys(actor: AdminDep, gateway: GatewayDep) -> dict[str, list[str]]:
        """Delete private keys whose grace period has ended."""
        return {"pruned": gateway.prune_keys(actor)}

    @app.get("/v1/audit", tags=["audit"])
    def audit_events(
        _: AdminDep,
        gateway: GatewayDep,
        agent_id: str | None = None,
        user_id: str | None = None,
        event_type: str | None = None,
        decision: str | None = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    ) -> list[AuditEvent]:
        return gateway.audit.query(
            agent_id=agent_id,
            user_id=user_id,
            event_type=event_type,
            decision=decision,
            limit=limit,
        )

    @app.get("/v1/audit/verify", tags=["audit"])
    def audit_verify(_: AdminDep, gateway: GatewayDep) -> dict[str, Any]:
        result = gateway.audit.verify()
        return {
            "ok": result.ok,
            "checked": result.checked,
            "head_hash": result.head_hash,
            "first_bad_seq": result.first_bad_seq,
            "reason": result.reason,
        }

    @app.get("/v1/audit/export", tags=["audit"], response_model=None)
    def audit_export(
        _: AdminDep,
        gateway: GatewayDep,
        after_seq: Annotated[int, Query(ge=0)] = 0,
        after_hash: Annotated[str | None, Query(pattern=r"^[0-9a-f]{64}$")] = None,
        format: Literal["ocsf", "native"] = "ocsf",
        limit: Annotated[int, Query(ge=1, le=1000)] = 500,
    ) -> dict[str, Any] | JSONResponse:
        """Pull-based export: page through the chain, oldest first, keeping your own cursor.

        Pass back ``next.after_seq`` and ``next.after_hash``; a ``409`` means entries you
        already have were changed or removed since (the chain no longer continues from them).
        """
        if after_hash is None:
            after_hash = GENESIS_HASH
            if after_seq:
                row = gateway.db.query_one("SELECT hash FROM audit_log WHERE seq = ?", (after_seq,))
                after_hash = row["hash"] if row else ""
        try:
            events = gateway.audit.entries_after(after_seq, after_hash, limit)
        except AuditIntegrityError as exc:
            return JSONResponse(
                {"error": "AuditIntegrityError", "detail": str(exc), "seq": exc.seq},
                status_code=409,
            )
        last_seq, last_hash = (
            (events[-1].seq, events[-1].hash) if events else (after_seq, after_hash)
        )
        return {
            "format": format,
            "events": [format_event(e, format) for e in events],
            "next": {"after_seq": last_seq, "after_hash": last_hash},
        }

    @app.get("/v1/audit/checkpoint", tags=["audit"])
    def audit_checkpoint(_: AdminDep, gateway: GatewayDep) -> dict[str, Any]:
        return gateway.audit.checkpoint()

    @app.get("/v1/analyzer/report", tags=["audit"], response_model=None)
    def analyzer_report(
        _: AdminDep,
        gateway: GatewayDep,
        days: Annotated[int, Query(ge=1, le=365)] = 30,
        format: Literal["json", "markdown"] = "json",
    ) -> dict[str, Any] | PlainTextResponse:
        report = gateway.analyze(days)
        if format == "markdown":
            return PlainTextResponse(report.to_markdown(), media_type="text/markdown")
        return report.to_dict()

    return app
