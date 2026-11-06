"""Python SDK: guard an agent's tools with AgentWarden.

Two transports share one interface:

* :class:`WardenClient` talks to a remote AgentWarden over HTTP.
* :class:`LocalWarden` calls an in-process :class:`~agentwarden.gateway.Gateway` (tests, demos,
  single-process agents).

The client also tracks **provenance**. Report everything the agent reads with
:meth:`observe` (or ``@guard(observe_output=True)``), and the gateway can tell whether an
email address or URL in a later tool call came from the user or from content an attacker
controls::

    warden = WardenClient("https://warden.internal", token=agent_token)
    warden.set_user_prompt("Summarize my inbox")

    @warden.guard(observe_output=True)
    def read_inbox() -> list[str]: ...

    @warden.guard()
    def send_email(to: list[str], subject: str, body: str) -> None: ...

    try:
        send_email(to=["x@evil.example"], subject="hi", body="...")
    except AccessDenied as exc:
        print(exc.result.reasons)
"""

from __future__ import annotations

import functools
import inspect
import json
from collections import deque
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any, ParamSpec, TypeVar

import httpx

from agentwarden.errors import AgentWardenError, AuthenticationError, RateLimitedError
from agentwarden.identity.dpop import DpopPresentation
from agentwarden.models import AuthorizationResult, AuthorizeRequest, ContextSegment, Decision
from agentwarden.sdk.dpop import DpopKey

P = ParamSpec("P")
R = TypeVar("R")

MAX_SEGMENTS = 20
MAX_SEGMENT_CHARS = 200_000


class AccessDenied(AgentWardenError):
    """The gateway denied the tool call."""

    def __init__(self, result: AuthorizationResult) -> None:
        super().__init__(f"{result.tool}: denied ({'; '.join(result.reasons)})")
        self.result = result


class ApprovalRequired(AgentWardenError):
    """A human must approve this exact call. Retry with ``using_approval(approval_id)``."""

    def __init__(self, result: AuthorizationResult) -> None:
        super().__init__(f"{result.tool}: approval required ({result.approval_id})")
        self.result = result
        self.approval_id = result.approval_id


def _jsonable(value: Any) -> Any:
    """Arguments are hashed and policy-evaluated as JSON, so normalize them up front."""
    return json.loads(json.dumps(value, default=str))


class _WardenBase:
    def __init__(self) -> None:
        self._user_prompt: str | None = None
        self._context: deque[ContextSegment] = deque(maxlen=MAX_SEGMENTS)
        self._pending_approval: str | None = None

    # ------------------------------------------------------------- provenance
    def set_user_prompt(self, prompt: str | None) -> None:
        """The user's actual request. Destinations mentioned here count as user-chosen."""
        self._user_prompt = prompt

    def observe(self, source: str, content: Any, *, trusted: bool = False) -> None:
        """Record content the agent has read (tool outputs, documents, web pages)."""
        # ensure_ascii=False matters: escaping would turn smuggled Unicode (tag characters,
        # zero-width, bidi controls) into harmless-looking "\\uXXXX" text the detectors can't see.
        text = (
            content
            if isinstance(content, str)
            else json.dumps(content, default=str, ensure_ascii=False)
        )
        self._context.append(
            ContextSegment(source=source[:200], content=text[:MAX_SEGMENT_CHARS], trusted=trusted)
        )

    def clear_context(self) -> None:
        self._context.clear()

    @property
    def context(self) -> list[ContextSegment]:
        return list(self._context)

    @contextmanager
    def using_approval(self, approval_id: str | None) -> Iterator[None]:
        """Attach an approval id to the next authorization inside this block."""
        previous, self._pending_approval = self._pending_approval, approval_id
        try:
            yield
        finally:
            self._pending_approval = previous

    # ---------------------------------------------------------- authorization
    def authorize(
        self, tool: str, args: Mapping[str, Any] | None = None, *, approval_id: str | None = None
    ) -> AuthorizationResult:
        request = AuthorizeRequest(
            tool=tool,
            args=_jsonable(dict(args or {})),
            user_prompt=self._user_prompt,
            context=list(self._context),
            approval_id=approval_id or self._pending_approval,
        )
        return self._send(request)

    def check(
        self, tool: str, args: Mapping[str, Any] | None = None, *, approval_id: str | None = None
    ) -> AuthorizationResult:
        """Like :meth:`authorize`, but raises unless the call is allowed."""
        result = self.authorize(tool, args, approval_id=approval_id)
        if result.decision is Decision.REQUIRE_APPROVAL:
            raise ApprovalRequired(result)
        if result.decision is not Decision.ALLOW:
            raise AccessDenied(result)
        return result

    def guard(
        self, tool: str | None = None, *, observe_output: bool = False, pass_receipt: bool = False
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorator: authorize every call to the wrapped function before running it.

        With ``pass_receipt=True`` the wrapped function also receives ``agentwarden_receipt=...``
        (forward it to tools that verify receipts, e.g. as the ``X-AgentWarden-Receipt`` header).
        The receipt covers the arguments the function was called with, not ``agentwarden_receipt``.
        """

        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            name = tool or func.__name__
            signature = inspect.signature(func)

            @functools.wraps(func)
            def wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                call_kwargs: dict[str, Any] = dict(kwargs)
                call_kwargs.pop("agentwarden_receipt", None)
                bound = signature.bind_partial(*args, **call_kwargs)
                bound.apply_defaults()
                arguments = {k: v for k, v in bound.arguments.items() if k != "agentwarden_receipt"}
                decision = self.check(name, arguments)
                if pass_receipt:
                    call_kwargs["agentwarden_receipt"] = decision.receipt
                result = func(*args, **call_kwargs)
                if observe_output:
                    self.observe(f"tool:{name}", result)
                return result

            return wrapper

        return decorator

    def _send(self, request: AuthorizeRequest) -> AuthorizationResult:  # pragma: no cover
        raise NotImplementedError


class WardenClient(_WardenBase):
    """HTTP client for a remote AgentWarden service."""

    def __init__(
        self,
        base_url: str,
        token: str,
        *,
        http_client: httpx.Client | None = None,
        timeout: float = 10.0,
        dpop_key: DpopKey | None = None,
    ) -> None:
        super().__init__()
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._dpop_key = dpop_key
        self._http = http_client or httpx.Client(base_url=base_url, timeout=timeout)
        self._owns_http = http_client is None

    def _send(self, request: AuthorizeRequest) -> AuthorizationResult:
        if self._dpop_key is not None:  # a fresh proof for every call (RFC 9449)
            headers = self._dpop_key.headers("POST", self._base_url + "/v1/authorize", self._token)
        else:
            headers = {"Authorization": f"Bearer {self._token}"}
        response = self._http.post(
            "/v1/authorize", json=request.model_dump(mode="json"), headers=headers
        )
        if response.status_code == 401:
            raise AuthenticationError(response.json().get("detail", "authentication failed"))
        if response.status_code == 429:
            retry_after = float(response.headers.get("Retry-After", "1"))
            raise RateLimitedError(response.json().get("detail", "rate limited"), retry_after)
        response.raise_for_status()
        return AuthorizationResult.model_validate(response.json())

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> WardenClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class LocalWarden(_WardenBase):
    """In-process client backed by a :class:`~agentwarden.gateway.Gateway`."""

    def __init__(self, gateway: Any, token: str, dpop_key: DpopKey | None = None) -> None:
        super().__init__()
        self._gateway = gateway
        self._token = token
        self._dpop_key = dpop_key

    def _send(self, request: AuthorizeRequest) -> AuthorizationResult:
        dpop = None
        if self._dpop_key is not None:
            url = self._gateway.endpoint_url("/v1/authorize")
            dpop = DpopPresentation(self._dpop_key.proof("POST", url, self._token), "POST", url)
        result: AuthorizationResult = self._gateway.authorize(self._token, request, dpop=dpop)
        return result
