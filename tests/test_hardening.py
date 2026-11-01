"""Rate limiting, one-time ID tokens and tool-side authorization receipts."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from agentwarden.api import create_app
from agentwarden.config import Settings
from agentwarden.errors import (
    AuthenticationError,
    ConfigurationError,
    PermissionDeniedError,
    RateLimitedError,
)
from agentwarden.gateway import Gateway
from agentwarden.identity import KeyManager
from agentwarden.models import AuthorizeRequest, Decision, TokenRequest
from agentwarden.ratelimit import RateLimiter
from agentwarden.receipts import HTTP_HEADER, ReceiptVerifier, args_digest, issue_receipt
from agentwarden.sdk import AccessDenied, LocalWarden, WardenClient
from tests.conftest import FakeClock


@pytest.fixture
def gw(settings: Settings, clock: FakeClock) -> Iterator[Gateway]:
    with Gateway.build(settings, clock=clock) as gateway:
        yield gateway


def agent_token(gw: Gateway, scopes: list[str] | None = None) -> str:
    request = TokenRequest(
        agent_id="inbox-assistant", scopes=scopes or ["email:read", "email:send"]
    )
    return gw.issue_token(gw.directory.users["alice"], request).access_token


# =============================================================================== rate limiter
def test_token_bucket(clock: FakeClock) -> None:
    limiter = RateLimiter(60, burst=3, clock=clock)
    assert [limiter.hit("a") for _ in range(3)] == [None, None, None]
    retry = limiter.hit("a")
    assert retry is not None and 0.9 < retry <= 1.0  # 60/min refills one token per second
    assert limiter.hit("b") is None  # buckets are per key
    assert limiter.peek("a") is not None
    clock.advance(1.0)
    assert limiter.peek("a") is None and limiter.hit("a") is None
    assert RateLimiter(0).hit("x") is None and not RateLimiter(0).enabled


def test_limiter_memory_is_bounded(clock: FakeClock) -> None:
    limiter = RateLimiter(10, clock=clock, max_keys=100)
    for i in range(1000):
        limiter.hit(f"ip-{i}")
    assert len(limiter._buckets) == 100


def test_per_agent_limit(settings: Settings, clock: FakeClock) -> None:
    with Gateway.build(replace(settings, rate_limit_per_agent=3), clock=clock) as gw:
        token = agent_token(gw)
        for _ in range(3):
            gw.authorize(token, AuthorizeRequest(tool="read_inbox"))
        with pytest.raises(RateLimitedError) as exc:
            gw.authorize(token, AuthorizeRequest(tool="read_inbox"))
        assert exc.value.retry_after > 0
        clock.advance(60)
        assert gw.authorize(token, AuthorizeRequest(tool="read_inbox")).decision is Decision.ALLOW


def test_api_limits(settings: Settings, clock: FakeClock) -> None:
    limits = replace(
        settings,
        rate_limit_per_ip=5,
        rate_limit_sensitive_per_ip=2,
        rate_limit_auth_failures_per_ip=3,
    )
    with Gateway.build(limits, clock=clock) as gw:
        client = TestClient(create_app(gw))
        assert client.get("/healthz").status_code == 200  # non-API paths aren't limited
        body = {"agent_id": "inbox-assistant", "scopes": ["email:read"]}
        statuses = [
            client.post(
                "/v1/tokens", headers={"X-API-Key": "alice-demo-key"}, json=body
            ).status_code
            for _ in range(3)
        ]
        assert statuses == [200, 200, 429]
        limited = client.post("/v1/tokens", headers={"X-API-Key": "alice-demo-key"}, json=body)
        assert (
            limited.headers["Retry-After"].isdigit()
            and limited.json()["error"] == "RateLimitedError"
        )

    with Gateway.build(limits, clock=clock) as gw:
        client = TestClient(create_app(gw))
        for _ in range(3):
            assert client.get("/v1/approvals", headers={"X-API-Key": "wrong"}).status_code == 401
        locked = client.get("/v1/approvals", headers={"X-API-Key": "bob-demo-key"})
        assert locked.status_code == 429 and "failed sign-ins" in locked.json()["detail"]


def test_forwarded_for_is_only_trusted_when_configured(
    settings: Settings, clock: FakeClock
) -> None:
    for trusted, expected in ((False, [200, 429]), (True, [200, 200])):
        with Gateway.build(
            replace(settings, rate_limit_per_ip=1, trust_proxy_headers=trusted), clock=clock
        ) as gw:
            client = TestClient(create_app(gw))
            codes = [
                client.get(
                    "/v1/me", headers={"X-API-Key": "bob-demo-key", "X-Forwarded-For": ip}
                ).status_code
                for ip in ("10.0.0.1", "10.0.0.2")
            ]
            assert codes == expected


def test_sdk_raises_rate_limited(settings: Settings, clock: FakeClock) -> None:
    with Gateway.build(replace(settings, rate_limit_per_agent=1), clock=clock) as gw:
        client = TestClient(create_app(gw))
        warden = WardenClient("http://testserver", agent_token(gw), http_client=client)
        warden.authorize("read_inbox")
        with pytest.raises(RateLimitedError):
            warden.authorize("read_inbox")


def test_rate_limit_settings() -> None:
    s = Settings.from_env(
        {
            "AGENTWARDEN_RATE_LIMIT_PER_AGENT": "0",
            "AGENTWARDEN_TRUST_PROXY_HEADERS": "1",
            "AGENTWARDEN_RECEIPT_TTL": "30",
        }
    )
    assert (s.rate_limit_per_agent, s.trust_proxy_headers, s.receipt_ttl) == (0, True, 30)
    with pytest.raises(ConfigurationError):
        Settings(rate_limit_per_ip=-1)
    with pytest.raises(ConfigurationError):
        Settings(receipt_ttl=3600)


# =============================================================================== one-time ID tokens
def test_id_tokens_can_be_exchanged_once(settings: Settings, clock: FakeClock) -> None:
    from agentwarden.identity.oidc import OidcVerifier
    from tests.test_oidc import CLIENT_ID, ISSUER, FakeIdP

    idp = FakeIdP(clock)
    verifier = OidcVerifier(
        issuer=ISSUER,
        audience=CLIENT_ID,
        http=httpx.Client(transport=httpx.MockTransport(idp.handler)),
        clock=clock,
    )
    oidc = replace(settings, oidc_issuer=ISSUER, oidc_audience=CLIENT_ID)
    with Gateway.build(oidc, clock=clock, oidc=verifier) as gw:
        id_token = idp.token()
        request = TokenRequest(agent_id="inbox-assistant", scopes=["email:read"])
        with pytest.raises(PermissionDeniedError):  # a failed exchange doesn't burn the sign-in...
            gw.exchange_token(id_token, TokenRequest(agent_id="finance-bot", scopes=["crm:write"]))
        assert gw.exchange_token(id_token, request).scope == ["email:read"]  # ...so this works
        with pytest.raises(AuthenticationError, match="already been exchanged"):
            gw.exchange_token(id_token, request)
        assert any(
            e.data.get("reason") == "ID token replayed"
            for e in gw.audit.query(event_type="auth.failed")
        )
        clock.advance(700)  # 5 minutes past the first token's expiry
        gw.exchange_token(idp.token(nonce="new"), request)  # expired entries are purged meanwhile
        assert gw.db.query_one("SELECT COUNT(*) AS n FROM used_id_tokens")["n"] == 1

    with Gateway.build(replace(oidc, oidc_one_time_tokens=False), clock=clock, oidc=verifier) as gw:
        id_token = idp.token(nonce="reusable")
        gw.exchange_token(id_token, request)
        gw.exchange_token(id_token, request)


# =============================================================================== receipts
def test_allowed_decisions_carry_a_receipt(gw: Gateway, settings: Settings) -> None:
    token = agent_token(gw)
    args = {"to": ["bob@acme.example"], "body": "hi"}
    allowed = gw.authorize(
        token, AuthorizeRequest(tool="send_email", args=args, user_prompt="email bob")
    )
    assert allowed.decision is Decision.ALLOW and allowed.receipt
    header = jwt.get_unverified_header(allowed.receipt)
    assert header["typ"] == "aw-receipt+jwt" and header["kid"] == gw.keys.kid
    pending = gw.authorize(
        token, AuthorizeRequest(tool="send_email", args={"to": ["x@contoso.example"]})
    )
    denied = gw.authorize(token, AuthorizeRequest(tool="transfer_funds", args={}))
    assert pending.receipt is None and denied.receipt is None
    assert allowed.receipt not in str(gw.audit.query(limit=5))  # receipts are not logged

    verifier = ReceiptVerifier(issuer=settings.issuer, jwks=gw.keys.jwks())
    claims = verifier.verify(allowed.receipt, tool="send_email", args=args)
    assert (claims.user_id, claims.agent_id, claims.decision_id) == (
        "alice",
        "inbox-assistant",
        allowed.decision_id,
    )


@pytest.fixture
def receipt_setup(
    gw: Gateway, settings: Settings, clock: FakeClock
) -> tuple[str, dict[str, Any], ReceiptVerifier]:
    args = {"to": ["bob@acme.example"], "amount": 1}
    result = gw.authorize(
        agent_token(gw), AuthorizeRequest(tool="send_email", args=args, user_prompt="email bob")
    )
    assert result.receipt
    return (
        result.receipt,
        args,
        ReceiptVerifier(issuer=settings.issuer, jwks=gw.keys.jwks(), clock=clock),
    )


def test_receipts_are_bound_to_tool_args_time_and_single_use(
    receipt_setup: Any, clock: FakeClock
) -> None:
    receipt, args, verifier = receipt_setup
    with pytest.raises(PermissionDeniedError, match="requires an AgentWarden receipt"):
        verifier.verify(None, tool="send_email", args=args)
    with pytest.raises(AuthenticationError):
        verifier.verify(receipt, tool="read_inbox", args=args)  # audience is tool:send_email
    with pytest.raises(PermissionDeniedError, match="arguments differ"):
        verifier.verify(receipt, tool="send_email", args={**args, "to": ["eve@evil.example"]})
    verifier.verify(
        receipt, tool="send_email", args={"amount": 1, "to": ["bob@acme.example"]}
    )  # key order doesn't matter
    with pytest.raises(PermissionDeniedError, match="replay"):
        verifier.verify(receipt, tool="send_email", args=args)


def test_expired_and_forged_receipts(gw: Gateway, settings: Settings, clock: FakeClock) -> None:
    args = {"to": ["bob@acme.example"]}
    verifier = ReceiptVerifier(issuer=settings.issuer, jwks=gw.keys.jwks(), clock=clock)
    old = gw.authorize(agent_token(gw), AuthorizeRequest(tool="send_email", args=args)).receipt
    clock.advance(settings.receipt_ttl + 10)
    with pytest.raises(AuthenticationError, match="expired"):
        verifier.verify(old, tool="send_email", args=args)
    attacker = KeyManager.generate()
    forged = issue_receipt(
        attacker,
        issuer=settings.issuer,
        user_id="alice",
        actor_chain=["inbox-assistant"],
        tool="send_email",
        args=args,
        decision_id="dec_x",
        ttl=60,
        now=clock.now,
    )
    with pytest.raises(AuthenticationError, match="unknown key"):
        verifier.verify(forged, tool="send_email", args=args)
    with pytest.raises(AuthenticationError, match="not an AgentWarden receipt"):
        verifier.verify(
            agent_token(gw), tool="send_email", args=args
        )  # an agent token is not a receipt
    with pytest.raises(AuthenticationError, match="malformed"):
        verifier.verify("nonsense", tool="send_email", args=args)


def test_verifier_fetches_and_refreshes_jwks(
    gw: Gateway, settings: Settings, clock: FakeClock
) -> None:
    fetches: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetches.append(1)
        return httpx.Response(200, json=gw.keys.jwks())

    verifier = ReceiptVerifier(
        issuer=settings.issuer, jwks_url="https://warden.internal/.well-known/jwks.json",
        http=httpx.Client(transport=httpx.MockTransport(handler)), clock=clock,
    )  # fmt: skip
    args = {"to": ["bob@acme.example"]}
    receipt = gw.authorize(agent_token(gw), AuthorizeRequest(tool="send_email", args=args)).receipt
    verifier.verify(receipt, tool="send_email", args=args)
    assert len(fetches) == 1
    with pytest.raises(ValueError):
        ReceiptVerifier(issuer=settings.issuer)
    assert args_digest({"b": 1, "a": "é"}) == args_digest({"a": "é", "b": 1})


def test_sdk_passes_receipts_to_tools(gw: Gateway, settings: Settings) -> None:
    warden = LocalWarden(gw, agent_token(gw))
    verifier = ReceiptVerifier(issuer=settings.issuer, jwks=gw.keys.jwks())
    delivered: list[str] = []

    @warden.guard(pass_receipt=True)
    def send_email(to: list[str], body: str = "", agentwarden_receipt: str | None = None) -> str:
        claims = verifier.verify(
            agentwarden_receipt, tool="send_email", args={"to": to, "body": body}
        )
        delivered.append(claims.decision_id)
        return "sent"

    assert send_email(["bob@acme.example"], body="hi") == "sent" and len(delivered) == 1
    with pytest.raises(AccessDenied):
        send_email(["x@evil.example"], body=open_secret())
    assert HTTP_HEADER == "X-AgentWarden-Receipt"


def open_secret() -> str:
    return "AKIA" + "IOSFODNN7" + "EXAMPLE"
