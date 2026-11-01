"""OIDC sign-in and RFC 8693 token exchange, against a fake identity provider."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from agentwarden.api import create_app
from agentwarden.config import Settings
from agentwarden.errors import AuthenticationError, ConfigurationError
from agentwarden.gateway import Gateway
from agentwarden.identity.oidc import OidcVerifier
from tests.conftest import FakeClock

ISSUER = "https://idp.example"
CLIENT_ID = "agentwarden-client"
GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ID_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id_token"
_KEYS = {
    kid: rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for kid in ("k1", "k2", "rogue")
}


class FakeIdP:
    """Discovery document + JWKS served through an httpx mock transport."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.published = ["k1"]
        self.fetches = 0
        self.issuer_in_discovery = ISSUER
        self.down = False

    def handler(self, request: httpx.Request) -> httpx.Response:
        if self.down:
            return httpx.Response(503)
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(
                200, json={"issuer": self.issuer_in_discovery, "jwks_uri": f"{ISSUER}/jwks"}
            )
        if request.url.path == "/jwks":
            self.fetches += 1
            keys = [
                {
                    **json.loads(RSAAlgorithm.to_jwk(_KEYS[kid].public_key())),
                    "kid": kid,
                    "use": "sig",
                    "alg": "RS256",
                }
                for kid in self.published
            ]
            keys.append(
                {"kty": "oct", "k": "c2VjcmV0", "kid": "hmac", "use": "sig"}
            )  # must be ignored
            return httpx.Response(200, json={"keys": keys})
        return httpx.Response(404)

    def token(self, kid: str = "k1", alg: str = "RS256", **overrides: Any) -> str:
        now = self.clock.now
        claims: dict[str, Any] = {
            "iss": ISSUER, "aud": CLIENT_ID, "sub": "user-123", "email": "Alice@acme.example",
            "email_verified": True, "iat": int(now), "exp": int(now) + 300,
        }  # fmt: skip
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, _KEYS[kid], algorithm=alg, headers={"kid": kid})


@pytest.fixture
def idp(clock: FakeClock) -> FakeIdP:
    return FakeIdP(clock)


@pytest.fixture
def verifier(idp: FakeIdP, clock: FakeClock) -> OidcVerifier:
    return OidcVerifier(
        issuer=ISSUER,
        audience=CLIENT_ID,
        http=httpx.Client(transport=httpx.MockTransport(idp.handler)),
        clock=clock,
    )


# ------------------------------------------------------------------------------ verifier
def test_valid_id_token(verifier: OidcVerifier, idp: FakeIdP) -> None:
    identity = verifier.verify(idp.token())
    assert (
        identity.subject == "user-123"
        and identity.email == "alice@acme.example"
        and identity.email_verified
    )
    assert identity.issuer == ISSUER


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"iss": "https://evil.example"}, "invalid ID token"),
        ({"aud": "some-other-app"}, "invalid ID token"),
        ({"exp": 1}, "expired"),
        ({"iat": 10**10}, "future"),
        ({"nbf": 10**10}, "not valid yet"),
        ({"aud": [CLIENT_ID, "other"], "azp": "other"}, "different client"),
        ({"email_verified": False}, "verified email"),
        ({"email": None}, "verified email"),
        ({"sub": None}, "invalid ID token"),
    ],
)
def test_invalid_claims_rejected(
    verifier: OidcVerifier, idp: FakeIdP, overrides: dict[str, Any], message: str
) -> None:
    with pytest.raises(AuthenticationError, match=message):
        verifier.verify(idp.token(**overrides))


def test_unverified_email_allowed_when_matching_by_subject(
    verifier: OidcVerifier, idp: FakeIdP
) -> None:
    assert (
        verifier.verify(idp.token(email_verified=False), require_verified_email=False).subject
        == "user-123"
    )


def _b64(obj: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_algorithm_attacks_rejected(verifier: OidcVerifier, idp: FakeIdP) -> None:
    payload = jwt.decode(idp.token(), options={"verify_signature": False})
    none_token = f"{_b64({'alg': 'none', 'kid': 'k1'})}.{_b64(payload)}."
    with pytest.raises(AuthenticationError, match="not accepted"):
        verifier.verify(none_token)
    # HMAC "signed" with the public key, the classic key-confusion attack
    header, body = _b64({"alg": "HS256", "kid": "k1"}), _b64(payload)
    public_jwk = RSAAlgorithm.to_jwk(_KEYS["k1"].public_key()).encode()
    sig = (
        base64.urlsafe_b64encode(
            hmac.new(public_jwk, f"{header}.{body}".encode(), hashlib.sha256).digest()
        )
        .rstrip(b"=")
        .decode()
    )
    with pytest.raises(AuthenticationError, match="not accepted"):
        verifier.verify(f"{header}.{body}.{sig}")
    with pytest.raises(AuthenticationError, match="malformed"):
        verifier.verify("garbage")
    no_kid = jwt.encode(payload, _KEYS["k1"], algorithm="RS256")
    with pytest.raises(AuthenticationError, match="no key id"):
        verifier.verify(no_kid)


def test_forged_signature_rejected(verifier: OidcVerifier, idp: FakeIdP) -> None:
    header, payload, _ = idp.token().split(".")
    forged = idp.token(kid="rogue").split(".")[2]  # attacker's own key, victim's kid
    tampered = jwt.encode(
        jwt.decode(idp.token(), options={"verify_signature": False}),
        _KEYS["rogue"],
        algorithm="RS256",
        headers={"kid": "k1"},
    )
    with pytest.raises(AuthenticationError, match="invalid ID token"):
        verifier.verify(tampered)
    with pytest.raises(AuthenticationError, match="invalid ID token"):
        verifier.verify(f"{header}.{payload}.{forged}")


def test_key_rotation_and_refresh_rate_limit(
    verifier: OidcVerifier, idp: FakeIdP, clock: FakeClock
) -> None:
    verifier.verify(idp.token())
    assert idp.fetches == 1
    clock.advance(60)
    idp.published = ["k1", "k2"]  # the IdP rotates keys
    assert verifier.verify(idp.token(kid="k2")).subject == "user-123"
    assert idp.fetches == 2
    for _ in range(5):  # unknown kids can't make us hammer the IdP
        with pytest.raises(AuthenticationError, match="doesn't publish"):
            verifier.verify(idp.token(kid="rogue"))
    assert idp.fetches == 2


def test_idp_failures(idp: FakeIdP, clock: FakeClock) -> None:
    http = httpx.Client(transport=httpx.MockTransport(idp.handler))
    idp.issuer_in_discovery = "https://other.example"
    with pytest.raises(AuthenticationError, match="different issuer"):
        OidcVerifier(issuer=ISSUER, audience=CLIENT_ID, http=http, clock=clock).verify(idp.token())
    idp.issuer_in_discovery, idp.down = ISSUER, True
    with pytest.raises(AuthenticationError, match="could not reach"):
        OidcVerifier(issuer=ISSUER, audience=CLIENT_ID, http=http, clock=clock).verify(idp.token())


def test_insecure_configuration_rejected() -> None:
    with pytest.raises(ConfigurationError, match="https"):
        OidcVerifier(issuer="http://idp.example", audience=CLIENT_ID)
    with pytest.raises(ConfigurationError, match="https"):
        OidcVerifier(issuer=ISSUER, audience=CLIENT_ID, jwks_url="http://idp.example/jwks")
    with pytest.raises(ConfigurationError, match="asymmetric"):
        OidcVerifier(issuer=ISSUER, audience=CLIENT_ID, algorithms=("HS256",))
    assert (
        OidcVerifier(issuer="http://localhost:9000/", audience=CLIENT_ID).issuer
        == "http://localhost:9000"
    )


def test_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    s = Settings.from_env(
        {
            "AGENTWARDEN_OIDC_ISSUER": ISSUER,
            "AGENTWARDEN_OIDC_AUDIENCE": CLIENT_ID,
            "AGENTWARDEN_API_KEYS": "false",
            "AGENTWARDEN_OIDC_USER_CLAIM": "sub",
        }
    )
    assert (s.oidc_issuer, s.oidc_audience, s.api_keys_enabled, s.oidc_user_claim) == (
        ISSUER,
        CLIENT_ID,
        False,
        "sub",
    )
    for bad in (
        {"oidc_issuer": ISSUER},
        {"oidc_issuer": ISSUER, "oidc_audience": "x", "oidc_user_claim": "name"},
        {"api_keys_enabled": False},
    ):
        with pytest.raises(ConfigurationError):
            Settings(**bad)  # type: ignore[arg-type]


# ------------------------------------------------------------------------------ exchange API
@pytest.fixture
def gw(settings: Settings, clock: FakeClock, verifier: OidcVerifier) -> Iterator[Gateway]:
    oidc_settings = replace(settings, oidc_issuer=ISSUER, oidc_audience=CLIENT_ID)
    with Gateway.build(oidc_settings, clock=clock, oidc=verifier) as gateway:
        yield gateway


@pytest.fixture
def client(gw: Gateway) -> TestClient:
    return TestClient(create_app(gw))


def exchange(
    client: TestClient, subject_token: str, *, as_json: bool = False, **extra: str
) -> httpx.Response:
    params = {
        "grant_type": GRANT, "subject_token": subject_token, "subject_token_type": ID_TOKEN_TYPE,
        "audience": "agent:inbox-assistant", "scope": "email:read email:send payments:write", **extra,
    }  # fmt: skip
    if as_json:
        return client.post("/v1/token/exchange", json=params)
    return client.post("/v1/token/exchange", data=params)


def test_token_exchange_success(client: TestClient, idp: FakeIdP, gw: Gateway) -> None:
    response = exchange(client, idp.token(), task="triage inbox")
    body = response.json()
    assert response.status_code == 200 and response.headers["Cache-Control"] == "no-store"
    assert (
        body["issued_token_type"] == "urn:ietf:params:oauth:token-type:jwt"
        and body["token_type"] == "Bearer"
    )
    assert body["scope"] == "email:read email:send" and body["denied_scopes"] == ["payments:write"]
    claims = gw.tokens.verify(body["access_token"])
    assert (
        claims.user_id == "alice"
        and claims.agent_id == "inbox-assistant"
        and claims.task == "triage inbox"
    )
    assert gw.audit.query(event_type="token.exchanged")[0].data["idp"] == ISSUER
    via_json = exchange(client, idp.token(), as_json=True, agent_id="inbox-assistant", audience="")
    assert via_json.status_code == 200
    agent = client.post(
        "/v1/authorize",
        headers={"Authorization": f"Bearer {body['access_token']}"},
        json={"tool": "read_inbox"},
    )
    assert agent.json()["decision"] == "allow"


@pytest.mark.parametrize(
    ("extra", "error"),
    [
        ({"grant_type": "password"}, "unsupported_grant_type"),
        ({"subject_token_type": "urn:ietf:params:oauth:token-type:saml2"}, "invalid_request"),
        ({"audience": ""}, "invalid_target"),
        ({"audience": "agent:ghost-agent"}, "invalid_target"),
        ({"scope": ""}, "invalid_scope"),
        ({"ttl_seconds": "soon"}, "invalid_request"),
        ({"scope": "payments:write", "audience": "agent:research-agent"}, "invalid_scope"),
    ],
)
def test_token_exchange_errors(
    client: TestClient, idp: FakeIdP, extra: dict[str, str], error: str
) -> None:
    response = exchange(client, idp.token(), **extra)
    assert response.status_code == 400 and response.json()["error"] == error


def test_token_exchange_rejects_bad_identities(
    client: TestClient, idp: FakeIdP, gw: Gateway
) -> None:
    assert exchange(client, "").json()["error"] == "invalid_request"
    assert exchange(client, idp.token(aud="other-app")).json()["error"] == "invalid_grant"
    unknown = exchange(client, idp.token(email="mallory@acme.example"))
    assert unknown.json() == {
        "error": "invalid_grant",
        "error_description": "signed in, but this identity has no AgentWarden user",
    }
    assert len(gw.audit.query(event_type="auth.failed")) == 2


def test_approver_can_sign_in_with_an_id_token(client: TestClient, idp: FakeIdP) -> None:
    bob = {"Authorization": f"Bearer {idp.token(email='bob@acme.example')}"}
    assert client.get("/v1/approvals", headers=bob).status_code == 200
    alice = {"Authorization": f"Bearer {idp.token()}"}
    assert (
        client.get("/v1/approvals", headers=alice).status_code == 403
    )  # signed in, but not an approver
    issued = client.post(
        "/v1/tokens", headers=alice, json={"agent_id": "inbox-assistant", "scopes": ["email:read"]}
    )
    assert issued.status_code == 200


def test_api_keys_can_be_disabled(
    settings: Settings, clock: FakeClock, verifier: OidcVerifier, idp: FakeIdP
) -> None:
    strict = replace(settings, oidc_issuer=ISSUER, oidc_audience=CLIENT_ID, api_keys_enabled=False)
    with Gateway.build(strict, clock=clock, oidc=verifier) as gateway:
        client = TestClient(create_app(gateway))
        rejected = client.post(
            "/v1/tokens",
            headers={"X-API-Key": "alice-demo-key"},
            json={"agent_id": "inbox-assistant", "scopes": ["email:read"]},
        )
        assert (
            rejected.status_code == 401
            and rejected.json()["detail"] == "sign in with Authorization: Bearer <ID token>"
        )
        assert exchange(client, idp.token()).status_code == 200


def test_subject_claim_mapping(
    settings: Settings, clock: FakeClock, verifier: OidcVerifier, idp: FakeIdP
) -> None:
    by_sub = replace(settings, oidc_issuer=ISSUER, oidc_audience=CLIENT_ID, oidc_user_claim="sub")
    with Gateway.build(by_sub, clock=clock, oidc=verifier) as gateway:
        gateway.directory.users["carol"].oidc_subject = "user-123"
        assert gateway.authenticate_identity(idp.token(email_verified=False)).id == "carol"


def test_exchange_without_oidc_configured(
    settings: Settings, clock: FakeClock, idp: FakeIdP
) -> None:
    with Gateway.build(settings, clock=clock) as gateway:
        client = TestClient(create_app(gateway))
        response = exchange(client, idp.token())
        assert (
            response.json()["error"] == "invalid_grant"
            and "not configured" in response.json()["error_description"]
        )
        assert (
            client.get("/v1/approvals", headers={"Authorization": "Bearer x"}).json()["detail"]
            == "sign in with X-API-Key"
        )
