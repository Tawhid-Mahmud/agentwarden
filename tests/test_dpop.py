"""DPoP sender-constrained tokens (RFC 9449): binding, proof checks and attacks."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from jwt.algorithms import ECAlgorithm

from agentwarden.api import create_app
from agentwarden.cli import main
from agentwarden.config import Settings
from agentwarden.errors import AuthenticationError, ConfigurationError
from agentwarden.gateway import Gateway
from agentwarden.identity.dpop import (
    DpopError,
    DpopPresentation,
    DpopVerifier,
    access_token_hash,
    normalize_htu,
)
from agentwarden.models import AuthorizeRequest, Decision, TokenRequest
from agentwarden.sdk import DpopKey, LocalWarden, WardenClient
from agentwarden.storage import Database
from tests.conftest import FakeClock

BASE = "http://testserver"
AUTHZ = BASE + "/v1/authorize"
ALICE = {"X-API-Key": "alice-demo-key"}
READ = {"tool": "read_inbox"}


@pytest.fixture
def gw(settings: Settings) -> Iterator[Gateway]:
    with Gateway.build(settings) as gateway:  # real clock: proofs carry real iat values
        yield gateway


@pytest.fixture
def client(gw: Gateway) -> TestClient:
    return TestClient(create_app(gw))


@pytest.fixture
def key() -> DpopKey:
    return DpopKey()


def bound_token(client: TestClient, key: DpopKey) -> str:
    response = client.post(
        "/v1/tokens",
        headers={**ALICE, "DPoP": key.proof("POST", BASE + "/v1/tokens")},
        json={"agent_id": "inbox-assistant", "scopes": ["email:read", "email:send"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["token_type"] == "DPoP"
    return str(response.json()["access_token"])


def authorize(client: TestClient, headers: dict[str, str]) -> Any:
    return client.post("/v1/authorize", headers=headers, json=READ)


def forged_proof(
    key: Any, jwk: dict[str, Any], *, alg: str = "ES256", typ: str = "dpop+jwt", **claims: Any
) -> str:
    body = {"jti": uuid.uuid4().hex, "htm": "POST", "htu": AUTHZ, "iat": int(time.time()), **claims}
    return jwt.encode(body, key, algorithm=alg, headers={"typ": typ, "jwk": jwk})


# ------------------------------------------------------------------------------ happy path
def test_bound_token_works_only_with_its_key(client: TestClient, gw: Gateway, key: DpopKey) -> None:
    token = bound_token(client, key)
    assert jwt.decode(token, options={"verify_signature": False})["cnf"] == {"jkt": key.thumbprint}
    ok = authorize(client, key.headers("POST", AUTHZ, token))
    assert ok.status_code == 200 and ok.json()["decision"] == "allow"
    assert gw.tokens.verify(token).jkt == key.thumbprint


# ------------------------------------------------------------------------------ attacks
def test_stolen_token_with_attackers_key_is_rejected(client: TestClient, key: DpopKey) -> None:
    token = bound_token(client, key)
    attacker = DpopKey()
    response = authorize(client, attacker.headers("POST", AUTHZ, token))
    assert response.status_code == 401 and "different key" in response.json()["detail"]
    assert 'error="invalid_dpop_proof"' in response.headers["WWW-Authenticate"]


def test_bound_token_cant_be_downgraded_to_bearer(client: TestClient, key: DpopKey) -> None:
    token = bound_token(client, key)
    assert (
        "send it with a DPoP proof"
        in authorize(client, {"Authorization": f"Bearer {token}"}).json()["detail"]
    )
    with_proof = {"Authorization": f"Bearer {token}", "DPoP": key.proof("POST", AUTHZ, token)}
    assert "must use 'Authorization: DPoP'" in authorize(client, with_proof).json()["detail"]


def test_proofs_cant_be_replayed(client: TestClient, key: DpopKey) -> None:
    token = bound_token(client, key)
    headers = key.headers("POST", AUTHZ, token)
    assert authorize(client, headers).status_code == 200
    replay = authorize(client, headers)
    assert replay.status_code == 401 and "replay" in replay.json()["detail"]


@pytest.mark.parametrize(
    ("method", "url", "for_other_token", "message"),
    [
        ("GET", AUTHZ, False, "different HTTP method"),
        ("POST", BASE + "/v1/tokens/revoke", False, "different URL"),
        ("POST", "https://evil.example/v1/authorize", False, "different URL"),
        ("POST", AUTHZ, True, "(ath)"),
    ],
)
def test_proofs_are_bound_to_the_request_and_token(
    client: TestClient, key: DpopKey, method: str, url: str, for_other_token: bool, message: str
) -> None:
    token = bound_token(client, key)
    proof = key.proof(method, url, "some-other-token" if for_other_token else token)
    response = authorize(client, {"Authorization": f"DPoP {token}", "DPoP": proof})
    assert response.status_code == 401 and message in response.json()["detail"]


def test_malformed_and_forged_proofs(client: TestClient, key: DpopKey) -> None:
    token = bound_token(client, key)
    ath = access_token_hash(token)
    private = ec.generate_private_key(ec.SECP256R1())
    public = json.loads(ECAlgorithm.to_jwk(private.public_key()))
    leaky = json.loads(ECAlgorithm.to_jwk(private))  # includes "d"
    cases = {
        "malformed DPoP proof": "garbage",
        "typ dpop+jwt": forged_proof(private, public, typ="JWT", ath=ath),
        "algorithm 'HS256'": jwt.encode(
            {"jti": "x"}, "k" * 32, algorithm="HS256", headers={"typ": "dpop+jwt", "jwk": public}
        ),
        "no private key material": forged_proof(private, leaky, ath=ath),
        "too old": forged_proof(private, public, ath=ath, iat=int(time.time()) - 3600),
        "from the future": forged_proof(private, public, ath=ath, iat=int(time.time()) + 3600),
        "invalid DPoP proof": forged_proof(private, public, ath=ath, htm=None),
    }
    for expected, proof in cases.items():
        response = authorize(client, {"Authorization": f"DPoP {token}", "DPoP": proof})
        assert response.status_code == 401, expected
        assert expected in response.json()["detail"], (expected, response.json())
    unsigned = jwt.encode(
        {"jti": "x", "htm": "POST", "htu": AUTHZ, "iat": int(time.time())},
        None,
        algorithm="none",
        headers={"typ": "dpop+jwt", "jwk": public},
    )
    assert (
        authorize(client, {"Authorization": f"DPoP {token}", "DPoP": unsigned}).status_code == 401
    )


def test_dpop_scheme_with_an_unbound_token_is_rejected(client: TestClient, key: DpopKey) -> None:
    plain = client.post(
        "/v1/tokens", headers=ALICE, json={"agent_id": "inbox-assistant", "scopes": ["email:read"]}
    ).json()
    assert plain["token_type"] == "Bearer"
    token = plain["access_token"]
    assert authorize(client, {"Authorization": f"Bearer {token}"}).status_code == 200
    response = authorize(client, key.headers("POST", AUTHZ, token))
    assert response.status_code == 401 and "isn't DPoP-bound" in response.json()["detail"]


# ------------------------------------------------------------------------------ policy & lifecycle
def test_dpop_can_be_required(settings: Settings) -> None:
    with Gateway.build(replace(settings, dpop_required=True)) as gw:
        client = TestClient(create_app(gw))
        unbound = client.post(
            "/v1/tokens",
            headers=ALICE,
            json={"agent_id": "inbox-assistant", "scopes": ["email:read"]},
        )
        assert unbound.status_code == 400 and "DPoP is required" in unbound.json()["detail"]
        key = DpopKey()
        assert (
            authorize(client, key.headers("POST", AUTHZ, bound_token(client, key))).status_code
            == 200
        )
        legacy = gw.tokens.issue(
            user=gw.directory.users["alice"],
            agent=gw.registry.require("inbox-assistant"),
            scopes=["email:read"],
        )
        with pytest.raises(DpopError, match="isn't bound"):
            gw.authorize(legacy.access_token, AuthorizeRequest(tool="read_inbox"))


def test_delegation_keeps_the_binding(client: TestClient, key: DpopKey) -> None:
    token = bound_token(client, key)
    url = BASE + "/v1/tokens/delegate"
    body = {"sub_agent_id": "summarizer", "scopes": ["email:read"]}
    shed = client.post(url, headers=key.headers("POST", url, token), json=body)
    assert shed.status_code == 400 and "child must be bound" in shed.json()["detail"]
    sub_key = DpopKey()
    child = client.post(
        url, headers=key.headers("POST", url, token), json={**body, "dpop_jkt": sub_key.thumbprint}
    ).json()
    assert child["token_type"] == "DPoP"
    child_token = child["access_token"]
    assert (
        authorize(client, key.headers("POST", AUTHZ, child_token)).status_code == 401
    )  # parent's key
    assert (
        authorize(client, sub_key.headers("POST", AUTHZ, child_token)).json()["agent_id"]
        == "summarizer"
    )
    revoke_url = BASE + "/v1/tokens/revoke"
    assert (
        client.post(revoke_url, headers=key.headers("POST", revoke_url, token)).status_code == 204
    )
    assert (
        authorize(client, sub_key.headers("POST", AUTHZ, child_token)).status_code == 401
    )  # cascade


def test_token_exchange_can_bind(settings: Settings, clock: FakeClock) -> None:
    import httpx

    from agentwarden.identity.oidc import OidcVerifier
    from tests.test_oidc import CLIENT_ID, GRANT, ID_TOKEN_TYPE, ISSUER, FakeIdP

    idp = FakeIdP(FakeClock())
    verifier = OidcVerifier(
        issuer=ISSUER,
        audience=CLIENT_ID,
        http=httpx.Client(transport=httpx.MockTransport(idp.handler)),
    )
    with Gateway.build(
        replace(settings, oidc_issuer=ISSUER, oidc_audience=CLIENT_ID), oidc=verifier
    ) as gw:
        client = TestClient(create_app(gw))
        key = DpopKey()
        url = BASE + "/v1/token/exchange"
        form = {
            "grant_type": GRANT,
            "subject_token_type": ID_TOKEN_TYPE,
            "audience": "agent:inbox-assistant",
            "scope": "email:read",
        }
        bound = client.post(
            url,
            data={**form, "subject_token": idp.token()},
            headers={"DPoP": key.proof("POST", url)},
        ).json()
        assert bound["token_type"] == "DPoP"
        bad = client.post(
            url, data={**form, "subject_token": idp.token(nonce="2")}, headers={"DPoP": "nope"}
        )
        assert bad.status_code == 400 and bad.json()["error"] == "invalid_dpop_proof"


def test_public_url_is_what_proofs_must_name(settings: Settings) -> None:
    public = "https://warden.example.com"
    with Gateway.build(replace(settings, public_url=public)) as gw:
        client = TestClient(create_app(gw))
        key = DpopKey()
        issued = client.post(
            "/v1/tokens",
            headers={**ALICE, "DPoP": key.proof("POST", public + "/v1/tokens")},
            json={"agent_id": "inbox-assistant", "scopes": ["email:read"]},
        )
        token = issued.json()["access_token"]
        assert (
            authorize(client, key.headers("POST", AUTHZ, token)).status_code == 401
        )  # internal URL
        assert (
            authorize(client, key.headers("POST", public + "/v1/authorize", token)).status_code
            == 200
        )


# ------------------------------------------------------------------------------ SDK, CLI, units
def test_sdk_clients_sign_every_call(client: TestClient, gw: Gateway, key: DpopKey) -> None:
    token = bound_token(client, key)
    remote = WardenClient(BASE, token, http_client=client, dpop_key=key)
    assert remote.authorize("read_inbox").decision is Decision.ALLOW
    assert remote.authorize("read_inbox").decision is Decision.ALLOW  # a fresh proof each time
    with pytest.raises(AuthenticationError):
        WardenClient(BASE, token, http_client=client).authorize("read_inbox")
    local_token = gw.issue_token(
        gw.directory.users["alice"],
        TokenRequest(agent_id="inbox-assistant", scopes=["email:read"]),
        jkt=key.thumbprint,
    ).access_token
    assert (
        LocalWarden(gw, local_token, dpop_key=key).authorize("read_inbox").decision
        is Decision.ALLOW
    )
    with pytest.raises(AuthenticationError):
        LocalWarden(gw, local_token).authorize("read_inbox")
    assert gw.endpoint_url("/v1/authorize") == "http://agentwarden.local/v1/authorize"
    assert gw.dpop_thumbprint(None) is None
    assert (
        gw.dpop_thumbprint(DpopPresentation(key.proof("POST", AUTHZ), "POST", AUTHZ))
        == key.thumbprint
    )


def test_replays_are_caught_by_the_shared_database(db: Database, key: DpopKey) -> None:
    """The jti store is in the database, so another instance rejects a replay too."""
    first, second = DpopVerifier(db), DpopVerifier(db)
    proof = key.proof("POST", AUTHZ)
    assert first.verify(proof, method="POST", url=AUTHZ) == key.thumbprint
    with pytest.raises(DpopError, match="replay"):
        second.verify(proof, method="POST", url=AUTHZ)


@pytest.mark.parametrize(
    ("raw", "normal"),
    [
        (
            "HTTPS://Warden.Example.com:443/v1/authorize?x=1#f",
            "https://warden.example.com/v1/authorize",
        ),
        ("http://localhost:8000/v1/authorize", "http://localhost:8000/v1/authorize"),
        ("http://example.com:80", "http://example.com/"),
    ],
)
def test_htu_normalization(raw: str, normal: str) -> None:
    assert normalize_htu(raw) == normal


def test_keys_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    key = DpopKey()
    path = key.save(tmp_path / "agent.pem")
    assert path.stat().st_mode & 0o777 == 0o600 and DpopKey.load(path).thumbprint == key.thumbprint
    with pytest.raises(FileExistsError):
        key.save(path)
    with pytest.raises(ValueError, match="P-256"):
        DpopKey(ec.generate_private_key(ec.SECP384R1()))
    out = tmp_path / "cli.pem"
    assert main(["dpop", "keygen", "--out", str(out)]) == 0
    jkt = capsys.readouterr().out.split("jkt: ")[1].strip()
    assert main(["dpop", "thumbprint", str(out)]) == 0 and capsys.readouterr().out.strip() == jkt
    assert main(["dpop", "keygen", "--out", str(out)]) == 1
    s = Settings.from_env(
        {
            "AGENTWARDEN_DPOP_REQUIRED": "true",
            "AGENTWARDEN_PUBLIC_URL": "https://w.example/",
            "AGENTWARDEN_DPOP_MAX_AGE": "120",
        }
    )
    assert (s.dpop_required, s.public_url, s.dpop_max_age) == (True, "https://w.example", 120)
    for bad in ({"dpop_max_age": 1}, {"public_url": "ftp://x"}):
        with pytest.raises(ConfigurationError):
            Settings(**bad)  # type: ignore[arg-type]
