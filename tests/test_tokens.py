from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import replace

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from agentwarden.config import Settings
from agentwarden.directory import Directory
from agentwarden.errors import AuthenticationError, DelegationError, PermissionDeniedError
from agentwarden.identity import AgentRegistry, KeyManager, RevocationList, TokenService
from agentwarden.identity.tokens import TokenClaims
from tests.conftest import FakeClock


def _b64(obj: dict[str, object]) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


@pytest.fixture
def alice_token(tokens: TokenService, directory: Directory, registry: AgentRegistry) -> str:
    issued = tokens.issue(
        user=directory.users["alice"],
        agent=registry.require("inbox-assistant"),
        scopes=["email:read", "email:send"],
        task="triage inbox",
    )
    return issued.access_token


def test_issue_grants_intersection_and_reports_denied(
    tokens: TokenService, directory: Directory, registry: AgentRegistry
) -> None:
    issued = tokens.issue(
        user=directory.users["carol"],  # contractor: only docs:read
        agent=registry.require("research-agent"),
        scopes=["docs:read", "web:request"],
    )
    assert issued.scope == ["docs:read"]
    assert issued.denied_scopes == ["web:request"]
    claims = tokens.verify(issued.access_token)
    assert claims.user_id == "carol"
    assert claims.agent_id == "research-agent"
    assert claims.scopes == ("docs:read",)


def test_claims_follow_rfc8693_layout(alice_token: str, keys: KeyManager) -> None:
    header = jwt.get_unverified_header(alice_token)
    assert header == {"alg": "EdDSA", "kid": keys.kid, "typ": "at+jwt"}
    payload = jwt.decode(alice_token, options={"verify_signature": False})
    assert payload["sub"] == "user:alice"
    assert payload["act"] == {"sub": "agent:inbox-assistant"}
    assert payload["scope"] == "email:read email:send"
    assert payload["task"] == "triage inbox"


def test_issue_rejects_when_nothing_grantable(
    tokens: TokenService, directory: Directory, registry: AgentRegistry
) -> None:
    with pytest.raises(PermissionDeniedError, match="none of the requested scopes"):
        tokens.issue(
            user=directory.users["carol"],
            agent=registry.require("finance-bot"),
            scopes=["payments:write"],
        )


def test_issue_rejects_disabled_agent(
    tokens: TokenService, directory: Directory, registry: AgentRegistry
) -> None:
    agent = registry.set_enabled("inbox-assistant", False)
    with pytest.raises(PermissionDeniedError, match="disabled"):
        tokens.issue(user=directory.users["alice"], agent=agent, scopes=["email:read"])


def test_ttl_is_clamped_to_max(
    tokens: TokenService, directory: Directory, registry: AgentRegistry, settings: Settings
) -> None:
    issued = tokens.issue(
        user=directory.users["alice"],
        agent=registry.require("inbox-assistant"),
        scopes=["email:read"],
        ttl=999_999,
    )
    assert issued.expires_in == settings.max_token_ttl


def test_expired_token_rejected(alice_token: str, tokens: TokenService, clock: FakeClock) -> None:
    clock.advance(901 + 30)
    with pytest.raises(AuthenticationError, match="expired"):
        tokens.verify(alice_token)


def test_token_from_the_future_rejected(
    alice_token: str, tokens: TokenService, clock: FakeClock
) -> None:
    clock.advance(-120)
    with pytest.raises(AuthenticationError, match="future"):
        tokens.verify(alice_token)


def test_alg_none_rejected(alice_token: str, tokens: TokenService) -> None:
    payload = jwt.decode(alice_token, options={"verify_signature": False})
    forged = f"{_b64({'alg': 'none', 'typ': 'JWT'})}.{_b64(payload)}."
    with pytest.raises(AuthenticationError, match="unsupported token algorithm"):
        tokens.verify(forged)


def test_hmac_key_confusion_rejected(
    alice_token: str, tokens: TokenService, keys: KeyManager
) -> None:
    # Classic key-confusion attack: sign with HS256 using the *public* key as the HMAC secret.
    payload = jwt.decode(alice_token, options={"verify_signature": False})
    payload["scope"] = "payments:write"
    public_pem = keys.public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = _b64({"alg": "HS256", "typ": "JWT", "kid": keys.kid})
    body = _b64(payload)
    sig = hmac.new(public_pem, f"{header}.{body}".encode(), hashlib.sha256).digest()
    forged = f"{header}.{body}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"
    with pytest.raises(AuthenticationError, match="unsupported token algorithm"):
        tokens.verify(forged)


def test_tampered_payload_rejected(alice_token: str, tokens: TokenService) -> None:
    header, _, sig = alice_token.split(".")
    payload = jwt.decode(alice_token, options={"verify_signature": False})
    payload["scope"] = "email:read email:send payments:write"
    with pytest.raises(AuthenticationError, match="invalid token"):
        tokens.verify(f"{header}.{_b64(payload)}.{sig}")


def test_token_signed_by_other_key_rejected(
    tokens: TokenService, keys: KeyManager, alice_token: str
) -> None:
    attacker = KeyManager.generate()
    payload = jwt.decode(alice_token, options={"verify_signature": False})
    forged = jwt.encode(payload, attacker.private_key, algorithm="EdDSA", headers={"kid": keys.kid})
    with pytest.raises(AuthenticationError, match="invalid token"):
        tokens.verify(forged)
    forged_kid = jwt.encode(
        payload, attacker.private_key, algorithm="EdDSA", headers={"kid": attacker.kid}
    )
    with pytest.raises(AuthenticationError, match="unknown key"):
        tokens.verify(forged_kid)


def test_wrong_audience_rejected(
    keys: KeyManager,
    settings: Settings,
    revocations: RevocationList,
    clock: FakeClock,
    directory: Directory,
    registry: AgentRegistry,
) -> None:
    other = TokenService(keys, replace(settings, audience="other-service"), revocations, clock)
    token = other.issue(
        user=directory.users["alice"],
        agent=registry.require("inbox-assistant"),
        scopes=["email:read"],
    ).access_token
    mine = TokenService(keys, settings, revocations, clock)
    with pytest.raises(AuthenticationError, match="invalid token"):
        mine.verify(token)


def test_malformed_token_rejected(tokens: TokenService) -> None:
    with pytest.raises(AuthenticationError, match="malformed"):
        tokens.verify("not-a-jwt")


def test_revoked_token_rejected(alice_token: str, tokens: TokenService) -> None:
    claims = tokens.verify(alice_token)
    tokens.revoke(claims, reason="test")
    with pytest.raises(AuthenticationError, match="revoked"):
        tokens.verify(alice_token)


@pytest.mark.parametrize("subject", ["user:alice", "agent:inbox-assistant"])
def test_subject_revocation_invalidates_existing_tokens_only(
    subject: str,
    alice_token: str,
    tokens: TokenService,
    revocations: RevocationList,
    clock: FakeClock,
    directory: Directory,
    registry: AgentRegistry,
) -> None:
    revocations.revoke_subject(subject, reason="compromised")
    with pytest.raises(AuthenticationError, match="have been revoked"):
        tokens.verify(alice_token)
    clock.advance(1)
    fresh = tokens.issue(
        user=directory.users["alice"],
        agent=registry.require("inbox-assistant"),
        scopes=["email:read"],
    )
    assert tokens.verify(fresh.access_token).user_id == "alice"


# --------------------------------------------------------------------------- delegation
@pytest.fixture
def parent(alice_token: str, tokens: TokenService) -> TokenClaims:
    return tokens.verify(alice_token)


def test_delegation_attenuates_and_nests_act(
    parent: TokenClaims, tokens: TokenService, registry: AgentRegistry
) -> None:
    issued = tokens.delegate(
        parent=parent, sub_agent=registry.require("summarizer"), scopes=["email:read"]
    )
    child = tokens.verify(issued.access_token)
    assert child.actor_chain == ("summarizer", "inbox-assistant")
    assert child.scopes == ("email:read",)
    assert child.depth == 1
    assert child.ancestors == (parent.jti,)
    assert child.task == parent.task
    payload = jwt.decode(issued.access_token, options={"verify_signature": False})
    assert payload["act"] == {"sub": "agent:summarizer", "act": {"sub": "agent:inbox-assistant"}}


def test_delegation_cannot_escalate(
    parent: TokenClaims, tokens: TokenService, registry: AgentRegistry
) -> None:
    with pytest.raises(DelegationError, match="does not hold: docs:read"):
        tokens.delegate(
            parent=parent,
            sub_agent=registry.require("summarizer"),
            scopes=["email:read", "docs:read"],
        )


def test_delegation_drops_scopes_beyond_sub_agent_ceiling(
    parent: TokenClaims, tokens: TokenService, registry: AgentRegistry
) -> None:
    issued = tokens.delegate(
        parent=parent, sub_agent=registry.require("summarizer"), scopes=["email:read", "email:send"]
    )
    assert issued.scope == ["email:read"]
    assert issued.denied_scopes == ["email:send"]


def test_delegation_never_outlives_parent(
    parent: TokenClaims, tokens: TokenService, registry: AgentRegistry
) -> None:
    issued = tokens.delegate(
        parent=parent, sub_agent=registry.require("summarizer"), scopes=["email:read"], ttl=3600
    )
    assert tokens.verify(issued.access_token).expires_at <= parent.expires_at


def test_delegation_cycle_rejected(
    parent: TokenClaims, tokens: TokenService, registry: AgentRegistry
) -> None:
    with pytest.raises(DelegationError, match="cycle"):
        tokens.delegate(
            parent=parent, sub_agent=registry.require("inbox-assistant"), scopes=["email:read"]
        )


def test_multi_hop_delegation_up_to_depth_limit(
    tokens: TokenService, directory: Directory, registry: AgentRegistry, settings: Settings
) -> None:
    assert settings.max_delegation_depth == 2
    root = tokens.verify(
        tokens.issue(
            user=directory.users["alice"],
            agent=registry.require("inbox-assistant"),
            scopes=["docs:read"],
        ).access_token
    )
    hop1 = tokens.verify(
        tokens.delegate(
            parent=root, sub_agent=registry.require("summarizer"), scopes=["docs:read"]
        ).access_token
    )
    hop2 = tokens.verify(
        tokens.delegate(
            parent=hop1, sub_agent=registry.require("research-agent"), scopes=["docs:read"]
        ).access_token
    )
    assert hop2.actor_chain == ("research-agent", "summarizer", "inbox-assistant")
    assert hop2.ancestors == (hop1.jti, root.jti)
    with pytest.raises(DelegationError, match="depth limit"):
        tokens.delegate(
            parent=hop2, sub_agent=registry.require("finance-bot"), scopes=["docs:read"]
        )


def test_depth_limit_enforced(
    keys: KeyManager,
    settings: Settings,
    revocations: RevocationList,
    clock: FakeClock,
    directory: Directory,
    registry: AgentRegistry,
) -> None:
    shallow = TokenService(keys, replace(settings, max_delegation_depth=0), revocations, clock)
    root = shallow.verify(
        shallow.issue(
            user=directory.users["alice"],
            agent=registry.require("inbox-assistant"),
            scopes=["email:read"],
        ).access_token
    )
    with pytest.raises(DelegationError, match="depth limit"):
        shallow.delegate(
            parent=root, sub_agent=registry.require("summarizer"), scopes=["email:read"]
        )


def test_revoking_parent_revokes_children(
    parent: TokenClaims, tokens: TokenService, registry: AgentRegistry
) -> None:
    child_token = tokens.delegate(
        parent=parent, sub_agent=registry.require("summarizer"), scopes=["email:read"]
    ).access_token
    tokens.revoke(parent)
    with pytest.raises(AuthenticationError, match="revoked"):
        tokens.verify(child_token)


def test_structurally_inconsistent_token_rejected(
    tokens: TokenService, keys: KeyManager, alice_token: str
) -> None:
    # Even a correctly signed token must be internally consistent (defense in depth).
    payload = jwt.decode(alice_token, options={"verify_signature": False})
    payload["dep"] = 1
    forged = jwt.encode(payload, keys.private_key, algorithm="EdDSA", headers={"kid": keys.kid})
    with pytest.raises(AuthenticationError, match="depth does not match"):
        tokens.verify(forged)
