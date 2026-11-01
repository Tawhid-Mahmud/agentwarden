"""Signing-key rotation: key ring lifecycle, zero-downtime verification, API and CLI."""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentwarden.api import create_app
from agentwarden.audit import AuditLog
from agentwarden.cli import main
from agentwarden.config import Settings
from agentwarden.directory import Directory
from agentwarden.errors import AuthenticationError, ConfigurationError
from agentwarden.gateway import Gateway
from agentwarden.identity import AgentRegistry, KeyRing, RevocationList, TokenService
from agentwarden.models import IssuedToken, TokenRequest
from agentwarden.storage import Database
from tests.conftest import FakeClock

GRACE = 3600 + 30


@pytest.fixture
def ring(tmp_path: Path, clock: FakeClock) -> KeyRing:
    return KeyRing.open(tmp_path / "keys", grace_seconds=GRACE, clock=clock, reload_interval=0)


def manifest(ring: KeyRing) -> list[dict[str, object]]:
    return list(json.loads((ring.directory / "keyring.json").read_text())["keys"])


def test_open_creates_a_first_key(ring: KeyRing) -> None:
    [entry] = ring.entries()
    assert entry.status == "active" and entry.kid == ring.kid
    pem = ring.directory / f"{ring.kid}.pem"
    assert pem.stat().st_mode & 0o777 == 0o600
    assert [k["kid"] for k in ring.jwks()["keys"]] == [ring.kid]


def test_rotation_keeps_live_tokens_valid(
    ring: KeyRing,
    settings: Settings,
    db: Database,
    directory: Directory,
    registry: AgentRegistry,
    clock: FakeClock,
) -> None:
    tokens = TokenService(ring, settings, RevocationList(db, clock), clock=clock)

    def issue() -> IssuedToken:
        return tokens.issue(
            user=directory.users["alice"],
            agent=registry.require("inbox-assistant"),
            scopes=["email:read"],
        )

    old_kid, before = ring.kid, issue()
    new = ring.rotate()
    after = issue()
    assert new.kid != old_kid and ring.kid == new.kid
    assert (
        before.access_token.split(".")[0] != after.access_token.split(".")[0]
    )  # different kid header
    assert tokens.verify(before.access_token).jti == before.jti  # old key still verifies
    assert tokens.verify(after.access_token).jti == after.jti
    assert {k["kid"] for k in ring.jwks()["keys"]} == {old_kid, new.kid}
    assert [e.status for e in ring.entries()] == ["retired", "active"]

    clock.advance(GRACE + 1)  # grace over: the old key is out of the JWKS and verifies nothing
    assert ring.verification_key(old_kid) is None
    assert [k["kid"] for k in ring.jwks()["keys"]] == [new.kid]
    with pytest.raises(AuthenticationError):
        tokens.verify(before.access_token)


def test_prune_deletes_private_keys_but_keeps_checkpoints_verifiable(
    ring: KeyRing, db: Database, clock: FakeClock
) -> None:
    audit = AuditLog(db, keys=ring, clock=clock)
    audit.append("test.event")
    old_kid, checkpoint = ring.kid, audit.checkpoint()
    ring.rotate()
    assert ring.prune() == []  # still inside the grace period
    clock.advance(GRACE)
    assert ring.prune() == [old_kid]
    assert not (ring.directory / f"{old_kid}.pem").exists()
    assert [e.status for e in ring.entries()] == ["pruned", "active"]
    assert ring.verification_key(old_kid) is None
    assert ring.any_public_key(old_kid) is not None
    assert audit.verify_checkpoint(checkpoint)  # signed by a pruned key, still provable
    assert ring.prune() == []


def test_other_processes_pick_up_a_rotation(ring: KeyRing, clock: FakeClock) -> None:
    other = KeyRing.open(ring.directory, grace_seconds=GRACE, clock=clock, reload_interval=60)
    original = other.kid
    rotated = ring.rotate()
    os.utime(ring.directory / "keyring.json", (clock.now + 5, clock.now + 5))
    # An unknown kid forces a reload even inside the reload interval.
    assert other.verification_key(rotated.kid) is not None
    assert other.kid == rotated.kid != original


@pytest.mark.parametrize(
    "damage", ["corrupt", "two_active", "missing_pem", "wrong_pem", "no_active"]
)
def test_damaged_rings_are_rejected(ring: KeyRing, clock: FakeClock, damage: str) -> None:
    ring.rotate()
    path = ring.directory / "keyring.json"
    keys = manifest(ring)
    if damage == "corrupt":
        path.write_text("{not json")
    elif damage == "two_active":
        keys[0]["status"] = "active"
        path.write_text(json.dumps({"keys": keys}))
    elif damage == "missing_pem":
        (ring.directory / f"{ring.kid}.pem").unlink()
    elif damage == "wrong_pem":
        first, second = (ring.directory / f"{k['kid']}.pem" for k in keys)
        first_bytes = first.read_bytes()
        first.write_bytes(second.read_bytes())
        second.write_bytes(first_bytes)
    else:
        keys[1]["status"] = "retired"
        path.write_text(json.dumps({"keys": keys}))
    with pytest.raises(ConfigurationError):
        KeyRing.open(ring.directory, grace_seconds=GRACE, clock=clock)


def test_open_without_create(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="no key ring"):
        KeyRing.open(tmp_path / "empty", grace_seconds=GRACE, create=False)


# ------------------------------------------------------------------------------ gateway & API
@pytest.fixture
def gw(settings: Settings, tmp_path: Path, clock: FakeClock) -> Iterator[Gateway]:
    with Gateway.build(
        replace(settings, signing_key_dir=tmp_path / "ring"), clock=clock
    ) as gateway:
        yield gateway


def test_rotation_over_the_admin_api(gw: Gateway, settings: Settings) -> None:
    client = TestClient(create_app(gw))
    admin = {"X-Admin-Key": str(settings.admin_key)}
    token = gw.issue_token(
        gw.directory.users["alice"], TokenRequest(agent_id="inbox-assistant", scopes=["email:read"])
    ).access_token
    old_kid = client.get("/v1/admin/keys", headers=admin).json()[0]["kid"]
    rotated = client.post("/v1/admin/keys/rotate", headers=admin).json()
    assert [k["status"] for k in rotated] == ["retired", "active"]
    assert rotated[0]["kid"] == old_kid and rotated[0]["verifies_tokens_until"]
    assert len(client.get("/.well-known/jwks.json").json()["keys"]) == 2
    response = client.post(
        "/v1/authorize", headers={"Authorization": f"Bearer {token}"}, json={"tool": "read_inbox"}
    )
    assert response.json()["decision"] == "allow"  # issued before the rotation, still accepted
    assert client.post("/v1/admin/keys/prune", headers=admin).json() == {"pruned": []}
    assert client.post("/v1/admin/keys/rotate").status_code == 401
    assert gw.audit.query(event_type="keys.rotated")[0].data["retired_kid"] == old_kid


def test_rotation_needs_a_ring(settings: Settings, clock: FakeClock) -> None:
    with Gateway.build(settings, clock=clock) as gateway:
        client = TestClient(create_app(gateway))
        admin = {"X-Admin-Key": str(settings.admin_key)}
        assert client.get("/v1/admin/keys", headers=admin).json()[0]["rotatable"] is False
        response = client.post("/v1/admin/keys/rotate", headers=admin)
        assert response.status_code == 400 and "SIGNING_KEY_DIR" in response.json()["detail"]


def test_settings_for_key_ring(tmp_path: Path) -> None:
    s = Settings.from_env({"AGENTWARDEN_SIGNING_KEY_DIR": str(tmp_path)})
    assert (
        s.signing_key_dir == tmp_path
        and s.key_grace_seconds == s.max_token_ttl + s.clock_skew_seconds
    )
    with pytest.raises(ConfigurationError, match="not both"):
        Settings(signing_key_path=tmp_path / "k.pem", signing_key_dir=tmp_path)


# ------------------------------------------------------------------------------ CLI
def test_keys_cli(
    capsys: pytest.CaptureFixture[str], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    directory = str(tmp_path / "cli-ring")
    assert main(["keys", "rotate", "--dir", directory]) == 0
    assert main(["keys", "rotate", "--dir", directory]) == 0
    out = capsys.readouterr().out
    assert "active key is now" in out and "retired" in out and "verifies tokens for" in out
    assert main(["keys", "prune", "--dir", directory]) == 0
    assert "pruned 0 key(s)" in capsys.readouterr().out
    monkeypatch.setenv("AGENTWARDEN_SIGNING_KEY_DIR", directory)
    assert main(["keys", "list"]) == 0
    assert capsys.readouterr().out.count("\n") == 2
    monkeypatch.delenv("AGENTWARDEN_SIGNING_KEY_DIR")
    assert main(["keys", "list"]) == 2
    assert "AGENTWARDEN_SIGNING_KEY_DIR" in capsys.readouterr().err
    assert main(["keys", "list", "--dir", str(tmp_path / "nothing-here")]) == 2
