from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from agentwarden.config import Settings
from agentwarden.directory import Directory
from agentwarden.errors import ConfigurationError
from agentwarden.identity import KeyManager
from agentwarden.storage import Database


def test_settings_from_env(tmp_path: Path) -> None:
    env = {
        "AGENTWARDEN_DB_PATH": str(tmp_path / "x.db"),
        "AGENTWARDEN_SIGNING_KEY_PATH": str(tmp_path / "k.pem"),
        "AGENTWARDEN_ISSUER": "https://warden.example",
        "AGENTWARDEN_AUDIENCE": "warden",
        "AGENTWARDEN_DEFAULT_TOKEN_TTL": "300",
        "AGENTWARDEN_MAX_TOKEN_TTL": "600",
        "AGENTWARDEN_MAX_DELEGATION_DEPTH": "1",
        "AGENTWARDEN_APPROVAL_TTL": "120",
        "AGENTWARDEN_ADMIN_KEY": "a" * 32,
        "AGENTWARDEN_LLM_JUDGE": "true",
        "AGENTWARDEN_LLM_JUDGE_MODEL": "claude-opus-5-5",
    }
    s = Settings.from_env(env)
    assert s.db_path.endswith("x.db") and s.signing_key_path == tmp_path / "k.pem"
    assert (s.issuer, s.audience, s.default_token_ttl, s.max_token_ttl) == (
        "https://warden.example",
        "warden",
        300,
        600,
    )
    assert s.max_delegation_depth == 1 and s.approval_ttl == 120 and s.llm_judge_enabled
    assert "a" * 32 not in repr(s)  # the admin key never shows up in logs
    assert Settings.from_env({}).llm_judge_enabled is False


@pytest.mark.parametrize(
    "env",
    [
        {"AGENTWARDEN_DEFAULT_TOKEN_TTL": "abc"},
        {"AGENTWARDEN_DEFAULT_TOKEN_TTL": "10"},
        {"AGENTWARDEN_MAX_TOKEN_TTL": "100000", "AGENTWARDEN_DEFAULT_TOKEN_TTL": "60"},
        {"AGENTWARDEN_MAX_DELEGATION_DEPTH": "9"},
        {"AGENTWARDEN_APPROVAL_TTL": "5"},
        {"AGENTWARDEN_ADMIN_KEY": "short"},
    ],
)
def test_invalid_settings_rejected(env: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        Settings.from_env(env)


def test_key_round_trip_and_validation(tmp_path: Path) -> None:
    keys = KeyManager.generate()
    path = keys.save_pem(tmp_path / "k.pem")
    loaded = KeyManager.load_or_generate(path)
    assert loaded.kid == keys.kid
    assert loaded.verify(keys.sign(b"msg"), b"msg") and not loaded.verify(b"x" * 64, b"msg")
    with pytest.raises(FileExistsError):
        keys.save_pem(path)
    with pytest.raises(ConfigurationError, match="not found"):
        KeyManager.from_pem_file(tmp_path / "missing.pem")
    (tmp_path / "junk.pem").write_text("not a key")
    (tmp_path / "junk.pem").chmod(0o600)
    with pytest.raises(ConfigurationError, match="could not parse"):
        KeyManager.from_pem_file(tmp_path / "junk.pem")
    ec_pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    (tmp_path / "ec.pem").write_bytes(ec_pem)
    (tmp_path / "ec.pem").chmod(0o600)
    with pytest.raises(ConfigurationError, match="Ed25519"):
        KeyManager.from_pem_file(tmp_path / "ec.pem")


@pytest.mark.skipif(os.name != "posix", reason="POSIX permissions")
def test_world_readable_key_warns(tmp_path: Path) -> None:
    path = KeyManager.generate().save_pem(tmp_path / "k.pem")
    path.chmod(0o644)
    with pytest.warns(UserWarning, match="chmod 600"):
        KeyManager.from_pem_file(path)


def test_directory_validation(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="not found"):
        Directory.load(tmp_path / "missing.yaml")
    (tmp_path / "bad.yaml").write_text("users: [unclosed")
    with pytest.raises(ConfigurationError, match="not valid YAML"):
        Directory.load(tmp_path / "bad.yaml")
    with pytest.raises(ConfigurationError, match="duplicate user"):
        Directory.from_dict({"users": [{"id": "a"}, {"id": "a"}]})
    with pytest.raises(ConfigurationError, match="duplicate tool"):
        Directory.from_dict(
            {"tools": [{"name": "t", "scope": "a:b"}, {"name": "t", "scope": "a:b"}]}
        )
    with pytest.raises(ConfigurationError, match="invalid directory"):
        Directory.from_dict({"tools": [{"name": "Bad Name", "scope": "a:b"}]})
    d = Directory.from_dict({"organization": {"trusted_domains": [" .Acme.Example "]}})
    assert d.trusted_domains == ["acme.example"]
    assert d.is_trusted_domain("mail.acme.example") and not d.is_trusted_domain("acme.example.evil")
    assert d.authenticate_api_key("") is None


def test_file_backed_database(tmp_path: Path) -> None:
    db = Database(str(tmp_path / "aw.db"))
    with pytest.raises(RuntimeError), db.transaction() as conn:
        conn.execute(
            "INSERT INTO revoked_tokens (jti, expires_at, revoked_at) VALUES ('a', 1, 'now')"
        )
        raise RuntimeError("roll back")
    assert db.query("SELECT * FROM revoked_tokens") == []  # transaction rolled back
    db.close()
