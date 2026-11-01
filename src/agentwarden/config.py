"""Runtime settings, loaded from environment variables with safe defaults."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from agentwarden.errors import ConfigurationError

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_POLICY_PATH = DATA_DIR / "policy.yaml"
DEFAULT_DIRECTORY_PATH = DATA_DIR / "directory.yaml"
DEFAULT_LLM_JUDGE_MODEL = "claude-opus-5-5"

_TRUE = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """AgentWarden configuration.

    Every field can be overridden with an ``AGENTWARDEN_<FIELD>`` environment variable; see
    :meth:`from_env`. Defaults are tuned for local development and the bundled demo.
    """

    db_path: str = "agentwarden.db"
    policy_path: Path = DEFAULT_POLICY_PATH
    directory_path: Path = DEFAULT_DIRECTORY_PATH
    #: PEM-encoded Ed25519 private key. ``None`` means an ephemeral in-memory key
    #: (fine for tests and demos, but tokens die with the process).
    signing_key_path: Path | None = None
    issuer: str = "https://agentwarden.local"
    audience: str = "agentwarden"
    default_token_ttl: int = 900
    max_token_ttl: int = 3600
    max_delegation_depth: int = 2
    approval_ttl: int = 900
    clock_skew_seconds: int = 30
    #: Shared secret for the admin API. ``None`` disables admin endpoints entirely.
    admin_key: str | None = field(default=None, repr=False)
    llm_judge_enabled: bool = False
    llm_judge_model: str = DEFAULT_LLM_JUDGE_MODEL

    def __post_init__(self) -> None:
        if not 30 <= self.default_token_ttl <= self.max_token_ttl:
            raise ConfigurationError("default_token_ttl must be between 30s and max_token_ttl")
        if self.max_token_ttl > 86_400:
            raise ConfigurationError("max_token_ttl may not exceed 24h for agent credentials")
        if not 0 <= self.max_delegation_depth <= 5:
            raise ConfigurationError("max_delegation_depth must be between 0 and 5")
        if self.approval_ttl < 30:
            raise ConfigurationError("approval_ttl must be at least 30 seconds")
        if self.admin_key is not None and len(self.admin_key) < 16:
            raise ConfigurationError("admin_key must be at least 16 characters")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env

        def get(name: str) -> str | None:
            value = env.get(f"AGENTWARDEN_{name}")
            return value if value not in (None, "") else None

        def get_int(name: str, default: int) -> int:
            raw = get(name)
            if raw is None:
                return default
            try:
                return int(raw)
            except ValueError as exc:
                raise ConfigurationError(f"AGENTWARDEN_{name} must be an integer") from exc

        base = cls()
        key_path = get("SIGNING_KEY_PATH")
        return replace(
            base,
            db_path=get("DB_PATH") or base.db_path,
            policy_path=Path(get("POLICY_PATH") or base.policy_path),
            directory_path=Path(get("DIRECTORY_PATH") or base.directory_path),
            signing_key_path=Path(key_path) if key_path else None,
            issuer=get("ISSUER") or base.issuer,
            audience=get("AUDIENCE") or base.audience,
            default_token_ttl=get_int("DEFAULT_TOKEN_TTL", base.default_token_ttl),
            max_token_ttl=get_int("MAX_TOKEN_TTL", base.max_token_ttl),
            max_delegation_depth=get_int("MAX_DELEGATION_DEPTH", base.max_delegation_depth),
            approval_ttl=get_int("APPROVAL_TTL", base.approval_ttl),
            clock_skew_seconds=get_int("CLOCK_SKEW_SECONDS", base.clock_skew_seconds),
            admin_key=get("ADMIN_KEY"),
            llm_judge_enabled=(get("LLM_JUDGE") or "").lower() in _TRUE,
            llm_judge_model=get("LLM_JUDGE_MODEL") or base.llm_judge_model,
        )
