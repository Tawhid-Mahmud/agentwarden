"""Runtime settings, loaded from environment variables with safe defaults."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path

from agentwarden.errors import ConfigurationError

DATA_DIR = Path(__file__).parent / "data"
DEFAULT_POLICY_PATH = DATA_DIR / "policy.yaml"
DEFAULT_CEDAR_POLICY_PATH = DATA_DIR / "policy.cedar"
DEFAULT_DIRECTORY_PATH = DATA_DIR / "directory.yaml"
DEFAULT_CORPUS_PATH = DATA_DIR / "injection_corpus.yaml"
DEFAULT_LLM_JUDGE_MODEL = "claude-opus-5-5"

_TRUE = {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """AgentWarden configuration.

    Every field can be overridden with an ``AGENTWARDEN_<FIELD>`` environment variable; see
    :meth:`from_env`. Defaults are tuned for local development and the bundled demo.
    """

    db_path: str = "agentwarden.db"
    #: PostgreSQL URL (postgresql://user:pass@host/db). Takes precedence over ``db_path`` and
    #: lets several AgentWarden instances share state.
    database_url: str | None = field(default=None, repr=False)
    policy_path: Path = DEFAULT_POLICY_PATH
    directory_path: Path = DEFAULT_DIRECTORY_PATH
    #: PEM-encoded Ed25519 private key. ``None`` means an ephemeral in-memory key
    #: (fine for tests and demos, but tokens die with the process).
    signing_key_path: Path | None = None
    #: Directory holding a rotating key ring (see ``agentwarden keys``). Preferred over
    #: ``signing_key_path``; created with a first key if empty.
    signing_key_dir: Path | None = None
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
    #: OpenID Connect issuer URL (e.g. https://accounts.google.com). Enables token exchange.
    oidc_issuer: str | None = None
    #: The OAuth client id AgentWarden is registered under at the IdP (the ID token audience).
    oidc_audience: str | None = None
    #: Override the JWKS URL instead of discovering it from the issuer.
    oidc_jwks_url: str | None = None
    #: How IdP identities map to directory users: "email" (verified email) or "sub".
    oidc_user_claim: str = "email"
    #: Demo-grade X-API-Key user authentication. Turn off once OIDC is configured.
    api_keys_enabled: bool = True
    #: Each ID token can be exchanged once (replays are refused across instances).
    oidc_one_time_tokens: bool = True
    #: Requests per minute per client IP to the API (0 disables).
    rate_limit_per_ip: int = 600
    #: Requests per minute per client IP to sign-in and token endpoints (0 disables).
    rate_limit_sensitive_per_ip: int = 30
    #: Failed authentications per minute per client IP before it is locked out (0 disables).
    rate_limit_auth_failures_per_ip: int = 20
    #: Authorization calls per minute per agent (0 disables).
    rate_limit_per_agent: int = 300
    #: Use the first X-Forwarded-For address as the client IP. Only behind a trusted proxy.
    trust_proxy_headers: bool = False
    #: Lifetime of authorization receipts handed to tools.
    receipt_ttl: int = 60
    #: Require every agent token to be DPoP-bound (RFC 9449). Off: binding is per token.
    dpop_required: bool = False
    #: How long a DPoP proof is accepted after its ``iat``.
    dpop_max_age: int = 60
    #: Public base URL clients use (e.g. https://warden.example.com). DPoP proofs name the URL
    #: they were made for; behind a proxy, set this so AgentWarden checks the external URL.
    public_url: str | None = None
    #: Export OpenTelemetry traces and metrics over OTLP/HTTP from ``agentwarden serve``
    #: (endpoint from OTEL_EXPORTER_OTLP_ENDPOINT; needs ``agentwarden[otel]``).
    otel_enabled: bool = False
    #: Policy backend: ``yaml`` (built in), ``cedar`` (in-process, needs ``agentwarden[cedar]``)
    #: or ``opa`` (an OPA server, usually a sidecar). See docs/POLICY_BACKENDS.md.
    policy_backend: str = "yaml"
    #: OPA base URL (e.g. http://localhost:8181) and the path of the decision rule.
    opa_url: str | None = None
    opa_path: str = "agentwarden/authz/decision"
    #: Bearer token for OPA's API, if OPA requires authentication.
    opa_token: str | None = None
    #: Seconds to wait for OPA before failing closed (deny).
    opa_timeout: float = 2.0

    @property
    def effective_policy_path(self) -> Path:
        """The policy file for file-based backends: Cedar uses the bundled ``policy.cedar``
        unless a policy path was configured explicitly."""
        if self.policy_backend == "cedar" and self.policy_path == DEFAULT_POLICY_PATH:
            return DEFAULT_CEDAR_POLICY_PATH
        return self.policy_path

    def __post_init__(self) -> None:
        if self.policy_backend not in ("yaml", "cedar", "opa"):
            raise ConfigurationError("policy_backend must be yaml, cedar or opa")
        if self.policy_backend == "opa" and not self.opa_url:
            raise ConfigurationError("the OPA policy backend needs opa_url (AGENTWARDEN_OPA_URL)")
        if self.opa_url and not self.opa_url.startswith(("http://", "https://")):
            raise ConfigurationError("opa_url must be an http(s) URL")
        if not 0.1 <= self.opa_timeout <= 30:
            raise ConfigurationError("opa_timeout must be between 0.1 and 30 seconds")
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
        if self.database_url and not self.database_url.startswith(("postgresql://", "postgres://")):
            raise ConfigurationError("database_url must be a postgresql:// URL")
        if self.signing_key_path and self.signing_key_dir:
            raise ConfigurationError("set either signing_key_path or signing_key_dir, not both")
        if self.oidc_issuer and not self.oidc_audience:
            raise ConfigurationError("oidc_audience (the client id) is required with oidc_issuer")
        if self.oidc_user_claim not in ("email", "sub"):
            raise ConfigurationError("oidc_user_claim must be 'email' or 'sub'")
        for name in (
            "rate_limit_per_ip",
            "rate_limit_sensitive_per_ip",
            "rate_limit_auth_failures_per_ip",
            "rate_limit_per_agent",
        ):
            if getattr(self, name) < 0:
                raise ConfigurationError(f"{name} can't be negative (0 disables it)")
        if not 10 <= self.dpop_max_age <= 600:
            raise ConfigurationError("dpop_max_age must be between 10 and 600 seconds")
        if self.public_url and not self.public_url.startswith(("https://", "http://")):
            raise ConfigurationError("public_url must be an http(s) URL")
        if not 5 <= self.receipt_ttl <= 600:
            raise ConfigurationError("receipt_ttl must be between 5 and 600 seconds")
        if not self.api_keys_enabled and not self.oidc_issuer:
            raise ConfigurationError("disabling API keys requires OIDC, or no user could sign in")

    @property
    def database(self) -> str:
        """What to open: the PostgreSQL URL if set, otherwise the SQLite path."""
        return self.database_url or self.db_path

    @property
    def key_grace_seconds(self) -> int:
        """How long a retired key keeps verifying tokens: the longest lifetime plus skew."""
        return self.max_token_ttl + self.clock_skew_seconds

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
        key_dir = get("SIGNING_KEY_DIR")
        return replace(
            base,
            db_path=get("DB_PATH") or base.db_path,
            database_url=get("DATABASE_URL"),
            policy_path=Path(get("POLICY_PATH") or base.policy_path),
            directory_path=Path(get("DIRECTORY_PATH") or base.directory_path),
            signing_key_path=Path(key_path) if key_path else None,
            signing_key_dir=Path(key_dir) if key_dir else None,
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
            oidc_issuer=get("OIDC_ISSUER"),
            oidc_audience=get("OIDC_AUDIENCE"),
            oidc_jwks_url=get("OIDC_JWKS_URL"),
            oidc_user_claim=get("OIDC_USER_CLAIM") or base.oidc_user_claim,
            api_keys_enabled=(get("API_KEYS") or "true").lower() in _TRUE,
            oidc_one_time_tokens=(get("OIDC_ONE_TIME_TOKENS") or "true").lower() in _TRUE,
            rate_limit_per_ip=get_int("RATE_LIMIT_PER_IP", base.rate_limit_per_ip),
            rate_limit_sensitive_per_ip=get_int(
                "RATE_LIMIT_SENSITIVE_PER_IP", base.rate_limit_sensitive_per_ip
            ),
            rate_limit_auth_failures_per_ip=get_int(
                "RATE_LIMIT_AUTH_FAILURES_PER_IP", base.rate_limit_auth_failures_per_ip
            ),
            rate_limit_per_agent=get_int("RATE_LIMIT_PER_AGENT", base.rate_limit_per_agent),
            trust_proxy_headers=(get("TRUST_PROXY_HEADERS") or "").lower() in _TRUE,
            receipt_ttl=get_int("RECEIPT_TTL", base.receipt_ttl),
            dpop_required=(get("DPOP_REQUIRED") or "").lower() in _TRUE,
            dpop_max_age=get_int("DPOP_MAX_AGE", base.dpop_max_age),
            public_url=(get("PUBLIC_URL") or "").rstrip("/") or None,
            otel_enabled=(get("OTEL") or "").lower() in _TRUE,
            policy_backend=(get("POLICY_BACKEND") or base.policy_backend).lower(),
            opa_url=(get("OPA_URL") or "").rstrip("/") or None,
            opa_path=get("OPA_PATH") or base.opa_path,
            opa_token=get("OPA_TOKEN") or None,
            opa_timeout=float(get("OPA_TIMEOUT") or base.opa_timeout),
        )
