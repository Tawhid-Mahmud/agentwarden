"""The directory: users, tools, seed agents and organization settings, loaded from YAML."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator

from agentwarden.errors import ConfigurationError
from agentwarden.models import Agent, Tool, User


class Organization(BaseModel):
    name: str = "Example Org"
    trusted_domains: list[str] = Field(default_factory=list)

    @field_validator("trusted_domains")
    @classmethod
    def _normalize(cls, domains: list[str]) -> list[str]:
        return sorted({d.strip().lower().lstrip(".") for d in domains if d.strip()})


class DirectoryDocument(BaseModel):
    organization: Organization = Field(default_factory=Organization)
    users: list[User] = Field(default_factory=list)
    tools: list[Tool] = Field(default_factory=list)
    agents: list[Agent] = Field(default_factory=list)


def hash_api_key(key: str) -> str:
    """Hash an API key for storage. Keys are high-entropy, so a fast hash is sufficient."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


class Directory:
    """In-memory, read-only view of the directory document."""

    def __init__(self, document: DirectoryDocument) -> None:
        self.organization = document.organization
        self.users: dict[str, User] = {}
        self.tools: dict[str, Tool] = {}
        for user in document.users:
            if user.id in self.users:
                raise ConfigurationError(f"duplicate user id {user.id!r}")
            self.users[user.id] = user
        for tool in document.tools:
            if tool.name in self.tools:
                raise ConfigurationError(f"duplicate tool {tool.name!r}")
            self.tools[tool.name] = tool
        self.seed_agents = list(document.agents)

    @classmethod
    def load(cls, path: str | Path) -> Directory:
        try:
            raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise ConfigurationError(f"directory file not found: {path}") from exc
        except yaml.YAMLError as exc:
            raise ConfigurationError(f"directory file is not valid YAML: {exc}") from exc
        return cls.from_dict(raw or {})

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Directory:
        try:
            return cls(DirectoryDocument.model_validate(raw))
        except ValidationError as exc:
            raise ConfigurationError(f"invalid directory: {exc}") from exc

    @property
    def trusted_domains(self) -> list[str]:
        return self.organization.trusted_domains

    def is_trusted_domain(self, domain: str) -> bool:
        domain = domain.lower().rstrip(".")
        return any(domain == d or domain.endswith("." + d) for d in self.trusted_domains)

    def get_user(self, user_id: str) -> User | None:
        return self.users.get(user_id)

    def get_tool(self, name: str) -> Tool | None:
        return self.tools.get(name)

    def find_by_identity(self, *, claim: str, value: str | None) -> User | None:
        """Find the user an IdP identity belongs to (``claim`` is "email" or "sub")."""
        if not value:
            return None
        for user in self.users.values():
            if claim == "email" and user.email and user.email.lower() == value.lower():
                return user
            if claim == "sub" and user.oidc_subject == value:
                return user
        return None

    def authenticate_api_key(self, key: str) -> User | None:
        """Return the user owning ``key``. Compares every hash in constant time."""
        if not key:
            return None
        candidate = hash_api_key(key)
        match: User | None = None
        for user in self.users.values():
            if user.api_key_sha256 and hmac.compare_digest(candidate, user.api_key_sha256):
                match = user
        return match
