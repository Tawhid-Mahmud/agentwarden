"""Agent registry and token revocation list (both persisted in SQLite)."""

from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Callable, Iterable
from datetime import UTC, datetime

from agentwarden.errors import InvalidRequestError, NotFoundError
from agentwarden.identity.scopes import dedupe, validate_scope
from agentwarden.models import Agent, TrustTier
from agentwarden.storage import Database


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _row_to_agent(row: sqlite3.Row) -> Agent:
    return Agent(
        id=row["id"],
        name=row["name"],
        owner=row["owner"],
        description=row["description"],
        scope_ceiling=json.loads(row["scope_ceiling"]),
        trust_tier=TrustTier(row["trust_tier"]),
        enabled=bool(row["enabled"]),
        created_at=datetime.fromisoformat(row["created_at"]),
    )


class AgentRegistry:
    """CRUD for agent identities. Disabling an agent is the kill switch."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def register(self, agent: Agent) -> Agent:
        ceiling = dedupe(validate_scope(s) for s in agent.scope_ceiling)
        now = _now_iso()
        try:
            self._db.execute(
                "INSERT INTO agents (id, name, owner, description, scope_ceiling, trust_tier,"
                " enabled, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    agent.id,
                    agent.name,
                    agent.owner,
                    agent.description,
                    json.dumps(ceiling),
                    agent.trust_tier.value,
                    int(agent.enabled),
                    now,
                    now,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise InvalidRequestError(f"agent {agent.id!r} already exists") from exc
        return self.require(agent.id)

    def seed(self, agents: Iterable[Agent]) -> int:
        """Register agents that do not exist yet. Returns how many were created."""
        created = 0
        for agent in agents:
            if self.get(agent.id) is None:
                self.register(agent)
                created += 1
        return created

    def get(self, agent_id: str) -> Agent | None:
        row = self._db.query_one("SELECT * FROM agents WHERE id = ?", (agent_id,))
        return _row_to_agent(row) if row else None

    def require(self, agent_id: str) -> Agent:
        agent = self.get(agent_id)
        if agent is None:
            raise NotFoundError(f"unknown agent {agent_id!r}")
        return agent

    def list(self) -> list[Agent]:
        return [_row_to_agent(r) for r in self._db.query("SELECT * FROM agents ORDER BY id")]

    def set_enabled(self, agent_id: str, enabled: bool) -> Agent:
        changed = self._db.execute(
            "UPDATE agents SET enabled = ?, updated_at = ? WHERE id = ?",
            (int(enabled), _now_iso(), agent_id),
        )
        if not changed:
            raise NotFoundError(f"unknown agent {agent_id!r}")
        return self.require(agent_id)

    def set_scope_ceiling(self, agent_id: str, scopes: Iterable[str]) -> Agent:
        ceiling = dedupe(validate_scope(s) for s in scopes)
        if not ceiling:
            raise InvalidRequestError("scope ceiling cannot be empty; disable the agent instead")
        changed = self._db.execute(
            "UPDATE agents SET scope_ceiling = ?, updated_at = ? WHERE id = ?",
            (json.dumps(ceiling), _now_iso(), agent_id),
        )
        if not changed:
            raise NotFoundError(f"unknown agent {agent_id!r}")
        return self.require(agent_id)


class RevocationList:
    """Revocation by token id (``jti``) and by subject ("all tokens issued before T")."""

    def __init__(self, db: Database, clock: Callable[[], float] = time.time) -> None:
        self._db = db
        self._clock = clock

    def revoke_token(self, jti: str, expires_at: float, reason: str = "") -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO revoked_tokens (jti, expires_at, revoked_at, reason)"
            " VALUES (?, ?, ?, ?)",
            (jti, expires_at, _now_iso(), reason),
        )

    def any_revoked(self, jtis: Iterable[str]) -> bool:
        """True if any of ``jtis`` is revoked. Chains are short (<= depth limit + 1)."""
        return any(
            self._db.query_one("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)) is not None
            for jti in jtis
        )

    def revoke_subject(self, subject: str, reason: str = "") -> float:
        """Invalidate every token for ``subject`` (``user:x`` or ``agent:y``) issued until now."""
        cutoff = self._clock()
        self._db.execute(
            "INSERT INTO subject_revocations (subject, not_before, reason) VALUES (?, ?, ?)"
            " ON CONFLICT(subject) DO UPDATE SET not_before = excluded.not_before,"
            " reason = excluded.reason",
            (subject, cutoff, reason),
        )
        return cutoff

    def subject_cutoff(self, subject: str) -> float | None:
        row = self._db.query_one(
            "SELECT not_before FROM subject_revocations WHERE subject = ?", (subject,)
        )
        return float(row["not_before"]) if row else None

    def purge_expired(self) -> int:
        """Drop revocation entries for tokens that have expired anyway."""
        return self._db.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (self._clock(),))
