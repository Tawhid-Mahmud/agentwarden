"""SQLite persistence shared by the registry, revocation list, approval queue and audit log.

A single connection guarded by a re-entrant lock keeps the implementation simple and safe for
FastAPI's thread pool. The storage surface is intentionally small so a Postgres backend can be
added later (roadmap v0.2).
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    owner         TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    scope_ceiling TEXT NOT NULL,
    trust_tier    TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti        TEXT PRIMARY KEY,
    expires_at REAL NOT NULL,
    revoked_at TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT ''
);

-- "Revoke every token for this subject issued at or before not_before".
CREATE TABLE IF NOT EXISTS subject_revocations (
    subject    TEXT PRIMARY KEY,
    not_before REAL NOT NULL,
    reason     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS approvals (
    id           TEXT PRIMARY KEY,
    decision_id  TEXT NOT NULL,
    status       TEXT NOT NULL,
    user_id      TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    tool         TEXT NOT NULL,
    call_hash    TEXT NOT NULL,
    args_preview TEXT NOT NULL,
    reasons      TEXT NOT NULL,
    risk_score   REAL NOT NULL,
    created_at   REAL NOT NULL,
    expires_at   REAL NOT NULL,
    reviewer     TEXT,
    reviewed_at  REAL,
    note         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

CREATE TABLE IF NOT EXISTS audit_log (
    seq        INTEGER PRIMARY KEY,
    ts         TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id    TEXT,
    agent_id   TEXT,
    tool       TEXT,
    decision   TEXT,
    data       TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_agent_ts ON audit_log(agent_id, ts);
"""


class Database:
    """Thread-safe wrapper around one SQLite connection."""

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.execute("PRAGMA synchronous = NORMAL")
            self._conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        """Run statements atomically. ``BEGIN IMMEDIATE`` takes the write lock up front."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        """Execute a write statement and return the number of affected rows."""
        with self._lock:
            return self._conn.execute(sql, params).rowcount

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
        with self._lock:
            row: sqlite3.Row | None = self._conn.execute(sql, params).fetchone()
            return row

    def close(self) -> None:
        with self._lock:
            self._conn.close()
