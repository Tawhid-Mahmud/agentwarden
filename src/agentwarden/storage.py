"""Persistence for the registry, revocation list, approval queue and audit log.

Two backends share one small interface:

* **SQLite** (default): ``Database("agentwarden.db")`` or ``Database(":memory:")``. One process.
* **PostgreSQL**: ``Database("postgresql://user:pass@host/db")``. Several AgentWarden instances
  can share one database. Requires ``pip install 'agentwarden[postgres]'``.

Callers write SQL with ``?`` placeholders in the common SQLite/PostgreSQL dialect; the Postgres
backend translates placeholders. Writes that must be serialized across instances (appending to
the audit hash chain, creating the schema) take a named lock: ``BEGIN IMMEDIATE`` on SQLite, a
transaction-scoped advisory lock on PostgreSQL.
"""

from __future__ import annotations

import sqlite3
import threading
import zlib
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any, Protocol

from agentwarden.errors import ConfigurationError

_TABLES = """
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
    expires_at {real} NOT NULL,
    revoked_at TEXT NOT NULL,
    reason     TEXT NOT NULL DEFAULT ''
);

-- "Revoke every token for this subject issued at or before not_before".
CREATE TABLE IF NOT EXISTS subject_revocations (
    subject    TEXT PRIMARY KEY,
    not_before {real} NOT NULL,
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
    risk_score   {real} NOT NULL,
    created_at   {real} NOT NULL,
    expires_at   {real} NOT NULL,
    reviewer     TEXT,
    reviewed_at  {real},
    note         TEXT NOT NULL DEFAULT '',
    details      TEXT NOT NULL DEFAULT '{{}}'
);
CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);

-- ID tokens already exchanged (one-time use), kept until they expire anyway.
CREATE TABLE IF NOT EXISTS used_id_tokens (
    token_hash TEXT PRIMARY KEY,
    expires_at {real} NOT NULL
);

-- DPoP proofs already presented (replay protection), kept for their acceptance window.
CREATE TABLE IF NOT EXISTS used_dpop_proofs (
    proof_hash TEXT PRIMARY KEY,
    expires_at {real} NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq        {bigint} PRIMARY KEY,
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

-- How far each SIEM export has delivered the audit chain (the last seq and its hash).
CREATE TABLE IF NOT EXISTS export_cursors (
    name       TEXT PRIMARY KEY,
    seq        {bigint} NOT NULL,
    hash       TEXT NOT NULL,
    updated_at {real} NOT NULL
);
"""

#: Kept for compatibility: the SQLite flavor of the schema.
SCHEMA = _TABLES.format(real="REAL", bigint="INTEGER")
POSTGRES_SCHEMA = _TABLES.format(real="DOUBLE PRECISION", bigint="BIGINT")
TABLES = (
    "agents",
    "revoked_tokens",
    "subject_revocations",
    "approvals",
    "used_id_tokens",
    "used_dpop_proofs",
    "audit_log",
    "export_cursors",
)

#: Columns added after a table first shipped: (table, column, definition). Applied on startup to
#: databases created by older versions; additive only, so it is safe to run repeatedly.
COLUMN_MIGRATIONS = (("approvals", "details", "TEXT NOT NULL DEFAULT '{}'"),)

Row = Mapping[str, Any]


class Cursor(Protocol):
    rowcount: int

    def fetchone(self) -> Any: ...

    def fetchall(self) -> list[Any]: ...


class Transaction(Protocol):
    def execute(self, sql: str, params: Sequence[Any] = ()) -> Cursor: ...


def is_postgres_url(target: str) -> bool:
    return target.startswith(("postgresql://", "postgres://"))


class Database:
    """Storage interface. ``Database(target)`` opens the backend ``target`` points at."""

    dialect: str = "abstract"
    #: Exception raised for unique-key violations by this backend.
    IntegrityError: type[Exception] = Exception

    def __new__(cls, target: str = ":memory:") -> Database:
        if cls is Database:
            backend: type[Database] = (
                PostgresDatabase if is_postgres_url(target) else SQLiteDatabase
            )
            return super().__new__(backend)
        return super().__new__(cls)

    def transaction(self, lock: str | None = None) -> Any:  # pragma: no cover - interface
        raise NotImplementedError

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:  # pragma: no cover
        raise NotImplementedError

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[Any]:  # pragma: no cover
        raise NotImplementedError

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Any:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover
        raise NotImplementedError


class SQLiteDatabase(Database):
    """One SQLite connection behind a re-entrant lock (safe for FastAPI's thread pool)."""

    dialect = "sqlite"
    IntegrityError = sqlite3.IntegrityError

    def __init__(self, target: str = ":memory:") -> None:
        self.path = target
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(target, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA foreign_keys = ON")
            if target != ":memory:":
                self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.execute("PRAGMA synchronous = NORMAL")
            self._conn.executescript(SCHEMA)
            for table, column, definition in COLUMN_MIGRATIONS:
                existing = {
                    row["name"] for row in self._conn.execute(f"PRAGMA table_info({table})")
                }
                if column not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    @contextmanager
    def transaction(self, lock: str | None = None) -> Iterator[sqlite3.Connection]:
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


def _translate(sql: str) -> str:
    """``?`` placeholders to psycopg's ``%s`` (literal ``%`` escaped first)."""
    return sql.replace("%", "%%").replace("?", "%s")


def _lock_id(name: str) -> int:
    return zlib.crc32(f"agentwarden:{name}".encode())


class _PgTransaction:
    def __init__(self, conn: Any) -> None:
        self._conn = conn

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Cursor:
        cursor: Cursor = self._conn.execute(_translate(sql), tuple(params))
        return cursor


class PostgresDatabase(Database):
    """PostgreSQL backend: one connection per AgentWarden process, shared by many processes."""

    dialect = "postgres"

    def __init__(self, target: str) -> None:
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:  # pragma: no cover - depends on installed extras
            raise ConfigurationError(
                "PostgreSQL support needs psycopg: pip install 'agentwarden[postgres]'"
            ) from exc
        self._psycopg = psycopg
        self._row_factory = dict_row
        self.IntegrityError = psycopg.errors.IntegrityError
        self._url = target
        self._lock = threading.RLock()
        try:
            self._conn = self._connect()
        except psycopg.Error as exc:
            raise ConfigurationError(f"could not connect to PostgreSQL: {exc}") from exc
        with self.transaction(lock="schema") as tx:  # instances starting together don't race
            for statement in POSTGRES_SCHEMA.split(";"):
                if statement.strip():
                    tx.execute(statement)
            for table, column, definition in COLUMN_MIGRATIONS:
                tx.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}")

    def _connect(self) -> Any:
        return self._psycopg.connect(self._url, autocommit=True, row_factory=self._row_factory)

    def _ensure(self) -> Any:
        if self._conn.closed or self._conn.broken:
            self._conn = self._connect()
        return self._conn

    @contextmanager
    def transaction(self, lock: str | None = None) -> Iterator[_PgTransaction]:
        with self._lock:
            conn = self._ensure()
            with conn.transaction():
                if lock is not None:
                    conn.execute("SELECT pg_advisory_xact_lock(%s)", (_lock_id(lock),))
                yield _PgTransaction(conn)

    def execute(self, sql: str, params: Sequence[Any] = ()) -> int:
        with self._lock:
            rowcount: int = self._ensure().execute(_translate(sql), tuple(params)).rowcount
            return rowcount

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[Any]:
        with self._lock:
            rows: list[Any] = self._ensure().execute(_translate(sql), tuple(params)).fetchall()
            return rows

    def query_one(self, sql: str, params: Sequence[Any] = ()) -> Any:
        with self._lock:
            return self._ensure().execute(_translate(sql), tuple(params)).fetchone()

    def close(self) -> None:
        with self._lock:
            if not self._conn.closed:
                self._conn.close()
