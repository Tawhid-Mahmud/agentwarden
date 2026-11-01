from __future__ import annotations

import os
import time
from collections.abc import Iterator

import pytest

from agentwarden.config import Settings
from agentwarden.directory import Directory
from agentwarden.identity import AgentRegistry, KeyManager, RevocationList, TokenService
from agentwarden.storage import TABLES, Database


class FakeClock:
    """Deterministic, manually advanced clock."""

    def __init__(self, start: float | None = None) -> None:
        self.now = start if start is not None else time.time()

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def settings() -> Settings:
    return Settings(db_path=":memory:", admin_key="test-admin-key-0123456789")


#: Set to a throwaway PostgreSQL database to run every storage test on Postgres too, e.g.
#: AGENTWARDEN_TEST_DATABASE_URL=postgresql://postgres@127.0.0.1:5432/agentwarden_test
PG_URL = os.environ.get("AGENTWARDEN_TEST_DATABASE_URL")
needs_postgres = pytest.mark.skipif(not PG_URL, reason="AGENTWARDEN_TEST_DATABASE_URL not set")


def fresh_postgres() -> Database:
    """Open the test Postgres database with every table emptied."""
    assert PG_URL
    database = Database(PG_URL)
    database.execute(f"TRUNCATE {', '.join(TABLES)}")
    return database


@pytest.fixture(params=["sqlite", pytest.param("postgres", marks=needs_postgres)])
def db(request: pytest.FixtureRequest) -> Iterator[Database]:
    database = Database(":memory:") if request.param == "sqlite" else fresh_postgres()
    yield database
    database.close()


@pytest.fixture
def directory(settings: Settings) -> Directory:
    return Directory.load(settings.directory_path)


@pytest.fixture
def registry(db: Database, directory: Directory) -> AgentRegistry:
    reg = AgentRegistry(db)
    reg.seed(directory.seed_agents)
    return reg


@pytest.fixture
def keys() -> KeyManager:
    return KeyManager.generate()


@pytest.fixture
def revocations(db: Database, clock: FakeClock) -> RevocationList:
    return RevocationList(db, clock=clock)


@pytest.fixture
def tokens(
    keys: KeyManager, settings: Settings, revocations: RevocationList, clock: FakeClock
) -> TokenService:
    return TokenService(keys, settings, revocations, clock=clock)
