from __future__ import annotations

import time
from collections.abc import Iterator

import pytest

from agentwarden.config import Settings
from agentwarden.directory import Directory
from agentwarden.identity import AgentRegistry, KeyManager, RevocationList, TokenService
from agentwarden.storage import Database


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


@pytest.fixture
def db() -> Iterator[Database]:
    database = Database(":memory:")
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
