"""Multi-instance behavior on PostgreSQL: several AgentWarden processes sharing one database.

Skipped unless AGENTWARDEN_TEST_DATABASE_URL points at a throwaway database.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest

from agentwarden.approvals import ApprovalQueue
from agentwarden.audit import AuditLog
from agentwarden.cli import main
from agentwarden.config import Settings
from agentwarden.errors import AuthenticationError, ConfigurationError
from agentwarden.gateway import Gateway
from agentwarden.models import AuthorizeRequest, Decision, TokenRequest
from agentwarden.storage import Database, PostgresDatabase
from tests.conftest import PG_URL, FakeClock, fresh_postgres, needs_postgres

pytestmark = needs_postgres


@pytest.fixture
def two_instances(
    settings: Settings, tmp_path: Path, clock: FakeClock
) -> Iterator[tuple[Gateway, Gateway]]:
    fresh_postgres().close()
    shared = replace(settings, database_url=PG_URL, signing_key_dir=tmp_path / "ring")
    with Gateway.build(shared, clock=clock) as a, Gateway.build(shared, clock=clock) as b:
        yield a, b


def test_backend_selection() -> None:
    db = Database(str(PG_URL))
    assert isinstance(db, PostgresDatabase) and db.dialect == "postgres"
    db.close()


def test_concurrent_audit_appends_keep_one_chain() -> None:
    """Two instances, four threads each, appending at once: the hash chain must not fork."""
    fresh_postgres().close()
    instances = [Database(str(PG_URL)), Database(str(PG_URL))]
    logs = [AuditLog(db) for db in instances]
    errors: list[BaseException] = []

    def writer(log: AuditLog, n: int) -> None:
        try:
            for i in range(25):
                log.append("load.test", data={"writer": n, "i": i})
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(logs[n % 2], n)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    result = logs[0].verify()
    assert result.ok and result.checked == 200
    for db in instances:
        db.close()


def test_an_approval_is_consumed_once_across_instances(
    clock: FakeClock, settings: Settings
) -> None:
    fresh_postgres().close()
    dbs = [Database(str(PG_URL)) for _ in range(2)]
    queues = [ApprovalQueue(db, clock=clock) for db in dbs]
    call = {
        "user_id": "alice",
        "actor_chain": ["inbox-assistant"],
        "tool": "send_email",
        "args": {"to": ["p@x.example"]},
    }
    request = queues[0].create(decision_id="d", reasons=[], risk_score=0.3, **call)  # type: ignore[arg-type]
    from agentwarden.directory import Directory

    queues[1].approve(request.id, Directory.load(settings.directory_path).users["bob"])
    outcomes: list[str] = []
    lock = threading.Lock()

    def consume(queue: ApprovalQueue) -> None:
        outcome = queue.check(request.id, **call).outcome  # type: ignore[arg-type]
        with lock:
            outcomes.append(outcome)

    threads = [threading.Thread(target=consume, args=(queues[n % 2],)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert outcomes.count("consumed") == 1 and outcomes.count("used") == 7
    for db in dbs:
        db.close()


def test_instances_share_identity_state(
    two_instances: tuple[Gateway, Gateway], clock: FakeClock
) -> None:
    a, b = two_instances
    alice, bob = a.directory.users["alice"], a.directory.users["bob"]
    token = a.issue_token(
        alice, TokenRequest(agent_id="inbox-assistant", scopes=["email:read", "email:send"])
    ).access_token
    assert (
        b.authorize(token, AuthorizeRequest(tool="read_inbox")).decision is Decision.ALLOW
    )  # issued on A, used on B

    # An approval requested through A, approved through B, consumed through A.
    args = {"to": ["partner@contoso.example"]}
    pending = a.authorize(
        token,
        AuthorizeRequest(tool="send_email", args=args, user_prompt="mail partner@contoso.example"),
    )
    assert pending.decision is Decision.REQUIRE_APPROVAL and pending.approval_id
    b.approve(pending.approval_id, bob)
    done = a.authorize(
        token,
        AuthorizeRequest(
            tool="send_email",
            args=args,
            user_prompt="mail partner@contoso.example",
            approval_id=pending.approval_id,
        ),
    )
    assert done.decision is Decision.ALLOW

    # The kill switch flipped on B stops the agent on A.
    b.set_agent_enabled("inbox-assistant", False, reason="incident")
    with pytest.raises(AuthenticationError):
        a.authorize(token, AuthorizeRequest(tool="read_inbox"))
    assert a.audit.verify().ok and b.audit.verify().ok


def test_key_rotation_on_one_instance_reaches_the_other(
    two_instances: tuple[Gateway, Gateway], clock: FakeClock
) -> None:
    a, b = two_instances
    before = a.issue_token(
        a.directory.users["alice"], TokenRequest(agent_id="inbox-assistant", scopes=["email:read"])
    ).access_token
    a.rotate_keys()
    clock.advance(10)  # past the ring's reload interval
    after = b.issue_token(
        b.directory.users["alice"], TokenRequest(agent_id="inbox-assistant", scopes=["email:read"])
    ).access_token
    assert b.keys.kid == a.keys.kid
    for gateway in (a, b):
        for token in (before, after):
            assert (
                gateway.authorize(token, AuthorizeRequest(tool="read_inbox")).decision
                is Decision.ALLOW
            )


def test_reconnects_after_the_connection_drops() -> None:
    db = fresh_postgres()
    db._conn.close()  # simulate a dropped connection
    assert db.query_one("SELECT 1 AS one")["one"] == 1
    db.close()


def test_cli_and_settings_use_the_url(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    fresh_postgres().close()
    monkeypatch.setenv("AGENTWARDEN_DATABASE_URL", str(PG_URL))
    assert Settings.from_env().database == PG_URL
    with Gateway.build(Settings.from_env()) as gateway:
        gateway.audit.append("cli.test")
    assert main(["audit", "verify"]) == 0
    assert capsys.readouterr().out.startswith("OK: 1 entries")


def test_bad_connection_is_a_configuration_error() -> None:
    with pytest.raises(ConfigurationError, match="could not connect"):
        Database("postgresql://nobody@127.0.0.1:1/nothing")
