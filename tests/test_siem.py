"""SIEM export: OCSF mapping, cursor-based delivery, sinks, and tamper detection on export."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from agentwarden.api import create_app
from agentwarden.audit import AuditIntegrityError, AuditLog
from agentwarden.cli import main
from agentwarden.config import Settings
from agentwarden.errors import AuthenticationError
from agentwarden.gateway import Gateway
from agentwarden.models import (
    AuditEvent,
    AuthorizeRequest,
    ContextSegment,
    DelegationRequest,
    TokenRequest,
)
from agentwarden.siem import (
    AuditExporter,
    ExportError,
    JsonLinesSink,
    WebhookSink,
    open_sink,
    to_ocsf,
)
from agentwarden.storage import Database
from tests.conftest import FakeClock

ADMIN = {"X-Admin-Key": "test-admin-key-0123456789"}
AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"


class ListSink:
    def __init__(self, fail: bool = False) -> None:
        self.batches: list[list[dict[str, Any]]] = []
        self.fail = fail

    def send(self, records: list[dict[str, Any]]) -> None:
        if self.fail:
            raise ExportError("sink down")
        self.batches.append(records)

    def close(self) -> None:
        pass

    @property
    def records(self) -> list[dict[str, Any]]:
        return [r for batch in self.batches for r in batch]


@pytest.fixture
def gw(settings: Settings, clock: FakeClock) -> Iterator[Gateway]:
    with Gateway.build(settings, clock=clock) as gateway:
        yield gateway


def run_scenario(gw: Gateway) -> None:
    """Produce one of (nearly) every audit event type."""
    alice, bob = gw.directory.users["alice"], gw.directory.users["bob"]
    token = gw.issue_token(
        alice,
        TokenRequest(agent_id="inbox-assistant", scopes=["email:read", "email:send", "docs:read"]),
    ).access_token
    gw.authorize(token, AuthorizeRequest(tool="read_inbox"))
    gw.authorize(token, AuthorizeRequest(tool="transfer_funds", args={"amount": 5}))
    pending = gw.authorize(
        token,
        AuthorizeRequest(
            tool="send_email",
            args={"to": ["dana@vendor.example"], "body": "Received, thanks"},
            user_prompt=f"Reply to Dana (my key is {AWS_KEY})",
            context=[ContextSegment(source="email:7", content="From: dana@vendor.example")],
        ),
    )
    assert pending.approval_id
    gw.approve(pending.approval_id, bob, note="ok")
    gw.delegate_token(token, DelegationRequest(sub_agent_id="summarizer", scopes=["email:read"]))
    with pytest.raises(AuthenticationError):
        gw.authorize("not-a-token", AuthorizeRequest(tool="read_inbox"))
    gw.set_agent_enabled("summarizer", False, reason="incident")
    gw.set_agent_enabled("summarizer", True)
    gw.revoke_token(token, "done")
    gw.audit.append("custom.event", data={"note": "something new"})


# ---------------------------------------------------------------------- OCSF


def test_ocsf_mapping_covers_the_audit_vocabulary(gw: Gateway) -> None:
    run_scenario(gw)
    events = list(reversed(gw.audit.query(limit=1000)))
    records = {e.event_type: to_ocsf(e) for e in events}
    expected = {
        "token.issued": (3002, 3),
        "token.delegated": (3002, 4),
        "token.revoked": (3002, 2),
        "auth.failed": (3002, 1),
        "authz.decision": (6003, 99),
        "approval.requested": (3004, 1),
        "approval.approved": (3004, 3),
        "agent.disabled": (3001, 5),
        "agent.enabled": (3001, 2),
        "custom.event": (0, 99),
    }
    for event_type, (class_uid, activity_id) in expected.items():
        record = records[event_type]
        assert (record["class_uid"], record["activity_id"]) == (class_uid, activity_id), event_type
        assert record["type_uid"] == class_uid * 100 + activity_id
        assert record["category_uid"] == class_uid // 1000
        assert record["metadata"]["event_code"] == event_type
        assert record["metadata"]["version"] == "1.3.0"
        for field in ("class_name", "category_name", "activity_name", "type_name", "severity"):
            assert isinstance(record[field], str) and record[field]
    assert records["auth.failed"]["status"] == "Failure"
    assert records["auth.failed"]["status_detail"]
    assert records["agent.disabled"]["user"]["uid"] == "summarizer"
    assert records["approval.approved"]["actor"]["user"]["uid"] == "bob"
    assert records["approval.approved"]["entity"]["type"] == "Approval"


def test_authorization_decisions_carry_status_severity_and_correlation(gw: Gateway) -> None:
    run_scenario(gw)
    decisions = [
        to_ocsf(e) for e in reversed(gw.audit.query(event_type="authz.decision", limit=100))
    ]
    by_tool = {r["api"]["operation"]: r for r in decisions}
    allowed, denied, pending = (
        by_tool["read_inbox"],
        by_tool["transfer_funds"],
        by_tool["send_email"],
    )
    assert allowed["status"] == "Success" and allowed["severity_id"] <= 2
    assert denied["status"] == "Failure" and denied["severity_id"] >= 3
    assert "transfer_funds" in denied["status_detail"] or "scope" in denied["status_detail"]
    assert "approval" in pending["status_detail"] and "status_detail" not in allowed
    assert pending["status"] == "Other" and pending["severity_id"] >= 2
    assert pending["actor"]["user"]["uid"] == "alice"
    assert pending["actor"]["app_name"] == "inbox-assistant"
    decision_id = pending["unmapped"]["agentwarden"]["data"]["decision_id"]
    assert pending["metadata"]["correlation_uid"] == pending["api"]["request"]["uid"] == decision_id
    assert "alice" in pending["message"] and "send_email" in pending["message"]


def test_ocsf_records_preserve_the_entry_and_its_redaction(gw: Gateway) -> None:
    run_scenario(gw)
    for event in gw.audit.query(limit=1000):
        record = to_ocsf(event)
        assert record["metadata"]["uid"] == event.hash
        assert record["metadata"]["sequence"] == event.seq
        assert record["time"] == int(event.ts.timestamp() * 1000)
        assert AuditEvent.model_validate(record["unmapped"]["agentwarden"]) == event
        assert AWS_KEY not in json.dumps(record)


# ------------------------------------------------------------------ exporter


def test_export_delivers_everything_once_then_only_new_entries(
    db: Database, clock: FakeClock
) -> None:
    audit = AuditLog(db, clock=clock)
    for i in range(7):
        audit.append("load.test", data={"i": i})
    sink = ListSink()
    exporter = AuditExporter(db, audit, sink, name="splunk", batch_size=3)
    assert exporter.export_all() == 7
    assert [len(b) for b in sink.batches] == [3, 3, 1]
    assert [r["metadata"]["sequence"] for r in sink.records] == list(range(1, 8))
    assert exporter.export_all() == 0

    audit.append("load.test", data={"i": 7})
    again = AuditExporter(db, audit, sink, name="splunk")  # the cursor lives in the database
    assert again.cursor()[0] == 7
    assert again.export_all() == 1 and sink.records[-1]["metadata"]["sequence"] == 8
    other = AuditExporter(db, audit, ListSink(), name="elastic", fmt="native")
    assert other.export_all() == 8  # cursors are independent per destination


def test_a_failed_send_does_not_move_the_cursor(db: Database, clock: FakeClock) -> None:
    audit = AuditLog(db, clock=clock)
    audit.append("a")
    exporter = AuditExporter(db, audit, ListSink(fail=True))
    with pytest.raises(ExportError):
        exporter.export_batch()
    assert exporter.cursor()[0] == 0
    retry = ListSink()
    assert AuditExporter(db, audit, retry).export_all() == 1  # at-least-once: nothing lost


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ("UPDATE audit_log SET data = '{\"i\":99}' WHERE seq = 2", "changed or removed"),
        ("DELETE FROM audit_log WHERE seq = 2", "changed or removed"),
        ("UPDATE audit_log SET data = '{\"i\":99}' WHERE seq = 3", "does not match its hash"),
        ("DELETE FROM audit_log WHERE seq = 3", "missing entry 3"),
        ("UPDATE audit_log SET prev_hash = hash WHERE seq = 3", "does not link"),
    ],
)
def test_export_stops_when_the_chain_was_rewritten(
    db: Database, clock: FakeClock, tamper: str, message: str
) -> None:
    audit = AuditLog(db, clock=clock)
    for i in range(2):
        audit.append("load.test", data={"i": i})
    sink = ListSink()
    exporter = AuditExporter(db, audit, sink)
    exporter.export_all()
    for i in range(2, 4):
        audit.append("load.test", data={"i": i})
    db.execute(tamper)
    with pytest.raises(AuditIntegrityError, match=message):
        exporter.export_all()
    assert len(sink.records) == 2 and exporter.cursor()[0] == 2


def test_rewriting_the_whole_tail_is_caught(db: Database, clock: FakeClock) -> None:
    """Truncate exported entries and append fresh, self-consistent ones: the cursor notices."""
    audit = AuditLog(db, clock=clock)
    for i in range(3):
        audit.append("load.test", data={"i": i})
    exporter = AuditExporter(db, audit, ListSink())
    exporter.export_all()
    db.execute("DELETE FROM audit_log WHERE seq >= 2")
    for i in range(3):
        audit.append("load.test", data={"i": f"forged-{i}"})
    assert audit.verify().ok  # internally consistent ...
    with pytest.raises(AuditIntegrityError):  # ... but not what was already exported
        exporter.export_all()


def test_reset_and_concurrent_cursor_moves(db: Database, clock: FakeClock) -> None:
    audit = AuditLog(db, clock=clock)
    for _ in range(3):
        audit.append("a")
    exporter = AuditExporter(db, audit, ListSink())
    exporter.reset(to_head=True)
    assert exporter.cursor()[0] == 3 and exporter.export_all() == 0
    exporter.reset()
    assert exporter.cursor()[0] == 0 and exporter.export_all() == 3

    audit.append("a")
    slow = AuditExporter(db, audit, ListSink())
    fast = AuditExporter(db, audit, ListSink())
    stale = slow.cursor()  # slow read its cursor, then fast exported first
    slow.cursor = lambda: stale  # type: ignore[method-assign]
    fast.export_all()
    audit.append("a")
    with pytest.raises(ExportError, match="moved by another exporter"):
        slow.export_batch()


def test_follow_retries_sink_errors(db: Database, clock: FakeClock) -> None:
    audit = AuditLog(db, clock=clock)
    audit.append("a")
    sink = ListSink(fail=True)
    rounds = iter([False, False, True])

    def stop() -> bool:
        done = next(rounds)
        sink.fail = False  # recovers after the first attempt
        return done

    assert AuditExporter(db, audit, sink).follow(0, stop) == 1


def test_unknown_format_is_rejected(db: Database) -> None:
    with pytest.raises(ValueError, match="unknown format"):
        AuditExporter(db, AuditLog(db), ListSink(), fmt="cef")  # type: ignore[arg-type]


# --------------------------------------------------------------------- sinks


def test_json_lines_sinks(tmp_path: Path) -> None:
    stream = io.StringIO()
    JsonLinesSink(stream).send([{"b": 1, "a": "é"}, {"c": 2}])
    assert stream.getvalue() == '{"a":"é","b":1}\n{"c":2}\n'
    path = tmp_path / "out.jsonl"
    for _ in range(2):
        sink = open_sink(f"file:{path}")
        sink.send([{"x": 1}])
        sink.close()
    assert path.read_text().splitlines() == ['{"x":1}', '{"x":1}']  # appends
    assert isinstance(open_sink("-"), JsonLinesSink)
    assert isinstance(open_sink("https://siem.example/hook", token="t"), WebhookSink)


def test_webhook_sink_posts_batches() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200 if len(seen) == 1 else 503)

    sink = WebhookSink(
        "https://siem.example/hook", token="tok", transport=httpx.MockTransport(handler)
    )
    sink.send([{"a": 1}])
    assert json.loads(seen[0].content) == [{"a": 1}]
    assert seen[0].headers["authorization"] == "Bearer tok"
    assert seen[0].headers["content-type"] == "application/json"
    with pytest.raises(ExportError, match="HTTP 503"):
        sink.send([{"a": 2}])
    sink.close()

    def broken(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    splunk = WebhookSink(
        "http://127.0.0.1:8088/services/collector",
        headers={"Authorization": "Splunk abc"},
        transport=httpx.MockTransport(broken),
    )
    with pytest.raises(ExportError, match="unreachable"):
        splunk.send([{"a": 1}])


@pytest.mark.parametrize(
    "url", ["http://siem.example/hook", "ftp://siem.example/x", "https://", "http://10.0.0.5/x"]
)
def test_webhook_sink_requires_https_off_loopback(url: str) -> None:
    with pytest.raises(ValueError):
        WebhookSink(url)


# ------------------------------------------------------------------- CLI/API


def test_cli_export(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db_path = tmp_path / "aw.db"
    settings = replace(Settings(db_path=str(db_path)))
    with Gateway.build(settings) as gateway:
        run_scenario(gateway)
        total = gateway.audit.head()[0]
    out = tmp_path / "ocsf.jsonl"
    assert main(["audit", "export", "--db", str(db_path), "--sink", str(out)]) == 0
    lines = [json.loads(line) for line in out.read_text().splitlines()]
    assert len(lines) == total and all("class_uid" in r for r in lines)
    assert f"exported {total} entries" in capsys.readouterr().err

    assert main(["audit", "export", "--db", str(db_path), "--sink", str(out)]) == 0
    assert len(out.read_text().splitlines()) == total  # nothing new

    assert main(["audit", "export", "--db", str(db_path), "--format", "native",
                 "--cursor", "raw", "--sink", "-"]) == 0  # fmt: skip
    assert len(capsys.readouterr().out.splitlines()) == total

    tampered = Database(str(db_path))
    tampered.execute("UPDATE audit_log SET data = '{}' WHERE seq = 1")
    tampered.close()
    assert main(["audit", "export", "--db", str(db_path), "--sink", str(out),
                 "--reset", "start"]) == 1  # fmt: skip
    assert "TAMPERED" in capsys.readouterr().err
    assert main(["audit", "export", "--db", str(db_path), "--sink", "http://evil.example/"]) == 2


def test_api_export_pages_through_the_chain(gw: Gateway) -> None:
    run_scenario(gw)
    client = TestClient(create_app(gw))
    assert client.get("/v1/audit/export").status_code == 401
    collected: list[dict[str, Any]] = []
    params: dict[str, Any] = {"limit": 4}
    while True:
        page = client.get("/v1/audit/export", params=params, headers=ADMIN).json()
        assert "events" in page, page
        if not page["events"]:
            break
        collected += page["events"]
        params = {"limit": 4, **page["next"]}
    assert [r["metadata"]["sequence"] for r in collected] == list(range(1, gw.audit.head()[0] + 1))
    native = client.get(
        "/v1/audit/export", params={"format": "native", "after_seq": 2}, headers=ADMIN
    ).json()
    assert native["events"][0]["seq"] == 3 and "hash" in native["events"][0]

    head_seq, head_hash = gw.audit.head()
    gw.db.execute("UPDATE audit_log SET data = '{}' WHERE seq = ?", (head_seq,))
    conflict = client.get(
        "/v1/audit/export",
        params={"after_seq": head_seq, "after_hash": head_hash},
        headers=ADMIN,
    )
    assert conflict.status_code == 409 and conflict.json()["seq"] == head_seq
    bad = client.get("/v1/audit/export", params={"after_hash": "nope"}, headers=ADMIN)
    assert bad.status_code == 422
