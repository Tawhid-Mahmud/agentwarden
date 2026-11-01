"""Tests for the audit chain, approval queue and least-privilege analyzer."""

from __future__ import annotations

import pytest

from agentwarden.analyzer import LeastPrivilegeAnalyzer
from agentwarden.approvals import ApprovalQueue, ApprovalStatus, call_hash
from agentwarden.audit import AUTHZ_EVENT, GENESIS_HASH, AuditLog
from agentwarden.directory import Directory
from agentwarden.errors import ApprovalError, NotFoundError, PermissionDeniedError
from agentwarden.identity import AgentRegistry, KeyManager
from agentwarden.models import Agent
from agentwarden.storage import Database
from tests.conftest import FakeClock

AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"


# =============================================================================== audit
@pytest.fixture
def audit(db: Database, keys: KeyManager, clock: FakeClock) -> AuditLog:
    return AuditLog(db, keys=keys, clock=clock)


def fill(audit: AuditLog, n: int = 5) -> None:
    for i in range(n):
        audit.append(
            AUTHZ_EVENT,
            user_id="alice",
            agent_id="bot",
            tool="search_docs",
            decision="allow",
            data={"i": i},
        )


def test_chain_links_and_verifies(audit: AuditLog) -> None:
    first = audit.append("token.issued", user_id="alice", data={"jti": "x"})
    second = audit.append("token.issued", user_id="alice", data={"jti": "y"})
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.hash
    result = audit.verify()
    assert result.ok and result.checked == 2 and result.head_hash == second.hash


def test_secrets_are_redacted_before_storage(audit: AuditLog, db: Database) -> None:
    audit.append(AUTHZ_EVENT, data={"args": {"body": f"key={AWS_KEY}"}})
    raw = db.query_one("SELECT data FROM audit_log")
    assert raw is not None and AWS_KEY not in raw["data"]
    assert "[REDACTED:aws_access_key_id]" in raw["data"]


@pytest.mark.parametrize(
    ("tamper", "reason"),
    [
        ("UPDATE audit_log SET data = '{\"i\": 99}' WHERE seq = 3", "does not match its hash"),
        ("UPDATE audit_log SET decision = 'deny' WHERE seq = 3", "does not match its hash"),
        ("DELETE FROM audit_log WHERE seq = 3", "missing entry 3"),
        ("UPDATE audit_log SET prev_hash = 'f' || substr(prev_hash, 2) WHERE seq = 3", "prev_hash"),
    ],
)
def test_tampering_is_detected(audit: AuditLog, db: Database, tamper: str, reason: str) -> None:
    fill(audit)
    db.execute(tamper)
    result = audit.verify()
    assert not result.ok
    assert result.first_bad_seq == 3
    assert reason in result.reason


def test_rehashing_a_row_breaks_the_next_link(audit: AuditLog, db: Database) -> None:
    """An attacker who recomputes a row's hash still breaks the following row's prev_hash."""
    from agentwarden.audit import entry_hash

    fill(audit)
    row = db.query_one("SELECT * FROM audit_log WHERE seq = 3")
    assert row is not None
    forged = entry_hash(
        seq=3, ts=row["ts"], event_type=row["event_type"], user_id=row["user_id"], agent_id=row["agent_id"],
        tool=row["tool"], decision="deny", data=row["data"], prev_hash=row["prev_hash"],
    )  # fmt: skip
    db.execute("UPDATE audit_log SET decision = 'deny', hash = ? WHERE seq = 3", (forged,))
    result = audit.verify()
    assert not result.ok and result.first_bad_seq == 4


def test_signed_checkpoints_detect_truncation(
    audit: AuditLog, db: Database, keys: KeyManager
) -> None:
    fill(audit, 3)
    checkpoint = audit.checkpoint()
    assert checkpoint["seq"] == 3 and checkpoint["kid"] == keys.kid
    assert audit.verify_checkpoint(checkpoint)
    fill(audit, 2)
    assert audit.verify_checkpoint(checkpoint)  # appending is fine
    db.execute("DELETE FROM audit_log WHERE seq >= 3")
    assert audit.verify().ok  # truncation alone keeps a valid (shorter) chain...
    assert not audit.verify_checkpoint(checkpoint)  # ...but the checkpoint exposes it


def test_forged_checkpoints_rejected(audit: AuditLog) -> None:
    fill(audit, 2)
    checkpoint = audit.checkpoint()
    assert not audit.verify_checkpoint({**checkpoint, "seq": 1})
    assert not audit.verify_checkpoint({**checkpoint, "signature": "AAAA"})
    assert not audit.verify_checkpoint({**checkpoint, "kid": "other"})
    other = AuditLog(Database(), keys=KeyManager.generate())
    assert not other.verify_checkpoint(checkpoint)
    assert AuditLog(Database()).verify_checkpoint(checkpoint) is False
    with pytest.raises(RuntimeError):
        AuditLog(Database()).checkpoint()


def test_query_filters_and_activity(audit: AuditLog, clock: FakeClock) -> None:
    fill(audit, 3)
    audit.append(AUTHZ_EVENT, agent_id="bot", tool="send_email", decision="deny")
    audit.append("token.issued", user_id="bob")
    assert len(audit.query(agent_id="bot")) == 4
    assert [e.decision for e in audit.query(decision="deny")] == ["deny"]
    assert len(audit.query(event_type="token.issued", user_id="bob")) == 1
    assert len(audit.query(limit=2)) == 2
    assert audit.query(since=clock.now + 10) == []
    assert audit.decision_counts("bot", clock.now - 60) == {"allow": 3, "deny": 1}
    assert audit.has_allowed("bot", "search_docs")
    assert not audit.has_allowed("bot", "send_email")
    assert audit.head()[0] == 5


# ============================================================================ approvals
@pytest.fixture
def queue(db: Database, clock: FakeClock) -> ApprovalQueue:
    return ApprovalQueue(db, ttl=600, clock=clock)


CALL = {
    "user_id": "alice",
    "actor_chain": ["inbox-assistant"],
    "tool": "send_email",
    "args": {"to": ["p@x.example"]},
}


def new_request(queue: ApprovalQueue) -> str:
    return queue.create(decision_id="dec_1", reasons=["external email"], risk_score=0.3, **CALL).id  # type: ignore[arg-type]


def test_approval_lifecycle(queue: ApprovalQueue, directory: Directory) -> None:
    approval_id = new_request(queue)
    assert approval_id.startswith("apr_") and len(approval_id) > 20
    assert queue.check(approval_id, **CALL).outcome == "pending"  # type: ignore[arg-type]
    approved = queue.approve(approval_id, directory.users["bob"], note="looks fine")
    assert approved.status is ApprovalStatus.APPROVED and approved.reviewer == "bob"
    first = queue.check(approval_id, **CALL)  # type: ignore[arg-type]
    assert first.outcome == "consumed"
    assert queue.check(approval_id, **CALL).outcome == "used"  # type: ignore[arg-type]  # single-use


def test_approval_is_bound_to_the_exact_call(queue: ApprovalQueue, directory: Directory) -> None:
    approval_id = new_request(queue)
    queue.approve(approval_id, directory.users["bob"])
    tampered = {**CALL, "args": {"to": ["attacker@evil.example"]}}
    assert queue.check(approval_id, **tampered).outcome == "mismatch"  # type: ignore[arg-type]
    other_agent = {**CALL, "actor_chain": ["summarizer", "inbox-assistant"]}
    assert queue.check(approval_id, **other_agent).outcome == "mismatch"  # type: ignore[arg-type]
    assert queue.check(approval_id, **CALL).outcome == "consumed"  # type: ignore[arg-type]


def test_separation_of_duties(queue: ApprovalQueue, directory: Directory) -> None:
    approval_id = new_request(queue)
    with pytest.raises(PermissionDeniedError, match="approver"):
        queue.approve(approval_id, directory.users["carol"])  # no approver role
    alice_as_approver = directory.users["alice"].model_copy(update={"roles": ["approver"]})
    with pytest.raises(ApprovalError, match="separation of duties"):
        queue.approve(approval_id, alice_as_approver)


def test_denied_and_expired_approvals(
    queue: ApprovalQueue, directory: Directory, clock: FakeClock
) -> None:
    denied = new_request(queue)
    queue.deny(denied, directory.users["bob"], note="no")
    assert queue.check(denied, **CALL).outcome == "denied"  # type: ignore[arg-type]
    with pytest.raises(ApprovalError, match="not pending"):
        queue.approve(denied, directory.users["bob"])

    stale = new_request(queue)
    queue.approve(stale, directory.users["bob"])
    clock.advance(601)
    assert queue.check(stale, **CALL).outcome == "expired"  # type: ignore[arg-type]
    assert queue.get(stale).status is ApprovalStatus.EXPIRED
    assert {a.id for a in queue.list(ApprovalStatus.EXPIRED)} == {stale}
    assert queue.check("apr_missing", **CALL).outcome == "not_found"  # type: ignore[arg-type]
    with pytest.raises(NotFoundError):
        queue.get("apr_missing")


def test_preview_is_redacted_and_truncated(queue: ApprovalQueue) -> None:
    request = queue.create(
        decision_id="d", user_id="alice", actor_chain=["bot"], tool="http_request",
        args={"body": AWS_KEY + " " + "x" * 2000}, reasons=[], risk_score=0.9,
    )  # fmt: skip
    body = request.args_preview["body"]
    assert AWS_KEY not in body and "[REDACTED:aws_access_key_id]" in body
    assert "chars]" in body
    assert request.call_hash == call_hash(
        "alice", ["bot"], "http_request", {"body": AWS_KEY + " " + "x" * 2000}
    )


# ============================================================================= analyzer
def test_analyzer_findings(db: Database, directory: Directory, clock: FakeClock) -> None:
    registry = AgentRegistry(db)
    registry.register(
        Agent(
            id="reader",
            name="Reader",
            owner="alice",
            scope_ceiling=["docs:read", "email:send", "files:*"],
        )
    )
    registry.register(Agent(id="sleepy", name="Sleepy", owner="alice", scope_ceiling=["docs:read"]))
    registry.register(
        Agent(
            id="vault",
            name="Vault",
            owner="bob",
            scope_ceiling=["docs:read"],
            trust_tier="privileged",
        )
    )
    audit = AuditLog(db, clock=clock)
    for _ in range(3):
        audit.append(AUTHZ_EVENT, agent_id="reader", tool="search_docs", decision="allow")
    audit.append(AUTHZ_EVENT, agent_id="reader", tool="read_file", decision="allow")
    for _ in range(3):
        audit.append(AUTHZ_EVENT, agent_id="reader", tool="send_email", decision="deny",
                     data={"risk": {"detectors": ["injection", "taint"]}})  # fmt: skip
    audit.append(AUTHZ_EVENT, agent_id="vault", tool="search_docs", decision="allow")

    report = LeastPrivilegeAnalyzer(registry, audit, directory, clock=clock).analyze(window_days=7)
    codes = {(f.agent_id, f.code) for f in report.findings}
    assert codes == {
        ("reader", "UNUSED_SCOPES"),
        ("reader", "WILDCARD_SCOPE"),
        ("reader", "HIGH_DENY_RATE"),
        ("reader", "INJECTION_EXPOSURE"),
        ("sleepy", "DORMANT_AGENT"),
        ("vault", "UNNEEDED_PRIVILEGED_TIER"),
    }
    reader = next(a for a in report.agents if a.agent_id == "reader")
    assert reader.used_scopes == ["docs:read", "files:read"]
    assert reader.unused_scopes == ["email:send"]
    assert reader.injection_exposures == 3
    assert report.findings[0].severity == "high"
    wildcard = next(f for f in report.findings if f.code == "WILDCARD_SCOPE")
    assert "files:read" in wildcard.recommendation

    markdown = report.to_markdown()
    assert "| `reader` | standard | yes | 4 / 0 / 3 | `email:send` |" in markdown
    assert report.to_dict()["window_days"] == 7


def test_analyzer_clean_report(db: Database, directory: Directory, clock: FakeClock) -> None:
    registry = AgentRegistry(db)
    registry.register(Agent(id="reader", name="Reader", owner="alice", scope_ceiling=["docs:read"]))
    audit = AuditLog(db, clock=clock)
    audit.append(AUTHZ_EVENT, agent_id="reader", tool="search_docs", decision="allow")
    report = LeastPrivilegeAnalyzer(registry, audit, directory, clock=clock).analyze()
    assert report.findings == []
    assert "No findings" in report.to_markdown()
