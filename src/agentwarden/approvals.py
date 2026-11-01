"""Human-in-the-loop approvals.

Approvals are designed against the classic HITL failure modes:

* **Bound**: an approval covers one exact call, ``sha256(user, actor chain, tool, args)``. An
  agent can't get "send email to bob" approved and then send something else.
* **Single-use**: consuming an approval flips its state atomically, so replays fail.
* **Expiring**: unused approvals stop working after ``approval_ttl`` seconds.
* **Separation of duties**: reviewers need the ``approver`` role and can't approve requests
  made on their own behalf.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel

from agentwarden.errors import ApprovalError, NotFoundError, PermissionDeniedError
from agentwarden.models import User
from agentwarden.risk.detectors import redact_obj
from agentwarden.storage import Database

APPROVER_ROLE = "approver"
_PREVIEW_LIMIT = 500


class ApprovalStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"
    EXPIRED = "expired"


class ApprovalRequest(BaseModel):
    id: str
    decision_id: str
    status: ApprovalStatus
    user_id: str
    agent_id: str
    tool: str
    call_hash: str
    args_preview: dict[str, Any]
    reasons: list[str]
    risk_score: float
    created_at: datetime
    expires_at: datetime
    reviewer: str | None = None
    reviewed_at: datetime | None = None
    note: str = ""


def call_hash(user_id: str, actor_chain: Sequence[str], tool: str, args: Mapping[str, Any]) -> str:
    material = json.dumps(
        {"user": user_id, "actors": list(actor_chain), "tool": tool, "args": args},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def preview_args(args: Mapping[str, Any], limit: int = _PREVIEW_LIMIT) -> dict[str, Any]:
    """Redact secrets and truncate long strings, for display and audit storage."""

    def shorten(value: Any) -> Any:
        if isinstance(value, str) and len(value) > limit:
            return value[:limit] + f"… [{len(value)} chars]"
        if isinstance(value, dict):
            return {k: shorten(v) for k, v in value.items()}
        if isinstance(value, list):
            return [shorten(v) for v in value]
        return value

    redacted: dict[str, Any] = redact_obj(dict(args))
    return {k: shorten(v) for k, v in redacted.items()}


def _ts(value: float | None) -> datetime | None:
    return datetime.fromtimestamp(value, UTC) if value is not None else None


def _ts_required(value: float) -> datetime:
    return datetime.fromtimestamp(value, UTC)


@dataclass(frozen=True)
class ApprovalCheck:
    """Outcome of presenting an approval id with a tool call."""

    outcome: Literal["consumed", "pending", "denied", "expired", "mismatch", "used", "not_found"]
    request: ApprovalRequest | None = None


class ApprovalQueue:
    def __init__(
        self, db: Database, ttl: int = 900, clock: Callable[[], float] = time.time
    ) -> None:
        self._db = db
        self._ttl = ttl
        self._clock = clock

    def create(
        self,
        *,
        decision_id: str,
        user_id: str,
        actor_chain: Sequence[str],
        tool: str,
        args: Mapping[str, Any],
        reasons: Sequence[str],
        risk_score: float,
    ) -> ApprovalRequest:
        now = self._clock()
        approval_id = "apr_" + secrets.token_urlsafe(18)
        self._db.execute(
            "INSERT INTO approvals (id, decision_id, status, user_id, agent_id, tool, call_hash,"
            " args_preview, reasons, risk_score, created_at, expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                approval_id,
                decision_id,
                ApprovalStatus.PENDING.value,
                user_id,
                actor_chain[0],
                tool,
                call_hash(user_id, actor_chain, tool, args),
                json.dumps(preview_args(args), default=str),
                json.dumps(list(reasons)),
                risk_score,
                now,
                now + self._ttl,
            ),
        )
        return self.get(approval_id)

    def get(self, approval_id: str) -> ApprovalRequest:
        row = self._db.query_one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        if row is None:
            raise NotFoundError(f"unknown approval {approval_id!r}")
        return self._to_model(row)

    def list(self, status: ApprovalStatus | None = None) -> list[ApprovalRequest]:
        self._expire_stale()
        if status is None:
            rows = self._db.query("SELECT * FROM approvals ORDER BY created_at DESC")
        else:
            rows = self._db.query(
                "SELECT * FROM approvals WHERE status = ? ORDER BY created_at DESC", (status.value,)
            )
        return [self._to_model(r) for r in rows]

    def approve(self, approval_id: str, reviewer: User, note: str = "") -> ApprovalRequest:
        return self._review(approval_id, reviewer, ApprovalStatus.APPROVED, note)

    def deny(self, approval_id: str, reviewer: User, note: str = "") -> ApprovalRequest:
        return self._review(approval_id, reviewer, ApprovalStatus.DENIED, note)

    def check(
        self,
        approval_id: str,
        *,
        user_id: str,
        actor_chain: Sequence[str],
        tool: str,
        args: Mapping[str, Any],
    ) -> ApprovalCheck:
        """Consume ``approval_id`` for this exact call if possible and say what happened."""
        self._expire_stale()
        try:
            request = self.get(approval_id)
        except NotFoundError:
            return ApprovalCheck("not_found")
        if request.call_hash != call_hash(user_id, actor_chain, tool, args):
            return ApprovalCheck("mismatch", request)
        if request.status is ApprovalStatus.PENDING:
            return ApprovalCheck("pending", request)
        if request.status is ApprovalStatus.DENIED:
            return ApprovalCheck("denied", request)
        if request.status is ApprovalStatus.EXPIRED:
            return ApprovalCheck("expired", request)
        if request.status is ApprovalStatus.CONSUMED:
            return ApprovalCheck("used", request)
        consumed = self._db.execute(
            "UPDATE approvals SET status = ? WHERE id = ? AND status = ? AND expires_at > ?",
            (
                ApprovalStatus.CONSUMED.value,
                approval_id,
                ApprovalStatus.APPROVED.value,
                self._clock(),
            ),
        )
        if not consumed:  # lost a race with another consumer or with expiry
            return ApprovalCheck("used", self.get(approval_id))
        return ApprovalCheck("consumed", self.get(approval_id))

    # ------------------------------------------------------------------ internals
    def _review(
        self, approval_id: str, reviewer: User, status: ApprovalStatus, note: str
    ) -> ApprovalRequest:
        if APPROVER_ROLE not in reviewer.roles:
            raise PermissionDeniedError(
                f"user {reviewer.id!r} does not have the '{APPROVER_ROLE}' role"
            )
        self._expire_stale()
        request = self.get(approval_id)
        if request.user_id == reviewer.id:
            raise ApprovalError(
                "separation of duties: you cannot review a request made on your behalf"
            )
        if request.status is not ApprovalStatus.PENDING:
            raise ApprovalError(f"approval is {request.status.value}, not pending")
        changed = self._db.execute(
            "UPDATE approvals SET status = ?, reviewer = ?, reviewed_at = ?, note = ?"
            " WHERE id = ? AND status = ?",
            (
                status.value,
                reviewer.id,
                self._clock(),
                note[:1000],
                approval_id,
                ApprovalStatus.PENDING.value,
            ),
        )
        if not changed:
            raise ApprovalError("approval was reviewed concurrently")
        return self.get(approval_id)

    def _expire_stale(self) -> None:
        self._db.execute(
            "UPDATE approvals SET status = ? WHERE status IN (?, ?) AND expires_at <= ?",
            (
                ApprovalStatus.EXPIRED.value,
                ApprovalStatus.PENDING.value,
                ApprovalStatus.APPROVED.value,
                self._clock(),
            ),
        )

    @staticmethod
    def _to_model(row: sqlite3.Row) -> ApprovalRequest:
        return ApprovalRequest(
            id=row["id"],
            decision_id=row["decision_id"],
            status=ApprovalStatus(row["status"]),
            user_id=row["user_id"],
            agent_id=row["agent_id"],
            tool=row["tool"],
            call_hash=row["call_hash"],
            args_preview=json.loads(row["args_preview"]),
            reasons=json.loads(row["reasons"]),
            risk_score=row["risk_score"],
            created_at=_ts_required(row["created_at"]),
            expires_at=_ts_required(row["expires_at"]),
            reviewer=row["reviewer"],
            reviewed_at=_ts(row["reviewed_at"]),
            note=row["note"],
        )
