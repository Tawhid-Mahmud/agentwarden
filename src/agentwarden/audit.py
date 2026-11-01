"""Tamper-evident audit log.

Every entry stores the hash of the previous entry, so modifying, deleting or reordering any row
breaks the chain from that point on (:meth:`AuditLog.verify`). Signed *checkpoints* let an
auditor detect truncation of the tail as well: keep a checkpoint somewhere the database owner
can't write, and later prove that row ``seq`` still has the checkpointed hash.

Secrets are redacted before anything is written.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from agentwarden.identity.keys import KeyManager, b64url, b64url_decode
from agentwarden.models import AuditEvent
from agentwarden.risk.detectors import redact_obj
from agentwarden.storage import Database

GENESIS_HASH = "0" * 64
AUTHZ_EVENT = "authz.decision"


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).isoformat(timespec="microseconds")


def entry_hash(
    *,
    seq: int,
    ts: str,
    event_type: str,
    user_id: str | None,
    agent_id: str | None,
    tool: str | None,
    decision: str | None,
    data: str,
    prev_hash: str,
) -> str:
    material = canonical_json(
        {
            "seq": seq,
            "ts": ts,
            "event_type": event_type,
            "user_id": user_id,
            "agent_id": agent_id,
            "tool": tool,
            "decision": decision,
            "data": data,
            "prev_hash": prev_hash,
        }
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    head_hash: str
    first_bad_seq: int | None = None
    reason: str = ""


def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        seq=row["seq"],
        ts=datetime.fromisoformat(row["ts"]),
        event_type=row["event_type"],
        user_id=row["user_id"],
        agent_id=row["agent_id"],
        tool=row["tool"],
        decision=row["decision"],
        data=json.loads(row["data"]),
        prev_hash=row["prev_hash"],
        hash=row["hash"],
    )


class AuditLog:
    def __init__(
        self,
        db: Database,
        keys: KeyManager | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._db = db
        self._keys = keys
        self._clock = clock

    # ------------------------------------------------------------------ writing
    def append(
        self,
        event_type: str,
        *,
        user_id: str | None = None,
        agent_id: str | None = None,
        tool: str | None = None,
        decision: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> AuditEvent:
        payload = canonical_json(redact_obj(data or {}))
        ts = _iso(self._clock())
        with self._db.transaction() as conn:
            last = conn.execute(
                "SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            seq = last["seq"] + 1 if last else 1
            prev_hash = last["hash"] if last else GENESIS_HASH
            digest = entry_hash(
                seq=seq,
                ts=ts,
                event_type=event_type,
                user_id=user_id,
                agent_id=agent_id,
                tool=tool,
                decision=decision,
                data=payload,
                prev_hash=prev_hash,
            )
            conn.execute(
                "INSERT INTO audit_log (seq, ts, event_type, user_id, agent_id, tool, decision,"
                " data, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    seq,
                    ts,
                    event_type,
                    user_id,
                    agent_id,
                    tool,
                    decision,
                    payload,
                    prev_hash,
                    digest,
                ),
            )
        return AuditEvent(
            seq=seq,
            ts=datetime.fromisoformat(ts),
            event_type=event_type,
            user_id=user_id,
            agent_id=agent_id,
            tool=tool,
            decision=decision,
            data=json.loads(payload),
            prev_hash=prev_hash,
            hash=digest,
        )

    # ---------------------------------------------------------------- integrity
    def verify(self) -> VerifyResult:
        """Recompute the whole chain. Detects modified, deleted, inserted or reordered rows."""
        expected_prev, expected_seq, checked = GENESIS_HASH, 1, 0
        for row in self._db.query("SELECT * FROM audit_log ORDER BY seq"):
            seq = row["seq"]
            if seq != expected_seq:
                return VerifyResult(
                    False, checked, expected_prev, expected_seq, f"missing entry {expected_seq}"
                )
            if row["prev_hash"] != expected_prev:
                return VerifyResult(
                    False,
                    checked,
                    expected_prev,
                    seq,
                    "prev_hash does not link to the previous entry",
                )
            recomputed = entry_hash(
                seq=seq,
                ts=row["ts"],
                event_type=row["event_type"],
                user_id=row["user_id"],
                agent_id=row["agent_id"],
                tool=row["tool"],
                decision=row["decision"],
                data=row["data"],
                prev_hash=row["prev_hash"],
            )
            if recomputed != row["hash"]:
                return VerifyResult(
                    False, checked, expected_prev, seq, "entry content does not match its hash"
                )
            expected_prev, expected_seq, checked = row["hash"], seq + 1, checked + 1
        return VerifyResult(True, checked, expected_prev)

    def head(self) -> tuple[int, str]:
        row = self._db.query_one("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1")
        return (row["seq"], row["hash"]) if row else (0, GENESIS_HASH)

    def checkpoint(self) -> dict[str, Any]:
        """Sign the current head of the chain."""
        if self._keys is None:
            raise RuntimeError("checkpoints need a signing key")
        seq, digest = self.head()
        body = {"seq": seq, "hash": digest, "ts": _iso(self._clock())}
        signature = self._keys.sign(canonical_json(body).encode("utf-8"))
        return {**body, "kid": self._keys.kid, "signature": b64url(signature)}

    def verify_checkpoint(self, checkpoint: dict[str, Any]) -> bool:
        """True if the checkpoint is authentic *and* the log still contains that exact head."""
        if self._keys is None or checkpoint.get("kid") != self._keys.kid:
            return False
        body = {k: checkpoint.get(k) for k in ("seq", "hash", "ts")}
        try:
            signature = b64url_decode(str(checkpoint["signature"]))
        except (KeyError, ValueError):
            return False
        if not self._keys.verify(signature, canonical_json(body).encode("utf-8")):
            return False
        if body["seq"] == 0:
            return True
        row = self._db.query_one("SELECT hash FROM audit_log WHERE seq = ?", (body["seq"],))
        return row is not None and row["hash"] == body["hash"]

    # ------------------------------------------------------------------ reading
    def query(
        self,
        *,
        agent_id: str | None = None,
        user_id: str | None = None,
        event_type: str | None = None,
        decision: str | None = None,
        since: float | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        since_iso = _iso(since) if since is not None else None
        rows = self._db.query(
            "SELECT * FROM audit_log"
            " WHERE (? IS NULL OR agent_id = ?) AND (? IS NULL OR user_id = ?)"
            " AND (? IS NULL OR event_type = ?) AND (? IS NULL OR decision = ?)"
            " AND (? IS NULL OR ts >= ?)"
            " ORDER BY seq DESC LIMIT ?",
            (
                agent_id, agent_id, user_id, user_id, event_type, event_type,
                decision, decision, since_iso, since_iso, max(1, min(limit, 100_000)),
            ),
        )  # fmt: skip
        return [_row_to_event(r) for r in rows]

    # ---------------------------------------------- ActivitySource (anomaly detector)
    def decision_counts(self, agent_id: str, since: float) -> dict[str, int]:
        rows = self._db.query(
            "SELECT decision, COUNT(*) AS n FROM audit_log WHERE event_type = ? AND agent_id = ?"
            " AND ts >= ? GROUP BY decision",
            (AUTHZ_EVENT, agent_id, _iso(since)),
        )
        return {row["decision"]: row["n"] for row in rows}

    def has_allowed(self, agent_id: str, tool: str) -> bool:
        row = self._db.query_one(
            "SELECT 1 FROM audit_log WHERE event_type = ? AND agent_id = ? AND tool = ?"
            " AND decision = 'allow' LIMIT 1",
            (AUTHZ_EVENT, agent_id, tool),
        )
        return row is not None
