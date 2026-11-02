"""Cursor-based export of the audit chain to a SIEM.

The exporter reads the audit log from where it last stopped (a named cursor stored in the
database), formats each entry, hands the batch to a sink, and only then moves the cursor. Delivery
is therefore **at-least-once**: after a crash between sending and saving the cursor, a batch is
sent again. De-duplicate on ``metadata.uid`` (OCSF) or ``hash`` (native), which is unique per entry.

Because the cursor stores the hash of the last exported entry, every batch is checked against the
chain before it is sent: if anything already exported was modified, deleted or re-linked in the
database, export stops with :class:`~agentwarden.audit.AuditIntegrityError` instead of quietly
shipping a rewritten history.
"""

from __future__ import annotations

import ipaddress
import os
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, Protocol, TextIO
from urllib.parse import urlsplit

import httpx

from agentwarden.audit import GENESIS_HASH, AuditLog, canonical_json
from agentwarden.models import AuditEvent
from agentwarden.siem.ocsf import to_ocsf
from agentwarden.storage import Database

Format = Literal["ocsf", "native"]
FORMATS: tuple[Format, ...] = ("ocsf", "native")


class ExportError(Exception):
    """A sink couldn't take the batch; the cursor was not moved."""


class Sink(Protocol):
    def send(self, records: list[dict[str, Any]]) -> None: ...

    def close(self) -> None: ...


class JsonLinesSink:
    """One JSON object per line, to a stream (stdout) or appended to a file."""

    def __init__(self, target: TextIO | str | Path) -> None:
        if isinstance(target, (str, Path)):
            self._stream: TextIO = open(target, "a", encoding="utf-8")  # noqa: SIM115
            self._owned = True
        else:
            self._stream, self._owned = target, False

    def send(self, records: list[dict[str, Any]]) -> None:
        for record in records:
            self._stream.write(canonical_json(record) + "\n")
        self._stream.flush()
        if self._owned:
            os.fsync(self._stream.fileno())  # don't move the cursor past unsynced data

    def close(self) -> None:
        if self._owned:
            self._stream.close()


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class WebhookSink:
    """POSTs each batch as a JSON array (Splunk HEC, Elastic, Sentinel and Cribl HTTP inputs).

    HTTPS is required except for loopback addresses. ``token`` is sent as a Bearer token;
    ``headers`` replace the defaults (e.g. ``{"Authorization": "Splunk <token>"}``).
    """

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"not an http(s) URL: {url!r}")
        if parts.scheme == "http" and not _is_loopback(parts.hostname):
            raise ValueError("webhook sinks must use https (plain http only for loopback)")
        default = {"Authorization": f"Bearer {token}"} if token else {}
        self._url = url
        self._client = httpx.Client(
            headers={"Content-Type": "application/json", **default, **(headers or {})},
            timeout=timeout,
            transport=transport,
            follow_redirects=False,
        )

    def send(self, records: list[dict[str, Any]]) -> None:
        try:
            response = self._client.post(self._url, content=canonical_json(records))
        except httpx.HTTPError as exc:
            raise ExportError(f"webhook unreachable: {exc}") from exc
        if not response.is_success:
            raise ExportError(f"webhook answered HTTP {response.status_code}")

    def close(self) -> None:
        self._client.close()


def open_sink(target: str, *, token: str | None = None) -> Sink:
    """``-`` for stdout, ``http(s)://...`` for a webhook, anything else is a file path."""
    if target == "-":
        return JsonLinesSink(sys.stdout)
    if target.startswith(("http://", "https://")):
        return WebhookSink(target, token=token)
    return JsonLinesSink(target.removeprefix("file:"))


def format_event(event: AuditEvent, fmt: Format) -> dict[str, Any]:
    return to_ocsf(event) if fmt == "ocsf" else event.model_dump(mode="json")


class AuditExporter:
    def __init__(
        self,
        db: Database,
        audit: AuditLog,
        sink: Sink,
        *,
        name: str = "default",
        fmt: Format = "ocsf",
        batch_size: int = 500,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if fmt not in FORMATS:
            raise ValueError(f"unknown format {fmt!r}; use one of {', '.join(FORMATS)}")
        self._db, self._audit, self._sink = db, audit, sink
        self.name, self._fmt, self._batch = name, fmt, batch_size
        self._clock = clock

    def cursor(self) -> tuple[int, str]:
        """``(seq, hash)`` of the last entry this exporter delivered (``(0, genesis)`` if none)."""
        row = self._db.query_one(
            "SELECT seq, hash FROM export_cursors WHERE name = ?", (self.name,)
        )
        return (row["seq"], row["hash"]) if row else (0, GENESIS_HASH)

    def reset(self, to_head: bool = False) -> None:
        """Forget the cursor: export from the beginning, or (``to_head``) only new entries."""
        self._db.execute("DELETE FROM export_cursors WHERE name = ?", (self.name,))
        if to_head:
            seq, digest = self._audit.head()
            self._save(None, seq, digest)

    def export_batch(self) -> int:
        """Send the next batch. Returns how many entries were delivered (0 when caught up)."""
        seq, digest = self.cursor()
        events = self._audit.entries_after(seq, digest, self._batch)
        if not events:
            return 0
        self._sink.send([format_event(e, self._fmt) for e in events])
        self._save(seq, events[-1].seq, events[-1].hash)
        return len(events)

    def export_all(self) -> int:
        total = 0
        while sent := self.export_batch():
            total += sent
        return total

    def follow(self, interval: float = 5.0, stop: Callable[[], bool] = lambda: False) -> int:
        """Keep exporting new entries until ``stop()`` is true. Sink errors are retried."""
        total = 0
        while not stop():
            try:
                total += self.export_all()
            except ExportError as exc:
                print(f"agentwarden export: {exc}; retrying", file=sys.stderr)
            time.sleep(interval)
        return total

    def _save(self, previous: int | None, seq: int, digest: str) -> None:
        now = self._clock()
        if previous is None or previous == 0:
            updated = self._db.execute(
                "INSERT INTO export_cursors (name, seq, hash, updated_at) VALUES (?, ?, ?, ?)"
                " ON CONFLICT (name) DO NOTHING",
                (self.name, seq, digest, now),
            )
            if updated or previous is None:
                return
        # Compare-and-set, so two exporters sharing a cursor name can't move it backwards.
        updated = self._db.execute(
            "UPDATE export_cursors SET seq = ?, hash = ?, updated_at = ?"
            " WHERE name = ? AND seq = ?",
            (seq, digest, now, self.name, previous),
        )
        if not updated:
            raise ExportError(
                f"cursor {self.name!r} was moved by another exporter; this batch may be duplicated"
            )
