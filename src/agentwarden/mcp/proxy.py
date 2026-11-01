"""MCP proxy mode: put AgentWarden in front of any stdio MCP server.

The proxy speaks the Model Context Protocol on both sides. The agent (MCP client) launches the
proxy instead of the real server; the proxy launches the real server as a subprocess and relays
newline-delimited JSON-RPC messages in both directions, with three interventions:

* ``tools/call`` requests are authorized first. Allowed calls are forwarded unchanged. Denied
  calls and calls awaiting approval are answered by the proxy itself with an MCP tool error
  (``isError: true``) that explains why, so the model sees the reason and the server never runs.
* Results of forwarded tool calls are recorded as **untrusted context**, so later calls are
  checked against what the agent actually read (taint tracking, injection detection).
* ``tools/list`` responses can hide tools that have no AgentWarden mapping.

Approvals need no client support: when a call requires approval, the proxy remembers the
approval id for that exact call. Once a human approves it, the agent simply retries the same call.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from agentwarden.errors import AgentWardenError, ConfigurationError
from agentwarden.models import Decision
from agentwarden.sdk.client import _WardenBase

log = logging.getLogger(__name__)

#: Optional key in ``tools/call`` params ``_meta`` carrying the user's request, for taint tracking.
USER_PROMPT_META_KEY = "agentwarden/userPrompt"


class ToolMapping(BaseModel):
    """How MCP tool names map onto AgentWarden directory tools."""

    model_config = ConfigDict(extra="forbid")

    #: MCP tool name -> AgentWarden tool name. Unmapped tools keep their own name, and the
    #: gateway denies names it doesn't know (default deny).
    tools: dict[str, str] = Field(default_factory=dict)
    #: Remove unmapped tools from ``tools/list`` so the model never sees them.
    hide_unmapped: bool = False

    @classmethod
    def load(cls, path: str | Path) -> ToolMapping:
        try:
            return cls.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
        except FileNotFoundError as exc:
            raise ConfigurationError(f"MCP tool mapping not found: {path}") from exc
        except (yaml.YAMLError, ValidationError) as exc:
            raise ConfigurationError(f"invalid MCP tool mapping {path}: {exc}") from exc

    def resolve(self, mcp_name: str) -> str:
        return self.tools.get(mcp_name, mcp_name)


@dataclass(frozen=True)
class Route:
    """Where a message goes. ``message=None`` means "forward the original line unchanged"."""

    to: Literal["upstream", "client"]
    message: dict[str, Any] | None = None


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _id_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True)


def _call_fingerprint(tool: str, args: Mapping[str, Any]) -> str:
    material = json.dumps({"tool": tool, "args": args}, sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def tool_error(request_id: Any, text: str) -> dict[str, Any]:
    """An MCP tool result flagged as an error, which the model reads like any tool output."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {"content": [{"type": "text", "text": text}], "isError": True},
    }


def result_text(result: Any) -> str:
    """Flatten an MCP ``CallToolResult`` into text for provenance tracking."""
    if not isinstance(result, Mapping):
        return json.dumps(result, ensure_ascii=False, default=str)
    parts: list[str] = []
    for item in result.get("content") or []:
        if isinstance(item, Mapping):
            if isinstance(item.get("text"), str):
                parts.append(item["text"])
            elif isinstance(item.get("resource"), Mapping) and isinstance(
                item["resource"].get("text"), str
            ):
                parts.append(item["resource"]["text"])
    if result.get("structuredContent") is not None:
        parts.append(json.dumps(result["structuredContent"], ensure_ascii=False, default=str))
    return "\n".join(parts)


@dataclass
class McpProxy:
    """Protocol logic, independent of transport (and therefore easy to test)."""

    warden: _WardenBase
    mapping: ToolMapping = field(default_factory=ToolMapping)
    _pending_calls: dict[str, str] = field(default_factory=dict)
    _pending_lists: set[str] = field(default_factory=set)
    _approvals: dict[str, str] = field(default_factory=dict)

    def from_client(self, message: dict[str, Any]) -> Route:
        method = message.get("method")
        if method == "tools/call" and "id" in message:
            return self._authorize_call(message)
        if method == "tools/list" and "id" in message:
            self._pending_lists.add(_id_key(message["id"]))
        return Route("upstream")

    def from_upstream(self, message: dict[str, Any]) -> Route:
        if "method" in message or "id" not in message:
            return Route("client")  # server requests/notifications pass through
        key = _id_key(message["id"])
        if key in self._pending_calls:
            name = self._pending_calls.pop(key)
            if "result" in message:
                text = result_text(message["result"])
                if text:
                    self.warden.observe(f"mcp:{name}", text)
        elif key in self._pending_lists:
            self._pending_lists.discard(key)
            if self.mapping.hide_unmapped and isinstance(message.get("result"), dict):
                tools = message["result"].get("tools")
                if isinstance(tools, list):
                    visible = [
                        t
                        for t in tools
                        if isinstance(t, dict) and t.get("name") in self.mapping.tools
                    ]
                    return Route(
                        "client", {**message, "result": {**message["result"], "tools": visible}}
                    )
        return Route("client")

    def _authorize_call(self, message: dict[str, Any]) -> Route:
        request_id = message["id"]
        params = _as_dict(message.get("params"))
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return Route(
                "client", tool_error(request_id, "AgentWarden: tools/call without a tool name")
            )
        args = _as_dict(params.get("arguments"))
        meta = _as_dict(params.get("_meta"))
        if isinstance(meta.get(USER_PROMPT_META_KEY), str):
            self.warden.set_user_prompt(meta[USER_PROMPT_META_KEY])

        tool = self.mapping.resolve(name)
        fingerprint = _call_fingerprint(tool, args)
        try:
            result = self.warden.authorize(tool, args, approval_id=self._approvals.get(fingerprint))
        except AgentWardenError as exc:
            log.warning("authorization failed for %s: %s", name, exc)
            return Route(
                "client", tool_error(request_id, f"AgentWarden could not authorize {name!r}: {exc}")
            )

        if result.decision is Decision.ALLOW:
            self._approvals.pop(fingerprint, None)
            self._pending_calls[_id_key(request_id)] = name
            return Route("upstream")
        if result.decision is Decision.REQUIRE_APPROVAL and result.approval_id:
            self._approvals[fingerprint] = result.approval_id
            return Route(
                "client",
                tool_error(
                    request_id,
                    f"AgentWarden: {name!r} needs human approval "
                    f"(approval id {result.approval_id}). Do not try a different action. Tell the "
                    "user an approval is pending; once it is approved, call this tool again with "
                    "exactly the same arguments.\n"
                    f"Why: {'; '.join(result.reasons)}",
                ),
            )
        self._approvals.pop(fingerprint, None)
        signals = ", ".join(s.name for s in result.risk.signals[:5]) or "none"  # strongest first
        return Route(
            "client",
            tool_error(
                request_id,
                f"AgentWarden denied {name!r} (decision {result.decision_id}). Do not retry or "
                f"work around this.\nWhy: {'; '.join(result.reasons)}\nRisk signals: {signals}",
            ),
        )


# ------------------------------------------------------------------------------ stdio runner
def _parse(line: bytes) -> dict[str, Any] | None:
    try:
        message = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return message if isinstance(message, dict) else None


def _encode(message: dict[str, Any]) -> bytes:
    return (json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


async def run_stdio_proxy(proxy: McpProxy, command: list[str]) -> int:
    """Relay MCP stdio between our stdin/stdout and the upstream server ``command``."""
    if not command:
        raise ConfigurationError("no upstream MCP server command given")
    upstream = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        limit=16 * 1024 * 1024,
    )
    if upstream.stdin is None or upstream.stdout is None:  # pragma: no cover - PIPE always set
        raise RuntimeError("failed to open pipes to the upstream MCP server")
    up_in, up_out = upstream.stdin, upstream.stdout
    loop = asyncio.get_running_loop()
    client_in = asyncio.StreamReader(limit=16 * 1024 * 1024)
    await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(client_in), sys.stdin)
    out_lock = asyncio.Lock()

    async def to_client(data: bytes) -> None:
        async with out_lock:
            sys.stdout.buffer.write(data if data.endswith(b"\n") else data + b"\n")
            sys.stdout.buffer.flush()

    async def client_to_upstream() -> None:
        while line := await client_in.readline():
            message = _parse(line)
            route = (
                await asyncio.to_thread(proxy.from_client, message)
                if message
                else Route("upstream")
            )
            if route.to == "upstream":
                up_in.write(line if route.message is None else _encode(route.message))
                await up_in.drain()
            else:
                await to_client(_encode(route.message) if route.message else line)
        up_in.close()

    async def upstream_to_client() -> None:
        while line := await up_out.readline():
            message = _parse(line)
            route = (
                await asyncio.to_thread(proxy.from_upstream, message)
                if message
                else Route("client")
            )
            await to_client(line if route.message is None else _encode(route.message))

    reader = asyncio.create_task(upstream_to_client())
    await client_to_upstream()
    await reader
    return await upstream.wait()
