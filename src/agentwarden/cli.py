"""Command-line interface: ``agentwarden <command>``."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any

from agentwarden import __version__
from agentwarden.config import DEFAULT_CORPUS_PATH, Settings
from agentwarden.errors import AgentWardenError, ConfigurationError


def _settings(args: argparse.Namespace) -> Settings:
    settings = Settings.from_env()
    if getattr(args, "db", None):
        settings = replace(settings, db_path=args.db)
    return settings


# ------------------------------------------------------------------------------ commands
def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from agentwarden.api import create_app

    settings = _settings(args)
    if settings.signing_key_path is None:
        print(
            "warning: no AGENTWARDEN_SIGNING_KEY_PATH set; using an ephemeral key "
            "(tokens will not survive a restart). Create one with: agentwarden keygen",
            file=sys.stderr,
        )
    if settings.admin_key is None:
        print("note: admin API disabled (set AGENTWARDEN_ADMIN_KEY to enable)", file=sys.stderr)
    if settings.otel_enabled:
        from agentwarden.telemetry import configure_otlp

        configure_otlp()
        print("OpenTelemetry: exporting traces and metrics over OTLP/HTTP", file=sys.stderr)
    uvicorn.run(create_app(settings=settings), host=args.host, port=args.port, log_level="info")
    return 0


def cmd_keygen(args: argparse.Namespace) -> int:
    from agentwarden.identity import KeyManager

    keys = KeyManager.generate()
    try:
        path = keys.save_pem(args.out)
    except FileExistsError:
        print(
            f"error: {args.out} already exists; refusing to overwrite a signing key",
            file=sys.stderr,
        )
        return 1
    print(f"wrote Ed25519 signing key to {path} (mode 0600)")
    print(f"kid: {keys.kid}")
    print(f"export AGENTWARDEN_SIGNING_KEY_PATH={path}")
    return 0


def _ring(args: argparse.Namespace) -> Any:
    from agentwarden.identity import KeyRing

    settings = Settings.from_env()
    directory = args.dir or settings.signing_key_dir
    if directory is None:
        raise ConfigurationError("give --dir or set AGENTWARDEN_SIGNING_KEY_DIR")
    return KeyRing.open(
        directory, grace_seconds=settings.key_grace_seconds, create=args.command_name == "rotate"
    )


def _print_keys(ring: Any) -> None:
    for entry in ring.entries():
        until = ""
        if entry.status == "retired" and entry.retired_at is not None:
            left = max(0, int(entry.retired_at + ring.grace_seconds - time.time()))
            until = f"  verifies tokens for {left}s more"
        print(f"{entry.status:<8} {entry.kid}{until}")


def cmd_keys(args: argparse.Namespace) -> int:
    from agentwarden.identity.keyring import MANIFEST

    directory = args.dir or Settings.from_env().signing_key_dir
    existed = directory is not None and (Path(directory) / MANIFEST).exists()
    ring = _ring(args)
    if args.command_name == "rotate":
        if existed:  # a brand-new ring was just created with its first key
            ring.rotate()
        print(f"active key is now {ring.kid}")
    elif args.command_name == "prune":
        pruned = ring.prune()
        print(f"pruned {len(pruned)} key(s)" + (": " + ", ".join(pruned) if pruned else ""))
    _print_keys(ring)
    return 0


def cmd_hash_key(args: argparse.Namespace) -> int:
    from agentwarden.directory import hash_api_key

    key = args.key if args.key is not None else getpass.getpass("API key: ")
    if len(key) < 12:
        print("error: API keys should be at least 12 characters", file=sys.stderr)
        return 1
    print(hash_api_key(key))
    return 0


def cmd_policy_validate(args: argparse.Namespace) -> int:
    from agentwarden.policy import CedarPolicy, PolicyEngine

    path = Path(args.file) if args.file else Settings.from_env().effective_policy_path
    if path.suffix == ".cedar":
        print(f"OK {path}: {CedarPolicy.from_file(path).rule_count} Cedar policies")
        return 0
    policy = PolicyEngine.from_file(path).policy
    counts = {
        e: sum(1 for r in policy.rules if r.effect.value == e)
        for e in ("allow", "deny", "require_approval")
    }
    breakdown = (
        f"{counts['allow']} allow, {counts['deny']} deny, {counts['require_approval']} approval"
    )
    print(f"OK {path}: {len(policy.rules)} rules ({breakdown})")
    return 0


def cmd_policy_test(args: argparse.Namespace) -> int:
    from agentwarden.policy.testing import run_suite

    failed = total = 0
    for suite in args.suites:
        results = run_suite(
            suite,
            policy_path=args.policy,
            backend=args.backend,
            opa_url=args.opa_url or os.environ.get("AGENTWARDEN_OPA_URL"),
        )
        print(f"{suite}")
        for result in results:
            total += 1
            mark = "PASS" if result.passed else "FAIL"
            line = f"  {mark}  {result.name}"
            if not result.passed:
                failed += 1
                line += (
                    f"  ({result.message}; matched: {', '.join(result.matched_rules) or 'none'})"
                )
            print(line)
    print(f"\n{total - failed}/{total} policy cases passed")
    return 1 if failed else 0


def cmd_audit_verify(args: argparse.Namespace) -> int:
    from agentwarden.audit import AuditLog
    from agentwarden.storage import Database

    db = Database(_settings(args).database)
    try:
        result = AuditLog(db).verify()
    finally:
        db.close()
    if result.ok:
        print(f"OK: {result.checked} entries, head {result.head_hash}")
        return 0
    print(f"TAMPERED: entry {result.first_bad_seq}: {result.reason}")
    print(f"({result.checked} entries verified before it)")
    return 1


def cmd_audit_export(args: argparse.Namespace) -> int:
    from agentwarden.audit import AuditIntegrityError, AuditLog
    from agentwarden.siem import AuditExporter, ExportError, open_sink
    from agentwarden.storage import Database

    db = Database(_settings(args).database)
    try:
        sink = open_sink(args.sink, token=os.environ.get("AGENTWARDEN_EXPORT_TOKEN"))
    except ValueError as exc:
        db.close()
        print(f"error: {exc}", file=sys.stderr)
        return 2
    exporter = AuditExporter(
        db, AuditLog(db), sink, name=args.cursor, fmt=args.format, batch_size=args.batch
    )
    try:
        if args.reset:
            exporter.reset(to_head=args.reset == "head")
        if args.follow:
            exporter.follow(args.interval)
            return 0
        sent = exporter.export_all()
        seq, _ = exporter.cursor()
        print(f"exported {sent} entries (cursor {args.cursor!r} at seq {seq})", file=sys.stderr)
        return 0
    except AuditIntegrityError as exc:
        print(f"TAMPERED: {exc}. Nothing after the last good entry was exported.", file=sys.stderr)
        return 1
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover - interactive
        return 0
    finally:
        sink.close()
        db.close()


def cmd_analyze(args: argparse.Namespace) -> int:
    from agentwarden.gateway import Gateway

    with Gateway.build(_settings(args)) as gateway:
        report = gateway.analyze(args.days)
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.to_markdown(), end="")
    return 0


def cmd_bench(args: argparse.Namespace) -> int:
    from agentwarden.benchmark import run_benchmark
    from agentwarden.errors import ConfigurationError

    try:
        report = run_benchmark(
            tracks=args.track or ("detection", "agent"),
            cache_dir=Path(args.cache_dir) if args.cache_dir else None,
            threshold=args.threshold,
            limit=args.limit,
            offline=args.offline,
            split=args.split,
        )
    except ConfigurationError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    markdown = report.to_markdown()
    if args.markdown:
        Path(args.markdown).write_text(markdown, encoding="utf-8")
    if args.json:
        Path(args.json).write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    if not args.quiet:
        print(markdown, end="")
    failures = report.check(
        min_recall=args.min_recall,
        max_fpr=args.max_fpr,
        max_asr=args.max_asr,
        min_utility=args.min_utility,
        max_false_alarms=args.max_false_alarms,
    )
    for failure in failures:
        print(f"GATE FAILED: {failure}", file=sys.stderr)
    return 1 if failures else 0


def cmd_eval(args: argparse.Namespace) -> int:
    from agentwarden.evaluation import evaluate, load_corpus
    from agentwarden.risk import InjectionDetector

    detectors: list[object] = [InjectionDetector()]
    if args.llm_judge:
        from agentwarden.risk.llm_judge import ClaudeInjectionJudge

        detectors.append(ClaudeInjectionJudge(model=Settings.from_env().llm_judge_model))
    report = evaluate(load_corpus(args.corpus), threshold=args.threshold, detectors=detectors)  # type: ignore[arg-type]
    summary = report.summary()
    if args.json:
        print(
            json.dumps(
                {"summary": summary, "results": [r.__dict__ for r in report.results]}, indent=2
            )
        )
    else:
        for r in report.results:
            if not r.correct:
                kind = "missed" if r.label == "malicious" else "false positive"
                print(f"  {kind:<15} {r.id}  (top: {r.top_signal or '-'} {r.top_weight:.2f})")
        metrics = "  ".join(f"{k}={summary[k]:.3f}" for k in ("precision", "recall", "fpr", "f1"))
        print(f"\n{summary['samples']} samples  {metrics}")
    ok = report.recall >= args.min_recall and report.fpr <= args.max_fpr
    if not ok:
        print(
            f"quality gate FAILED (min recall {args.min_recall}, max FPR {args.max_fpr})",
            file=sys.stderr,
        )
    return 0 if ok else 1


def cmd_mcp_proxy(args: argparse.Namespace) -> int:
    import asyncio
    import logging
    import os

    from agentwarden.mcp import McpProxy, ToolMapping, run_stdio_proxy
    from agentwarden.sdk import DpopKey, LocalWarden, WardenClient
    from agentwarden.sdk.client import _WardenBase

    # stdout carries the MCP protocol: every diagnostic goes to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.WARNING, format="agentwarden: %(message)s")
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("error: give the upstream MCP server command after '--'", file=sys.stderr)
        return 2
    mapping = ToolMapping.load(args.map) if args.map else ToolMapping()

    warden: _WardenBase
    gateway = None
    if args.local:
        from agentwarden.gateway import Gateway
        from agentwarden.models import TokenRequest

        if not args.agent or not args.scopes:
            print("error: --local needs --agent and --scopes", file=sys.stderr)
            return 2
        gateway = Gateway.build(_settings(args))
        user = gateway.directory.get_user(args.user)
        if user is None:
            gateway.close()
            print(f"error: unknown user {args.user!r}", file=sys.stderr)
            return 2
        try:
            # The local proxy binds its own token to a throwaway DPoP key (RFC 9449).
            dpop_key = DpopKey()
            issued = gateway.issue_token(
                user,
                TokenRequest(agent_id=args.agent, scopes=args.scopes, task=args.task),
                jkt=dpop_key.thumbprint,
            )
        except AgentWardenError:
            gateway.close()
            raise
        warden = LocalWarden(gateway, issued.access_token, dpop_key=dpop_key)
    else:
        token = os.environ.get("AGENTWARDEN_TOKEN")
        if not token:
            print("error: set AGENTWARDEN_TOKEN (the agent token) or use --local", file=sys.stderr)
            return 2
        key = DpopKey.load(args.dpop_key) if args.dpop_key else None
        warden = WardenClient(args.url, token, dpop_key=key)
    if args.user_prompt:
        warden.set_user_prompt(args.user_prompt)
    try:
        return asyncio.run(run_stdio_proxy(McpProxy(warden, mapping), command))
    finally:
        if gateway is not None:
            gateway.close()


def cmd_dpop(args: argparse.Namespace) -> int:
    from agentwarden.sdk import DpopKey

    if args.dpop_command == "keygen":
        key = DpopKey()
        try:
            key.save(args.out)
        except FileExistsError:
            print(f"error: {args.out} already exists; refusing to overwrite a key", file=sys.stderr)
            return 1
        print(f"wrote DPoP key (ES256) to {args.out} (mode 0600)")
        print(f"jkt: {key.thumbprint}")
        return 0
    print(DpopKey.load(args.key).thumbprint)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from agentwarden.demo import run_demo

    run_demo(color=False if args.no_color else None)
    return 0


def cmd_version(_: argparse.Namespace) -> int:
    print(f"agentwarden {__version__}")
    return 0


# ------------------------------------------------------------------------------ parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agentwarden", description="Identity & access management for AI agents."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("serve", help="run the HTTP API")
    p.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--db", help="SQLite path (overrides AGENTWARDEN_DB_PATH)")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("keygen", help="create an Ed25519 signing key")
    p.add_argument("--out", default="keys/signing-key.pem")
    p.set_defaults(func=cmd_keygen)

    keys = sub.add_parser("keys", help="signing-key ring: rotate, list, prune")
    keys_sub = keys.add_subparsers(dest="command_name", required=True)
    for name, text in (
        ("list", "show keys and their status"),
        ("rotate", "create a new active key (creates the ring if needed)"),
        ("prune", "delete private keys whose grace period is over"),
    ):
        p = keys_sub.add_parser(name, help=text)
        p.add_argument("--dir", help="key ring directory (default: AGENTWARDEN_SIGNING_KEY_DIR)")
        p.set_defaults(func=cmd_keys)

    p = sub.add_parser("hash-key", help="hash a user API key for directory.yaml")
    p.add_argument(
        "key", nargs="?", help="the key (prompted if omitted, keeping it out of shell history)"
    )
    p.set_defaults(func=cmd_hash_key)

    policy = sub.add_parser("policy", help="policy-as-code tools").add_subparsers(
        dest="policy_command", required=True
    )
    p = policy.add_parser("validate", help="validate a policy file")
    p.add_argument("file", nargs="?", help="policy .yaml or .cedar (default: configured policy)")
    p.set_defaults(func=cmd_policy_validate)
    p = policy.add_parser("test", help="run policy test suites")
    p.add_argument("suites", nargs="+")
    p.add_argument("--policy", help="policy file (overrides each suite's 'policy' key)")
    p.add_argument(
        "--backend",
        choices=["yaml", "cedar", "opa"],
        default="yaml",
        help="cedar: the .cedar file next to the suite's policy; opa: the server at --opa-url",
    )
    p.add_argument("--opa-url", help="OPA server for --backend opa (default AGENTWARDEN_OPA_URL)")
    p.set_defaults(func=cmd_policy_test)

    audit = sub.add_parser("audit", help="audit log tools").add_subparsers(
        dest="audit_command", required=True
    )
    p = audit.add_parser("verify", help="verify the audit hash chain")
    p.add_argument("--db", help="SQLite path (overrides AGENTWARDEN_DB_PATH)")
    p.set_defaults(func=cmd_audit_verify)
    p = audit.add_parser("export", help="export the audit log to a SIEM (OCSF or native JSON)")
    p.add_argument(
        "--sink",
        default="-",
        help="'-' for stdout, a file path, or an http(s) URL (token: AGENTWARDEN_EXPORT_TOKEN)",
    )
    p.add_argument("--format", choices=["ocsf", "native"], default="ocsf")
    p.add_argument("--cursor", default="default", help="cursor name (one per destination)")
    p.add_argument("--batch", type=int, default=500)
    p.add_argument("--follow", action="store_true", help="keep exporting new entries")
    p.add_argument("--interval", type=float, default=5.0, help="seconds between polls (--follow)")
    p.add_argument(
        "--reset", choices=["start", "head"], help="restart from the beginning or from now"
    )
    p.add_argument("--db", help="SQLite path (overrides AGENTWARDEN_DB_PATH)")
    p.set_defaults(func=cmd_audit_export)

    p = sub.add_parser("analyze", help="least-privilege report from the audit log")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--db", help="SQLite path (overrides AGENTWARDEN_DB_PATH)")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser(
        "bench", help="benchmark against public prompt-injection datasets (BIPIA, InjecAgent)"
    )
    p.add_argument(
        "--track",
        action="append",
        choices=["detection", "agent"],
        help="repeatable (default: both)",
    )
    p.add_argument("--threshold", type=float, default=0.3, help="detector flag threshold")
    p.add_argument("--limit", type=int, help="use only the first N cases of each dataset file")
    p.add_argument(
        "--split",
        choices=["all", "dev", "test"],
        default="all",
        help="dev: for developing detectors; test: held out; all: the reported numbers",
    )
    p.add_argument("--cache-dir", help="dataset cache (default ~/.cache/agentwarden/benchmarks)")
    p.add_argument("--offline", action="store_true", help="use cached datasets only")
    p.add_argument("--markdown", help="also write the Markdown report here")
    p.add_argument("--json", help="also write the JSON report here")
    p.add_argument("--quiet", action="store_true", help="don't print the report")
    p.add_argument("--min-recall", type=float, help="gate: overall detection recall")
    p.add_argument("--max-fpr", type=float, help="gate: false-positive rate on benign documents")
    p.add_argument("--max-asr", type=float, help="gate: agent-track attack success rate")
    p.add_argument("--min-utility", type=float, help="gate: agent-track utility")
    p.add_argument(
        "--max-false-alarms", type=float, help="gate: risk-engine flags on benign user actions"
    )
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("eval", help="evaluate injection detection on a labeled corpus")
    p.add_argument("--corpus", default=str(DEFAULT_CORPUS_PATH))
    p.add_argument("--threshold", type=float, default=0.3)
    p.add_argument("--min-recall", type=float, default=0.9)
    p.add_argument("--max-fpr", type=float, default=0.1)
    p.add_argument(
        "--llm-judge", action="store_true", help="also run the Claude judge (needs API access)"
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser(
        "mcp-proxy",
        help="enforce AgentWarden on a stdio MCP server",
        description="Run an MCP server behind AgentWarden: mcp-proxy [options] -- CMD...",
    )
    p.add_argument("--url", default="http://127.0.0.1:8000", help="AgentWarden service URL")
    p.add_argument("--map", help="YAML mapping of MCP tool names to AgentWarden tools")
    p.add_argument("--user-prompt", help="the user's request, for taint tracking")
    p.add_argument("--local", action="store_true", help="in-process gateway (demos and tests)")
    p.add_argument("--user", default="alice", help="--local: user who delegates to the agent")
    p.add_argument("--agent", help="--local: agent id")
    p.add_argument("--scopes", nargs="+", help="--local: scopes to request")
    p.add_argument("--task", help="--local: task recorded in the token")
    p.add_argument("--db", help="--local: SQLite path (overrides AGENTWARDEN_DB_PATH)")
    p.add_argument("--dpop-key", help="PEM key the agent token is DPoP-bound to (remote mode)")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- upstream server command")
    p.set_defaults(func=cmd_mcp_proxy)

    dpop = sub.add_parser("dpop", help="agent DPoP keys (RFC 9449)").add_subparsers(
        dest="dpop_command", required=True
    )
    p = dpop.add_parser("keygen", help="create an agent DPoP key (ES256)")
    p.add_argument("--out", default="agent-dpop.pem")
    p.set_defaults(func=cmd_dpop)
    p = dpop.add_parser("thumbprint", help="print a key's RFC 7638 thumbprint (jkt)")
    p.add_argument("key")
    p.set_defaults(func=cmd_dpop)

    p = sub.add_parser("demo", help="run the scripted end-to-end attack demo")
    p.add_argument("--no-color", action="store_true")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("version", help="print the version")
    p.set_defaults(func=cmd_version)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        code: int = args.func(args)
    except AgentWardenError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
