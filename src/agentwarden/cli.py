"""Command-line interface: ``agentwarden <command>``."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path

from agentwarden import __version__
from agentwarden.config import DEFAULT_CORPUS_PATH, Settings
from agentwarden.errors import AgentWardenError


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


def cmd_hash_key(args: argparse.Namespace) -> int:
    from agentwarden.directory import hash_api_key

    key = args.key if args.key is not None else getpass.getpass("API key: ")
    if len(key) < 12:
        print("error: API keys should be at least 12 characters", file=sys.stderr)
        return 1
    print(hash_api_key(key))
    return 0


def cmd_policy_validate(args: argparse.Namespace) -> int:
    from agentwarden.policy import PolicyEngine

    path = Path(args.file) if args.file else Settings.from_env().policy_path
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
        results = run_suite(suite, policy_path=args.policy)
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

    db = Database(_settings(args).db_path)
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


def cmd_analyze(args: argparse.Namespace) -> int:
    from agentwarden.gateway import Gateway

    with Gateway.build(_settings(args)) as gateway:
        report = gateway.analyze(args.days)
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(report.to_markdown(), end="")
    return 0


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

    p = sub.add_parser("hash-key", help="hash a user API key for directory.yaml")
    p.add_argument(
        "key", nargs="?", help="the key (prompted if omitted, keeping it out of shell history)"
    )
    p.set_defaults(func=cmd_hash_key)

    policy = sub.add_parser("policy", help="policy-as-code tools").add_subparsers(
        dest="policy_command", required=True
    )
    p = policy.add_parser("validate", help="validate a policy file")
    p.add_argument("file", nargs="?", help="policy YAML (default: configured policy)")
    p.set_defaults(func=cmd_policy_validate)
    p = policy.add_parser("test", help="run policy test suites")
    p.add_argument("suites", nargs="+")
    p.add_argument("--policy", help="policy file (overrides each suite's 'policy' key)")
    p.set_defaults(func=cmd_policy_test)

    audit = sub.add_parser("audit", help="audit log tools").add_subparsers(
        dest="audit_command", required=True
    )
    p = audit.add_parser("verify", help="verify the audit hash chain")
    p.add_argument("--db", help="SQLite path (overrides AGENTWARDEN_DB_PATH)")
    p.set_defaults(func=cmd_audit_verify)

    p = sub.add_parser("analyze", help="least-privilege report from the audit log")
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("--db", help="SQLite path (overrides AGENTWARDEN_DB_PATH)")
    p.set_defaults(func=cmd_analyze)

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
