"""Prompt-injection benchmark against public datasets (``agentwarden bench``).

See ``docs/BENCHMARK.md`` for the method and the latest results.
"""

from agentwarden.benchmark.report import TRACKS, BenchmarkReport, run_benchmark
from agentwarden.benchmark.suites import (
    AgentCase,
    TextSample,
    bipia_samples,
    injecagent_cases,
    insert_attack,
    run_agent,
    run_detection,
)

__all__ = [
    "TRACKS",
    "AgentCase",
    "BenchmarkReport",
    "TextSample",
    "bipia_samples",
    "injecagent_cases",
    "insert_attack",
    "run_agent",
    "run_benchmark",
    "run_detection",
]
