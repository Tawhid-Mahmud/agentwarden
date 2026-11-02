"""Public prompt-injection datasets, pinned to exact commits and verified by SHA-256.

Datasets are downloaded on first use into a local cache (``$AGENTWARDEN_CACHE_DIR`` or
``~/.cache/agentwarden/benchmarks``) and never shipped with AgentWarden. InjecAgent's repository
has no license file, so it is only fetched for local evaluation; respect its authors' terms.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from agentwarden.errors import ConfigurationError


@dataclass(frozen=True)
class Source:
    name: str
    repo: str
    commit: str
    license: str
    citation: str

    @property
    def homepage(self) -> str:
        return f"https://github.com/{self.repo}"


@dataclass(frozen=True)
class DatasetFile:
    source: Source
    path: str
    sha256: str

    @property
    def url(self) -> str:
        return (
            f"https://raw.githubusercontent.com/{self.source.repo}/{self.source.commit}/{self.path}"
        )

    @property
    def cache_name(self) -> str:
        return f"{self.source.repo.replace('/', '__')}__{self.sha256[:12]}__{Path(self.path).name}"


BIPIA = Source(
    name="BIPIA",
    repo="microsoft/BIPIA",
    commit="a004b69ec0dd446e0afd461d98cb5e96e120a5d0",
    license="MIT",
    citation=(
        "Yi et al., Benchmarking and Defending Against Indirect Prompt Injection Attacks on "
        "Large Language Models (2023)"
    ),
)
INJECAGENT = Source(
    name="InjecAgent",
    repo="uiuc-kang-lab/InjecAgent",
    commit="f19c9f2c79a41046eb13c03c51a24c567a8ffa07",
    license="no license file in the repository: fetched for local evaluation only",
    citation=(
        "Zhan et al., InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated "
        "Large Language Model Agents (ACL Findings 2024)"
    ),
)

FILES: dict[str, DatasetFile] = {
    "bipia/email": DatasetFile(
        BIPIA,
        "benchmark/email/test.jsonl",
        "217b403faaa1d0cb12c24892bea39f4a0b9e2819919ac7e2b902006e28278cdb",
    ),
    "bipia/table": DatasetFile(
        BIPIA,
        "benchmark/table/test.jsonl",
        "3d5eaab192b80bada762e3cd7655583a14e5888ba8b845a01f0434e4ccc4291e",
    ),
    "bipia/code": DatasetFile(
        BIPIA,
        "benchmark/code/test.jsonl",
        "ed40b84f541352fb45753032a80750922de8d5e0b70997924df3d04cf942e058",
    ),
    "bipia/text_attacks": DatasetFile(
        BIPIA,
        "benchmark/text_attack_test.json",
        "75750e7b4e8b34e8f9d88d89b357aeaaf02bd07f9e493ccd37eda74a0cd7c7f8",
    ),
    "bipia/code_attacks": DatasetFile(
        BIPIA,
        "benchmark/code_attack_test.json",
        "892545c5aaec0645b1ded65dc7816b3d70e9ef4eadcba2301a7a3db93676b6e0",
    ),
    "injecagent/dh_base": DatasetFile(
        INJECAGENT,
        "data/test_cases_dh_base.json",
        "0a8186468d21389af432e8c7b399ae42264d1b93a07b65c7a489468508604305",
    ),
    "injecagent/ds_base": DatasetFile(
        INJECAGENT,
        "data/test_cases_ds_base.json",
        "4daab35c62a3845e8b9400f4dca58b9c9f37e57cd33b2337552557fbb26282e9",
    ),
    "injecagent/dh_enhanced": DatasetFile(
        INJECAGENT,
        "data/test_cases_dh_enhanced.json",
        "885602716b72c18af80695ce6c2e1f242fa03163bc90b0788b0c5e4ab6216d50",
    ),
    "injecagent/ds_enhanced": DatasetFile(
        INJECAGENT,
        "data/test_cases_ds_enhanced.json",
        "7bc510868df032511053fc40e8470e68a041fb7148d055112093594bf73ab0ce",
    ),
}


def default_cache_dir() -> Path:
    configured = os.environ.get("AGENTWARDEN_CACHE_DIR")
    base = Path(configured) if configured else Path.home() / ".cache" / "agentwarden"
    return base / "benchmarks"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(
    key: str,
    cache_dir: Path | None = None,
    *,
    client: httpx.Client | None = None,
    offline: bool = False,
) -> Path:
    """Path to the verified local copy of dataset file ``key``, downloading it if needed."""
    spec = FILES[key]
    target = (cache_dir or default_cache_dir()) / spec.cache_name
    if target.exists() and _sha256(target.read_bytes()) == spec.sha256:
        return target
    if offline:
        raise ConfigurationError(f"{key} is not in the cache ({target}) and --offline is set")
    owned = client is None
    http = client or httpx.Client(timeout=60, follow_redirects=False)
    try:
        response = http.get(spec.url)
    except httpx.HTTPError as exc:
        raise ConfigurationError(f"could not download {spec.url}: {exc}") from exc
    finally:
        if owned:
            http.close()
    if response.status_code != 200:
        raise ConfigurationError(f"could not download {spec.url}: HTTP {response.status_code}")
    digest = _sha256(response.content)
    if digest != spec.sha256:
        raise ConfigurationError(
            f"{spec.url} has SHA-256 {digest}, expected {spec.sha256}; refusing to use it"
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    partial = target.with_suffix(".partial")
    partial.write_bytes(response.content)
    partial.replace(target)
    return target


def load_json(key: str, cache_dir: Path | None = None, **kwargs: Any) -> Any:
    return json.loads(fetch(key, cache_dir, **kwargs).read_text(encoding="utf-8"))


def load_jsonl(key: str, cache_dir: Path | None = None, **kwargs: Any) -> list[Any]:
    text = fetch(key, cache_dir, **kwargs).read_text(encoding="utf-8")
    return [json.loads(line) for line in text.splitlines() if line.strip()]
