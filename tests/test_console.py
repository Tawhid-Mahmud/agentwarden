"""Approver console: served assets, security properties, and the data it relies on."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Iterator
from importlib import resources
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import agentwarden.risk as risk_package
from agentwarden.api import create_app
from agentwarden.config import Settings
from agentwarden.gateway import Gateway
from agentwarden.models import AuthorizeRequest, ContextSegment, TokenRequest
from agentwarden.storage import Database
from tests.conftest import FakeClock

CONSOLE = resources.files("agentwarden.api") / "console"
AWS_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"


@pytest.fixture
def gw(settings: Settings, clock: FakeClock) -> Iterator[Gateway]:
    with Gateway.build(settings, clock=clock) as gateway:
        yield gateway


@pytest.fixture
def client(gw: Gateway) -> TestClient:
    return TestClient(create_app(gw))


@pytest.mark.parametrize(
    ("path", "media"),
    [
        ("/console", "text/html"),
        ("/console/app.js", "text/javascript"),
        ("/console/app.css", "text/css"),
    ],
)
def test_assets_are_served_with_a_strict_csp(client: TestClient, path: str, media: str) -> None:
    response = client.get(path)
    assert response.status_code == 200 and response.headers["content-type"].startswith(media)
    csp = response.headers["content-security-policy"]
    assert (
        "default-src 'none'" in csp
        and "script-src 'self'" in csp
        and "frame-ancestors 'none'" in csp
    )
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert client.get("/console/", follow_redirects=False).headers["location"] == "/console"


def test_console_never_parses_data_as_html() -> None:
    script = (CONSOLE / "app.js").read_text(encoding="utf-8")
    for dangerous in (
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ):
        assert dangerous not in script, dangerous
    page = (CONSOLE / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)", page), "inline <script> would break the CSP"
    assert "style=" not in page and "on" + "click=" not in page


def test_whoami(client: TestClient) -> None:
    bob = client.get("/v1/me", headers={"X-API-Key": "bob-demo-key"}).json()
    assert bob == {
        "id": "bob",
        "name": "Bob Okafor",
        "email": "bob@acme.example",
        "roles": ["employee", "approver", "security"],
        "approver": True,
    }
    assert client.get("/v1/me", headers={"X-API-Key": "alice-demo-key"}).json()["approver"] is False
    assert client.get("/v1/me").status_code == 401


def test_approvals_carry_review_details(client: TestClient, gw: Gateway) -> None:
    token = gw.issue_token(
        gw.directory.users["alice"],
        TokenRequest(agent_id="inbox-assistant", scopes=["email:send"], task="triage"),
    ).access_token
    gw.authorize(
        token,
        AuthorizeRequest(
            tool="send_email",
            args={"to": ["dana@vendor.example"], "body": "Received, thanks"},
            user_prompt=f"Reply to Dana (my key is {AWS_KEY})",
            context=[ContextSegment(source="email:7", content="From: dana@vendor.example")],
        ),
    )
    [approval] = client.get(
        "/v1/approvals?status=pending", headers={"X-API-Key": "bob-demo-key"}
    ).json()
    details = approval["details"]
    assert details["actor_chain"] == ["inbox-assistant"] and details["task"] == "triage"
    assert details["context_sources"] == ["email:7"]
    assert {s["name"] for s in details["signals"]} >= {
        "tainted_external_destination",
        "external_recipient",
    }
    assert details["risk_level"] in {"medium", "high", "critical"}
    assert AWS_KEY not in str(approval)  # redacted everywhere, including the user's prompt
    assert "Reply to Dana" in details["user_prompt"]
    assert (
        len(client.get("/v1/approvals?limit=1", headers={"X-API-Key": "bob-demo-key"}).json()) == 1
    )


def test_old_databases_gain_the_details_column(tmp_path: Path) -> None:
    path = tmp_path / "v01.db"
    legacy = sqlite3.connect(path)
    legacy.execute(
        "CREATE TABLE approvals (id TEXT PRIMARY KEY, decision_id TEXT NOT NULL, status TEXT NOT NULL,"
        " user_id TEXT NOT NULL, agent_id TEXT NOT NULL, tool TEXT NOT NULL, call_hash TEXT NOT NULL,"
        " args_preview TEXT NOT NULL, reasons TEXT NOT NULL, risk_score REAL NOT NULL,"
        " created_at REAL NOT NULL, expires_at REAL NOT NULL, reviewer TEXT, reviewed_at REAL,"
        " note TEXT NOT NULL DEFAULT '')"
    )
    legacy.execute(
        "INSERT INTO approvals VALUES ('apr_old','d','pending','alice','bot','t','h','{}','[]',0.3,1,2,NULL,NULL,'')"
    )
    legacy.commit()
    legacy.close()
    db = Database(str(path))
    from agentwarden.approvals import ApprovalQueue

    assert ApprovalQueue(db).get("apr_old").details == {}
    Database(str(path)).close()  # running the migration again is harmless
    db.close()


def test_every_risk_signal_has_a_plain_language_label() -> None:
    """Reviewers see signals in plain words; a new detector signal needs a label in app.js."""
    source = "\n".join(
        p.read_text(encoding="utf-8") for p in Path(risk_package.__file__).parent.glob("*.py")
    )
    names = set(re.findall(r'name="([a-z_]+)"', source))
    names |= set(re.findall(r'emit\(\s*"([a-z_]+)"', source))
    names |= set(re.findall(r'_p\(\s*"([a-z_]+)"', source))
    names |= set(re.findall(r'^\s+"([a-z_]+)",\n\s+0\.\d', source, re.M))  # _p("x",\n 0.6 ...)
    names -= {"injection", "provenance", "taint", "secrets", "exfiltration", "anomaly", "llm_judge"}
    script = (CONSOLE / "app.js").read_text(encoding="utf-8")
    labels = set(re.findall(r"^\s+([a-z_]+): \"", script, re.M))
    assert len(names) >= 25, names
    assert names <= labels, f"signals without a console label: {sorted(names - labels)}"
