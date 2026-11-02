"""OpenTelemetry: spans and metrics per decision, linked to the audit log, without sensitive data."""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import ReadableSpan, TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from agentwarden.config import Settings
from agentwarden.errors import AuthenticationError, DelegationError
from agentwarden.gateway import Gateway
from agentwarden.models import AuthorizeRequest, DelegationRequest, TokenRequest
from agentwarden.telemetry import Telemetry, available
from tests.conftest import FakeClock

SECRET_ARG = "very-private-body-text"


class Otel:
    def __init__(self) -> None:
        self.spans = InMemorySpanExporter()
        self.tracer_provider = TracerProvider()
        self.tracer_provider.add_span_processor(SimpleSpanProcessor(self.spans))
        self.metrics = InMemoryMetricReader()
        self.meter_provider = MeterProvider(metric_readers=[self.metrics])

    def finished(self, name: str) -> list[ReadableSpan]:
        return [s for s in self.spans.get_finished_spans() if s.name == name]

    def points(self, metric: str) -> list[Any]:
        data = self.metrics.get_metrics_data()
        assert data is not None
        return [
            point
            for resource in data.resource_metrics
            for scope in resource.scope_metrics
            for m in scope.metrics
            if m.name == metric
            for point in m.data.data_points
        ]


@pytest.fixture
def otel() -> Iterator[Otel]:
    o = Otel()
    yield o
    o.tracer_provider.shutdown()
    o.meter_provider.shutdown()


@pytest.fixture
def gw(settings: Settings, clock: FakeClock, otel: Otel) -> Iterator[Gateway]:
    telemetry = Telemetry(otel.tracer_provider, otel.meter_provider)
    with Gateway.build(settings, clock=clock, telemetry=telemetry) as gateway:
        yield gateway


def token_for(gw: Gateway, scopes: list[str]) -> str:
    return gw.issue_token(
        gw.directory.users["alice"], TokenRequest(agent_id="inbox-assistant", scopes=scopes)
    ).access_token


def test_otel_is_available_in_the_dev_environment() -> None:
    assert available()


def test_authorize_emits_a_span_tree_linked_to_the_audit_entry(gw: Gateway, otel: Otel) -> None:
    token = token_for(gw, ["email:read", "email:send"])
    result = gw.authorize(
        token,
        AuthorizeRequest(
            tool="send_email",
            args={"to": ["dana@vendor.example"], "body": SECRET_ARG},
            user_prompt="mail dana",
        ),
    )
    [root] = otel.finished("agentwarden.authorize")
    attrs = dict(root.attributes or {})
    assert attrs["agentwarden.tool"] == "send_email"
    assert attrs["agentwarden.agent_id"] == "inbox-assistant"
    assert attrs["agentwarden.decision"] == result.decision.value
    assert attrs["agentwarden.decision_id"] == result.decision_id
    assert attrs["agentwarden.risk.level"] == result.risk.level.value
    assert tuple(attrs["agentwarden.policy.rules"]) == tuple(result.matched_rules)
    for child in ("agentwarden.risk", "agentwarden.policy"):
        [span] = otel.finished(child)
        assert span.parent is not None and span.parent.span_id == root.context.span_id

    [entry] = gw.audit.query(event_type="authz.decision", limit=1)
    assert entry.data["trace_id"] == f"{root.context.trace_id:032x}"
    everything = json.dumps([dict(s.attributes or {}) for s in otel.spans.get_finished_spans()])
    assert SECRET_ARG not in everything and "alice" not in everything and "dana" not in everything


def test_decision_metrics(gw: Gateway, otel: Otel) -> None:
    token = token_for(gw, ["email:read"])
    for _ in range(3):
        gw.authorize(token, AuthorizeRequest(tool="read_inbox"))
    gw.authorize(token, AuthorizeRequest(tool="transfer_funds"))
    counts = {
        (p.attributes["agentwarden.tool"], p.attributes["agentwarden.decision"]): p.value
        for p in otel.points("agentwarden.decisions")
    }
    assert counts == {("read_inbox", "allow"): 3, ("transfer_funds", "deny"): 1}
    [hist] = [
        p
        for p in otel.points("agentwarden.authorize.duration")
        if p.attributes["agentwarden.tool"] == "read_inbox"
    ]
    assert hist.count == 3


def test_failures_mark_the_span_as_an_error(gw: Gateway, otel: Otel) -> None:
    with pytest.raises(AuthenticationError):
        gw.authorize("garbage", AuthorizeRequest(tool="read_inbox"))
    [span] = otel.finished("agentwarden.authorize")
    assert span.status.status_code is StatusCode.ERROR
    assert dict(span.attributes or {})["error.type"] == "AuthenticationError"
    [entry] = gw.audit.query(event_type="auth.failed", limit=1)
    assert entry  # still audited


def test_token_spans_and_metrics(gw: Gateway, otel: Otel) -> None:
    token = token_for(gw, ["email:read", "docs:read"])
    gw.delegate_token(token, DelegationRequest(sub_agent_id="summarizer", scopes=["email:read"]))
    with pytest.raises(DelegationError):
        gw.delegate_token(
            token, DelegationRequest(sub_agent_id="summarizer", scopes=["email:send"])
        )
    [issue] = otel.finished("agentwarden.token.issue")
    assert dict(issue.attributes or {})["agentwarden.dpop"] is False
    ok, failed = otel.finished("agentwarden.token.delegate")
    assert dict(ok.attributes or {})["agentwarden.delegation_depth"] == 1
    assert failed.status.status_code is StatusCode.ERROR
    outcomes = {
        (p.attributes["agentwarden.operation"], p.attributes["agentwarden.outcome"]): p.value
        for p in otel.points("agentwarden.tokens")
    }
    assert outcomes == {
        ("issue", "issued"): 1,
        ("delegate", "issued"): 1,
        ("delegate", "denied"): 1,
    }


def test_default_gateway_uses_the_global_providers(settings: Settings) -> None:
    with Gateway.build(settings) as gateway:  # no SDK configured: the API's no-op providers
        token = token_for(gateway, ["email:read"])
        assert (
            gateway.authorize(token, AuthorizeRequest(tool="read_inbox")).decision.value == "allow"
        )
        [entry] = gateway.audit.query(event_type="authz.decision", limit=1)
        assert entry.data["trace_id"] is None


def test_otel_setting() -> None:
    assert Settings.from_env({"AGENTWARDEN_OTEL": "true"}).otel_enabled
    assert not Settings.from_env({}).otel_enabled
