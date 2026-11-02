"""OpenTelemetry traces and metrics for AgentWarden's decisions.

Only the OpenTelemetry *API* is used here, and only if it is installed; without it every call
is a no-op. Spans and metrics go wherever the process's tracer and meter providers send them:
set them up yourself, run under ``opentelemetry-instrument``, or set ``AGENTWARDEN_OTEL=true``
with ``pip install 'agentwarden[otel]'`` to have :func:`configure_otlp` export over OTLP/HTTP
(endpoint and headers from the standard ``OTEL_EXPORTER_OTLP_*`` variables).

Attributes never include user IDs, tool arguments, prompts or context: traces often leave the
security boundary that the audit log stays inside. The ``agentwarden.decision_id`` attribute
links a span to its audit entry, and the audit entry records the ``trace_id``.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import Iterator, Mapping
from typing import Any

from agentwarden import __version__

try:  # pragma: no branch - depends on the environment
    from opentelemetry import metrics as _otel_metrics
    from opentelemetry import trace as _otel_trace
    from opentelemetry.trace import Status, StatusCode
except ImportError:  # pragma: no cover - exercised only without the otel extra
    _otel_trace = None  # type: ignore[assignment]
    _otel_metrics = None  # type: ignore[assignment]

INSTRUMENTATION = "agentwarden"


def available() -> bool:
    return _otel_trace is not None


class _NoSpan:
    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def record_error(self, exc: BaseException) -> None:
        pass

    @property
    def trace_id(self) -> str | None:
        return None


class _Span(_NoSpan):
    def __init__(self, span: Any) -> None:
        self._span = span

    def set_attribute(self, key: str, value: Any) -> None:
        if value is not None:
            self._span.set_attribute(key, value)

    def record_error(self, exc: BaseException) -> None:
        self._span.set_status(Status(StatusCode.ERROR, type(exc).__name__))
        self._span.set_attribute("error.type", type(exc).__name__)

    @property
    def trace_id(self) -> str | None:
        context = self._span.get_span_context()
        return f"{context.trace_id:032x}" if context.is_valid and context.trace_id else None


class Telemetry:
    """Tracer and instruments for one gateway. Pass providers to use non-global ones (tests)."""

    def __init__(self, tracer_provider: Any = None, meter_provider: Any = None) -> None:
        self._tracer: Any = None
        self._decisions: Any = None
        self._duration: Any = None
        self._issued: Any = None
        if _otel_trace is None or _otel_metrics is None:  # pragma: no cover
            return
        self._tracer = _otel_trace.get_tracer(INSTRUMENTATION, __version__, tracer_provider)
        meter = (meter_provider or _otel_metrics.get_meter_provider()).get_meter(
            INSTRUMENTATION, __version__
        )
        self._decisions = meter.create_counter(
            "agentwarden.decisions", unit="{decision}", description="Authorization decisions"
        )
        self._duration = meter.create_histogram(
            "agentwarden.authorize.duration", unit="s", description="Time to decide a tool call"
        )
        self._issued = meter.create_counter(
            "agentwarden.tokens", unit="{token}", description="Agent tokens issued or refused"
        )

    @contextlib.contextmanager
    def span(self, name: str, attributes: Mapping[str, Any] | None = None) -> Iterator[_NoSpan]:
        if self._tracer is None:  # pragma: no cover
            yield _NoSpan()
            return
        clean = {k: v for k, v in (attributes or {}).items() if v is not None}
        with self._tracer.start_as_current_span(
            name, attributes=clean, record_exception=True, set_status_on_exception=False
        ) as raw:
            span = _Span(raw)
            try:
                yield span
            except BaseException as exc:
                span.record_error(exc)
                raise

    def record_decision(self, decision: str, tool: str, agent_id: str, seconds: float) -> None:
        if self._decisions is None:  # pragma: no cover
            return
        attrs = {"agentwarden.decision": decision, "agentwarden.tool": tool}
        self._decisions.add(1, {**attrs, "agentwarden.agent_id": agent_id})
        self._duration.record(seconds, attrs)

    def record_token(self, operation: str, outcome: str, agent_id: str) -> None:
        if self._issued is None:  # pragma: no cover
            return
        self._issued.add(
            1,
            {
                "agentwarden.operation": operation,
                "agentwarden.outcome": outcome,
                "agentwarden.agent_id": agent_id,
            },
        )


def now() -> float:
    return time.perf_counter()


def configure_otlp(service_name: str = "agentwarden") -> None:  # pragma: no cover - needs network
    """Install global SDK providers that export over OTLP/HTTP (``AGENTWARDEN_OTEL=true``)."""
    try:
        from opentelemetry import metrics, trace
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError as exc:
        from agentwarden.errors import ConfigurationError

        raise ConfigurationError(
            "AGENTWARDEN_OTEL=true needs the OpenTelemetry SDK: pip install 'agentwarden[otel]'"
        ) from exc
    resource = Resource.create({"service.name": service_name, "service.version": __version__})
    tracer_provider = TracerProvider(resource=resource)
    tracer_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(tracer_provider)
    reader = PeriodicExportingMetricReader(OTLPMetricExporter())
    metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[reader]))
