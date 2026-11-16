"""Logs, metrics and traces.

- Structured JSON logs (one object per line) with the request id of the HTTP call that caused them.
- Prometheus metrics for HTTP traffic, the indexer, the chain head and gateway activity, served at ``/metrics``.
- OpenTelemetry traces when the ``otel`` extra is installed and ``OTEL_EXPORTER_OTLP_ENDPOINT`` is set.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import uuid
from collections.abc import Iterable
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from prometheus_client import CollectorRegistry, Counter, Histogram
from prometheus_client.core import GaugeMetricFamily
from prometheus_client.registry import Collector
from starlette.types import ASGIApp, Message, Receive, Scope, Send

if TYPE_CHECKING:
    from fastapi import FastAPI

    from .chain import Chain
    from .indexer import Indexer
    from .platform import Platform

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
REQUEST_ID_HEADER = "X-Request-ID"
# uvicorn adds `color_message` (the message with ANSI colours); JSON logs keep the plain one.
_STANDARD_ATTRS = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime", "color_message"}

# ---------------------------------------------------------------------------------------------------------- logging


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = request_id_var.get()
        if request_id:
            entry["request_id"] = request_id
        entry.update({k: v for k, v in record.__dict__.items() if k not in _STANDARD_ATTRS and not k.startswith("_")})
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    handler = logging.StreamHandler(sys.stdout)
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level.upper())
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).handlers[:] = []
        logging.getLogger(name).propagate = True
    # Request logs come from RequestContextMiddleware, with the route template and duration.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------------------------------------- metrics


GATEWAY_EVENTS = (
    "upload_staged",
    "read_logged",
    "record_proof",
    "relayed_request",
    "shredded",
    "auth_failed",
    "integrity_failure",
)
# Probes and scrapes are not user traffic: they stay out of the HTTP metrics and the access log.
UNOBSERVED_ROUTES = frozenset({"/healthz", "/readyz", "/metrics"})


class Metrics:
    """One registry per app, so tests and several apps in a process do not collide."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.http_requests = Counter(
            "dataledger_http_requests_total",
            "HTTP requests by route template, method and status.",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.http_duration = Histogram(
            "dataledger_http_request_duration_seconds",
            "HTTP request latency by route template.",
            ["method", "route"],
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
            registry=self.registry,
        )
        self.gateway_events = Counter(
            "dataledger_gateway_events_total",
            "Gateway actions: uploads, logged reads, proofs, relayed requests, shreds, auth and integrity failures.",
            ["event"],
            registry=self.registry,
        )
        for event in GATEWAY_EVENTS:  # export zeros from the start, so rates and alerts have a series to work on
            self.gateway_events.labels(event)

    def observe_platform(self, platform: Platform) -> None:
        self.registry.register(ChainCollector(platform.chain, platform.indexer))


class ChainCollector(Collector):
    """Chain head, indexer cursor and lag, read when Prometheus scrapes."""

    def __init__(self, chain: Chain, indexer: Indexer) -> None:
        self.chain = chain
        self.indexer = indexer

    def collect(self) -> Iterable[GaugeMetricFamily]:
        head = GaugeMetricFamily("dataledger_chain_head_block", "Latest block reported by the RPC endpoint.")
        indexed = GaugeMetricFamily("dataledger_indexer_block", "Last block applied by the indexer.")
        lag = GaugeMetricFamily("dataledger_indexer_lag_blocks", "Blocks the read models are behind the chain.")
        up = GaugeMetricFamily("dataledger_chain_up", "1 when the RPC endpoint answered this scrape.")
        try:
            head_block = self.chain.block_number
            cursor = self.indexer.cursor()
        except Exception:
            up.add_metric([], 0)
            yield up
            return
        up.add_metric([], 1)
        head.add_metric([], head_block)
        indexed.add_metric([], cursor)
        lag.add_metric([], max(0, head_block - cursor))
        yield from (up, head, indexed, lag)


def _route_template(scope: Scope) -> str:
    route = scope.get("route")
    path = getattr(route, "path", None)
    if path:
        return str(path)
    # Static console files and unknown paths are folded together to keep label cardinality bounded.
    return "/api/*" if str(scope.get("path", "")).startswith("/api/") else "/console"


class RequestContextMiddleware:
    """Request id, body digest for signed requests, metrics and one access-log line per request.

    The body digest is computed while the app reads the body, so a signed upload is hashed without being buffered
    twice. Authentication compares it with the `Content-Digest` the caller signed.
    """

    def __init__(self, app: ASGIApp, metrics: Metrics) -> None:
        self.app = app
        self.metrics = metrics
        self.log = logging.getLogger("dataledger.http")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        incoming = dict(scope.get("headers") or []).get(b"x-request-id", b"").decode("latin-1")
        request_id = incoming if 0 < len(incoming) <= 128 and incoming.isprintable() else uuid.uuid4().hex
        token = request_id_var.set(request_id)
        hasher = hashlib.sha256()
        state = scope.setdefault("state", {})
        state["body_hasher"] = hasher
        status = 500
        started = time.perf_counter()

        async def receive_and_hash() -> Message:
            message = await receive()
            if message["type"] == "http.request":
                hasher.update(message.get("body", b""))
            return message

        async def send_with_id(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = list(message.get("headers", []))
                headers.append((REQUEST_ID_HEADER.lower().encode(), request_id.encode()))
                message["headers"] = headers
            await send(message)

        try:
            await self.app(scope, receive_and_hash, send_with_id)
        finally:
            elapsed = time.perf_counter() - started
            route = _route_template(scope)
            method = scope.get("method", "GET")
            if route not in UNOBSERVED_ROUTES:
                self.metrics.http_requests.labels(method, route, str(status)).inc()
                self.metrics.http_duration.labels(method, route).observe(elapsed)
                self.log.info(
                    "%s %s %s",
                    method,
                    scope.get("path"),
                    status,
                    extra={"route": route, "status": status, "duration_ms": round(elapsed * 1000, 1)},
                )
            request_id_var.reset(token)


# ---------------------------------------------------------------------------------------------------------- headers

CONSOLE_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
SECURITY_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"referrer-policy": b"no-referrer",
    b"x-frame-options": b"DENY",
    b"cross-origin-opener-policy": b"same-origin",
    b"permissions-policy": b"camera=(), microphone=(), geolocation=()",
}
# The interactive API docs load Swagger UI from a CDN, so they keep the framework's defaults.
_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = str(scope.get("path", ""))

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                present = {k.lower() for k, _ in headers}
                extra = dict(SECURITY_HEADERS)
                if not path.startswith(_DOCS_PATHS) and not path.startswith("/api/"):
                    extra[b"content-security-policy"] = CONSOLE_CSP.encode()
                if path.startswith("/api/"):
                    extra[b"cache-control"] = b"no-store"
                if self.hsts:
                    extra[b"strict-transport-security"] = b"max-age=31536000; includeSubDomains"
                headers.extend((k, v) for k, v in extra.items() if k not in present)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)


# ---------------------------------------------------------------------------------------------------------- tracing


def configure_tracing(app: FastAPI, service_name: str = "dataledger") -> Any:
    """Instruments the app when OpenTelemetry is installed and an exporter is configured.

    Returns the tracer provider (call ``shutdown()`` to flush), or None when tracing stays off.
    """
    if not (os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or os.environ.get("OTEL_TRACES_EXPORTER") == "console"):
        return None
    try:
        from opentelemetry import trace
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SpanExporter
    except ImportError:
        logging.getLogger(__name__).warning("OTEL_* is set but the `otel` extra is not installed; tracing is off")
        return None

    exporter: SpanExporter
    if os.environ.get("OTEL_TRACES_EXPORTER") == "console":
        exporter = ConsoleSpanExporter()
    else:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

        exporter = OTLPSpanExporter()
    name = os.environ.get("OTEL_SERVICE_NAME", service_name)
    provider = TracerProvider(resource=Resource.create({"service.name": name}))
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    FastAPIInstrumentor.instrument_app(app, tracer_provider=provider, excluded_urls="metrics,healthz,readyz")
    return provider
