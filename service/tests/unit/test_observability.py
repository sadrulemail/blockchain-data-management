"""Request ids, JSON logs, security headers and HTTP metrics, on a small app without a chain."""

import hashlib
import json
import logging

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from prometheus_client import generate_latest

from dataledger.observability import (
    JsonFormatter,
    Metrics,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    configure_logging,
    configure_tracing,
    request_id_var,
)


def _app(metrics: Metrics, *, hsts: bool = False) -> FastAPI:
    app = FastAPI()

    @app.get("/api/items/{item_id}")
    def item(item_id: int) -> dict[str, int]:
        return {"item_id": item_id}

    @app.post("/api/echo")
    async def echo(request: Request) -> dict[str, str]:
        await request.body()
        return {"sha256": request.scope["state"]["body_hasher"].hexdigest()}

    @app.get("/index.html")
    def page() -> dict[str, str]:
        return {"page": "console"}

    app.add_middleware(SecurityHeadersMiddleware, hsts=hsts)
    app.add_middleware(RequestContextMiddleware, metrics=metrics)
    return app


def test_request_id_is_echoed_or_generated():
    client = TestClient(_app(Metrics()))
    assert client.get("/api/items/1", headers={"X-Request-ID": "abc-123"}).headers["x-request-id"] == "abc-123"
    generated = client.get("/api/items/1").headers["x-request-id"]
    assert len(generated) == 32
    assert client.get("/api/items/1", headers={"X-Request-ID": "x" * 200}).headers["x-request-id"] != "x" * 200


def test_body_digest_is_computed_while_streaming():
    client = TestClient(_app(Metrics()))
    body = b"a" * 100_000
    assert client.post("/api/echo", content=body).json()["sha256"] == hashlib.sha256(body).hexdigest()


def test_security_headers_and_console_csp():
    client = TestClient(_app(Metrics(), hsts=True))
    api = client.get("/api/items/1").headers
    assert api["x-content-type-options"] == "nosniff"
    assert api["cache-control"] == "no-store"
    assert api["strict-transport-security"].startswith("max-age=")
    assert "content-security-policy" not in api
    page = client.get("/index.html").headers
    assert "frame-ancestors 'none'" in page["content-security-policy"]
    assert "script-src 'self'" in page["content-security-policy"]


def test_http_metrics_use_route_templates():
    metrics = Metrics()
    client = TestClient(_app(metrics))
    for item_id in (1, 2, 3):
        client.get(f"/api/items/{item_id}")
    client.get("/api/missing")
    text = generate_latest(metrics.registry).decode()
    assert 'dataledger_http_requests_total{method="GET",route="/api/items/{item_id}",status="200"} 3.0' in text
    assert 'route="/api/*",status="404"' in text
    assert "/api/items/1" not in text


def test_json_formatter_carries_request_id_and_extras():
    record = logging.LogRecord("dataledger.test", logging.INFO, __file__, 1, "read %s", ("ok",), None)
    record.dataset_id = 7
    token = request_id_var.set("req-1")
    try:
        entry = json.loads(JsonFormatter().format(record))
    finally:
        request_id_var.reset(token)
    assert entry["message"] == "read ok"
    assert entry["request_id"] == "req-1"
    assert entry["dataset_id"] == 7
    assert entry["level"] == "info"


def test_configure_logging_switches_formatter():
    configure_logging("DEBUG", "json")
    assert isinstance(logging.getLogger().handlers[0].formatter, JsonFormatter)
    configure_logging("INFO", "text")
    assert not isinstance(logging.getLogger().handlers[0].formatter, JsonFormatter)


def test_tracing_is_off_without_an_exporter(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    monkeypatch.delenv("OTEL_TRACES_EXPORTER", raising=False)
    assert configure_tracing(FastAPI()) is None


def test_tracing_with_console_exporter(monkeypatch, capsys):
    monkeypatch.setenv("OTEL_TRACES_EXPORTER", "console")
    app = _app(Metrics())
    provider = configure_tracing(app)
    assert provider is not None
    assert TestClient(app).get("/api/items/5").status_code == 200
    provider.force_flush()
    provider.shutdown()
    assert '"name": "GET /api/items/{item_id}"' in capsys.readouterr().out


def test_version_comes_from_the_package_metadata():
    import tomllib
    from pathlib import Path

    import dataledger

    project = tomllib.loads((Path(__file__).resolve().parents[2] / "pyproject.toml").read_text(encoding="utf-8"))
    assert dataledger.__version__ == project["project"]["version"]
