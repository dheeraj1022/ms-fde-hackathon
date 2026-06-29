"""Transport-level tests for the served FastAPI app and platform middleware."""

import importlib
from pathlib import Path
from typing import Any
from typing import cast

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from fde.metrics import METRICS
from fde.platform import LATENCY_HEADER
from fde.platform import MODEL_HEADER
from fde.platform import REQUEST_ID_HEADER
from fde.platform import install_platform

_SAMPLE_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture
def sample_app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    monkeypatch.syspath_prepend(str(_SAMPLE_DIR))
    module = cast(Any, importlib.import_module("main"))
    return cast(FastAPI, module.app)


def _route_count(snapshot: dict[str, Any], path: str) -> int:
    for route in snapshot["routes"]:
        if route["path"] == path:
            return int(route["count"])
    return 0


def test_success_responses_include_observability_headers(sample_app: FastAPI) -> None:
    request_id = "test-request-headers"

    with TestClient(sample_app) as client:
        resp = client.get("/health", headers={REQUEST_ID_HEADER: request_id})

    assert resp.status_code == 200
    assert resp.headers[REQUEST_ID_HEADER] == request_id
    assert float(resp.headers[LATENCY_HEADER]) >= 0.0
    assert resp.headers[MODEL_HEADER] == "gpt-5.4-mini"


def test_validation_errors_use_uniform_envelope_and_headers(sample_app: FastAPI) -> None:
    request_id = "test-validation-envelope"

    with TestClient(sample_app) as client:
        resp = client.post("/triage", json={}, headers={REQUEST_ID_HEADER: request_id})

    assert resp.status_code == 422
    assert resp.headers[REQUEST_ID_HEADER] == request_id
    assert resp.headers[MODEL_HEADER] == "gpt-5.4-mini"
    assert float(resp.headers[LATENCY_HEADER]) >= 0.0
    body = resp.json()
    assert body["error"]["code"] == "validation_error"
    assert body["error"]["request_id"] == request_id
    assert isinstance(body["error"]["detail"], list)


def test_unexpected_errors_use_503_envelope_without_leaking_trace() -> None:
    app = FastAPI()
    install_platform(app, model_name="test-model")

    @app.get("/boom")
    async def boom() -> dict[str, str]:
        raise RuntimeError("boom")

    request_id = "test-unexpected-error"
    with TestClient(app, raise_server_exceptions=False) as client:
        resp = client.get("/boom", headers={REQUEST_ID_HEADER: request_id})

    assert resp.status_code == 503
    assert resp.headers[REQUEST_ID_HEADER] == request_id
    assert resp.headers[MODEL_HEADER] == "test-model"
    assert float(resp.headers[LATENCY_HEADER]) >= 0.0
    assert resp.json() == {
        "error": {
            "code": "internal_error",
            "message": "The service hit an unexpected error.",
            "request_id": request_id,
        }
    }


def test_metrics_json_reflects_completed_route_requests(sample_app: FastAPI) -> None:
    before = _route_count(METRICS.snapshot(), "/health")

    with TestClient(sample_app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        metrics = client.get("/metrics.json").json()

    assert _route_count(metrics, "/health") >= before + 1
    assert metrics["model"] == "gpt-5.4-mini"
