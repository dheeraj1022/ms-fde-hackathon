"""FDEBench served app: one HTTPS service exposing all four endpoints.

Thin transport layer only. Request/response validation comes from the shared contracts in
``fde.contracts`` (re-exported by ``models``); business logic lives in ``fde.<task>``; the
model client and its resilience live in ``fde.llm``. Observability headers and uniform
error envelopes are installed by ``fde.platform``.

Run:
    cd py/apps/sample
    uv run uvicorn main:app --port 8000

Score (second terminal):
    cd py/apps/eval
    uv run python run_eval.py --endpoint http://localhost:8000 --task triage
"""

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi import Request
from fastapi.responses import HTMLResponse
from fde.config import get_settings
from fde.extract import extract as run_extract
from fde.llm import build_client
from fde.metrics import DASHBOARD_HTML
from fde.metrics import METRICS
from fde.orchestrate import orchestrate as run_orchestrate
from fde.platform import install_platform
from fde.triage import triage as run_triage
from models import ExtractRequest
from models import ExtractResponse
from models import OrchestrateRequest
from models import OrchestrateResponse
from models import TriageRequest
from models import TriageResponse
from prometheus_fastapi_instrumentator import Instrumentator

_settings = get_settings()


def _enable_app_insights() -> None:
    """Wire OpenTelemetry -> Azure Monitor when a connection string is present.

    durable, multi-replica telemetry. No-ops (offline-safe) if the SDK or the
    APPLICATIONINSIGHTS_CONNECTION_STRING env var is absent, so local/dev runs
    never fail for lack of credentials.
    """
    if not os.getenv("APPLICATIONINSIGHTS_CONNECTION_STRING"):
        return
    try:
        from azure.monitor.opentelemetry import configure_azure_monitor  # noqa: PLC0415

        configure_azure_monitor(logger_name="fde")
    except Exception:  # noqa: BLE001 - telemetry must never break the service
        pass


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Build the LLM client once. Returns None when no credentials are configured, in which
    # case the services transparently fall back to deterministic logic (offline-safe).
    app.state.settings = _settings
    app.state.llm = build_client(_settings)
    yield


app = FastAPI(title="FDEBench — Mission Signal Triage", version="1.0.0", lifespan=lifespan)
install_platform(app, model_name=_settings.model_name)
_enable_app_insights()

# Prometheus exposition at /metrics (scraped by Azure Monitor managed Prometheus).
Instrumentator().instrument(app).expose(app, include_in_schema=False)


@app.get("/health")
async def health() -> dict[str, str]:
    """Liveness probe — returns 200 with a tiny body for the load balancer."""
    return {"status": "ok"}


@app.get("/metrics.json")
async def metrics_json() -> dict:
    """Live in-process counts + P50/P95 per route, consumed by the dashboard."""
    return METRICS.snapshot()


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> str:
    """Zero-dependency live ops dashboard (polls /metrics.json)."""
    return DASHBOARD_HTML


# Task 1: Signal Triage
@app.post("/triage", response_model=TriageResponse)
async def triage(req: TriageRequest, request: Request) -> TriageResponse:
    """Classify a signal: category, priority, owning team, missing info."""
    client = getattr(request.app.state, "llm", None)
    return await run_triage(req, client)


# Task 2: Document Extraction
@app.post("/extract", response_model=ExtractResponse)
async def extract(req: ExtractRequest, request: Request) -> ExtractResponse:
    """Extract structured fields + verbatim text from a document."""
    client = getattr(request.app.state, "llm", None)
    return await run_extract(req, client)


# Task 3: Workflow Orchestration
@app.post("/orchestrate", response_model=OrchestrateResponse)
async def orchestrate(req: OrchestrateRequest, request: Request) -> OrchestrateResponse:
    """Plan and execute the tool-call sequence that satisfies the workflow."""
    client = getattr(request.app.state, "llm", None)
    return await run_orchestrate(req, client)
