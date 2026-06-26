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

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi import Request
from fde.config import get_settings
from fde.llm import build_client
from fde.platform import install_platform
from fde.triage import triage as run_triage
from models import ExtractRequest
from models import ExtractResponse
from models import OrchestrateRequest
from models import OrchestrateResponse
from models import TriageRequest
from models import TriageResponse

_settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Build the LLM client once. Returns None when no credentials are configured, in which
    # case the services transparently fall back to deterministic logic (offline-safe).
    app.state.settings = _settings
    app.state.llm = build_client(_settings)
    yield


app = FastAPI(title="FDEBench — Mission Signal Triage", version="1.0.0", lifespan=lifespan)
install_platform(app, model_name=_settings.model_name)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


# Task 1: Signal Triage
@app.post("/triage", response_model=TriageResponse)
async def triage(req: TriageRequest, request: Request) -> TriageResponse:
    client = getattr(request.app.state, "llm", None)
    return await run_triage(req, client)


# Task 2: Document Extraction
@app.post("/extract", response_model=ExtractResponse)
async def extract(req: ExtractRequest, request: Request) -> ExtractResponse:
    # TODO(task2): vision extraction against req.json_schema via fde.extract.
    return ExtractResponse(document_id=req.document_id)


# Task 3: Workflow Orchestration
@app.post("/orchestrate", response_model=OrchestrateResponse)
async def orchestrate(req: OrchestrateRequest, request: Request) -> OrchestrateResponse:
    # TODO(task3): plan + execute tools via fde.orchestrate.
    return OrchestrateResponse(
        task_id=req.task_id,
        status="completed",
        steps_executed=[],
        constraints_satisfied=[],
    )
