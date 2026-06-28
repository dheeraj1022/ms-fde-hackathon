"""Shared transport concerns: observability headers and uniform error envelopes.

Imported by the served app so every endpoint — for all three tasks — gets consistent
``X-Request-Id`` / ``X-Latency-Ms`` / ``X-Model-Name`` headers and never leaks a stack
trace or hangs. Schema-invalid requests become a 422 envelope; an unexpected error becomes
a 503 envelope. The ``X-Model-Name`` header is what the benchmark reads for cost scoring,
so it is set on every response.
"""

import logging
import time
import uuid
from typing import Any

from fastapi import FastAPI
from fastapi import Request
from fastapi import Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from fde.metrics import METRICS

logger = logging.getLogger(__name__)

REQUEST_ID_HEADER = "X-Request-Id"
LATENCY_HEADER = "X-Latency-Ms"
MODEL_HEADER = "X-Model-Name"


def _error_body(request_id: str, code: str, message: str, detail: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message, "request_id": request_id}
    if detail is not None:
        error["detail"] = detail
    return {"error": error}


def _request_id(request: Request) -> str:
    return request.headers.get(REQUEST_ID_HEADER) or uuid.uuid4().hex


def install_platform(app: FastAPI, *, model_name: str) -> None:
    """Attach observability middleware and error handlers to ``app``."""

    @app.middleware("http")
    async def _observability(request: Request, call_next: Any) -> Response:
        request_id = _request_id(request)
        request.state.request_id = request_id
        start = time.perf_counter()
        try:
            response: Response = await call_next(request)
        except Exception:  # noqa: BLE001 - never hang or leak a trace; fail loud but clean
            logger.exception("unhandled_error [%s] %s %s", request_id, request.method, request.url.path)
            response = JSONResponse(
                status_code=503,
                content=_error_body(request_id, "internal_error", "The service hit an unexpected error."),
            )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        response.headers[REQUEST_ID_HEADER] = request_id
        response.headers[LATENCY_HEADER] = f"{elapsed_ms:.1f}"
        response.headers.setdefault(MODEL_HEADER, model_name)
        METRICS.record(request.url.path, elapsed_ms, response.status_code, model_name)
        return response

    @app.exception_handler(RequestValidationError)
    async def _on_validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        request_id = _request_id(request)
        return JSONResponse(
            status_code=422,
            content=_error_body(
                request_id,
                "validation_error",
                "Request failed schema validation.",
                jsonable_encoder(exc.errors()),
            ),
            headers={REQUEST_ID_HEADER: request_id, MODEL_HEADER: model_name},
        )


__all__ = ["LATENCY_HEADER", "MODEL_HEADER", "REQUEST_ID_HEADER", "install_platform"]
