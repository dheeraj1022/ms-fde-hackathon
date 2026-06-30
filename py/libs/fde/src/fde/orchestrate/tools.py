"""Tool plumbing for the orchestration agent.

Two jobs: translate the request's ``available_tools`` into OpenAI function specs the
model can call, and execute a chosen call as a real HTTP request to the tool's
endpoint (the eval harness rewrites endpoints to its local mock service). Execution is
best-effort: a deployed endpoint may be unable to reach the harness, so failures are
captured in the step (success=False) rather than raised — the trace is still scored.
"""

import asyncio
import json
import logging
from typing import Any

import httpx

from fde.contracts import ToolDefinition

logger = logging.getLogger(__name__)

_JSON_TYPES = {"string", "number", "integer", "boolean", "object", "array"}
_MAX_RETRY_DELAY_S = 10.0


def _param_schema(p_type: str) -> dict[str, Any]:
    """Coerce a tool param type to a valid JSON-schema type (default string)."""
    t = (p_type or "string").strip().lower()
    return {"type": t if t in _JSON_TYPES else "string"}


def to_function_specs(tools: list[ToolDefinition]) -> list[dict[str, Any]]:
    """Map tool definitions to OpenAI chat-completions function specs."""
    specs: list[dict[str, Any]] = []
    for tool in tools:
        properties: dict[str, Any] = {}
        required: list[str] = []
        params = tool.parameters
        if isinstance(params, dict):
            for name, p_type in params.items():
                properties[name] = _param_schema(str(p_type))
        else:
            for p in params:
                properties[p.name] = _param_schema(p.type)
                if p.description:
                    properties[p.name]["description"] = p.description
                if p.required:
                    required.append(p.name)
        specs.append(
            {
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": {"type": "object", "properties": properties, "required": required},
                },
            }
        )
    return specs


def endpoint_map(tools: list[ToolDefinition], mock_service_url: str | None) -> dict[str, str]:
    """Resolve each tool name to a callable URL (tool endpoint, else mock_service_url/name)."""
    out: dict[str, str] = {}
    for tool in tools:
        if tool.endpoint:
            out[tool.name] = tool.endpoint
        elif mock_service_url:
            out[tool.name] = f"{mock_service_url.rstrip('/')}/{tool.name}"
    return out


def _summarize(body: Any) -> str:
    """Compact a tool result to a short string for the trace/model context."""
    text = json.dumps(body) if not isinstance(body, str) else body
    return text if len(text) <= 240 else text[:237] + "..."


class ToolRunner:
    """Executes tool calls over HTTP, one shared async client per workflow."""

    def __init__(
        self,
        endpoints: dict[str, str],
        timeout: float = 8.0,
        *,
        max_retries: int = 2,
        retry_base_delay_s: float = 1.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._endpoints = endpoints
        self._max_retries = max_retries
        self._retry_base_delay_s = retry_base_delay_s
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport)

    @staticmethod
    def _retry_after(resp: httpx.Response) -> float | None:
        val_ms = resp.headers.get("retry-after-ms")
        if val_ms:
            try:
                return min(float(val_ms) / 1000.0, _MAX_RETRY_DELAY_S)
            except ValueError:
                pass
        val = resp.headers.get("retry-after")
        if not val:
            return None
        try:
            return min(float(val), _MAX_RETRY_DELAY_S)
        except ValueError:
            return None

    async def call(self, name: str, params: dict[str, Any], *, max_retries: int | None = None) -> tuple[Any, bool, str]:
        url = self._endpoints.get(name)
        if not url:
            return None, False, f"no endpoint for tool {name}"
        last_body: Any = None
        last_summary = ""
        attempts = self._max_retries if max_retries is None else max_retries
        try:
            for attempt in range(attempts + 1):
                resp = await self._client.post(url, json=params)
                try:
                    body: Any = resp.json()
                except (json.JSONDecodeError, ValueError):
                    body = resp.text
                last_body = body
                last_summary = _summarize(body)

                if resp.status_code == 200:
                    return body, True, last_summary
                if resp.status_code != 429 and not 500 <= resp.status_code < 600:
                    return body, False, last_summary
                if attempt >= attempts:
                    break

                delay = self._retry_after(resp) or self._retry_base_delay_s * (2**attempt)
                logger.warning("Tool %s retry %d after %.1fs (HTTP %d)", name, attempt + 1, delay, resp.status_code)
                await asyncio.sleep(delay)
            return last_body, False, last_summary
        except Exception as exc:  # noqa: BLE001 - tool failures are recorded, never fatal
            logger.warning("Tool %s call failed: %s", name, exc)
            return None, False, f"error: {type(exc).__name__}"

    async def aclose(self) -> None:
        await self._client.aclose()


__all__ = ["ToolRunner", "endpoint_map", "to_function_specs"]
