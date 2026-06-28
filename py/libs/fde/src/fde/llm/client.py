"""Swappable async LLM client.

A thin abstraction over Azure OpenAI exposing exactly the three call shapes the tasks
need, each wrapped in shared resilience (bounded concurrency, per-attempt timeout, and
retries that honor ``Retry-After`` — the OpenAI SDK does not do this by default):

- ``parse``        — structured output into a Pydantic model (Task 1 triage).
- ``extract_json`` — vision call returning JSON for a request-provided schema (Task 2).
- ``chat``         — tool-calling turn for the orchestration loop (Task 3).

Keeping this behind a ``Protocol`` lets tests inject ``FakeLLMClient`` and lets the
services fall back to deterministic logic when no model is configured.
"""

import asyncio
import json
import logging
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Protocol
from typing import TypeVar
from typing import runtime_checkable

from ms.common.models.base import FrozenBaseModel

from fde.config import Settings
from fde.config import get_settings

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=FrozenBaseModel)

# Reasoning models (OpenAI o-series and the GPT-5 family) only run at their default
# temperature and reject an explicit ``temperature`` argument, so it must be omitted for
# them. The GPT-5 ``-chat`` variants are non-reasoning and keep normal temperature control.
_REASONING_PREFIXES: tuple[str, ...] = ("o1", "o3", "o4", "gpt-5")


def _is_reasoning_model(model_name: str) -> bool:
    """True when the model rejects an explicit ``temperature`` (o-series / GPT-5 family)."""
    name = model_name.strip().lower()
    if not name.startswith(_REASONING_PREFIXES):
        return False
    return "-chat" not in name


@dataclass
class ToolCall:
    """A single tool invocation the model wants to make."""

    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class AssistantTurn:
    """One assistant turn: free-text content and/or tool calls."""

    content: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw_message: Any = None


@runtime_checkable
class LLMClient(Protocol):
    """Structural interface implemented by the Azure client and the fake."""

    model_name: str

    async def parse(
        self,
        *,
        system: str,
        user: str,
        response_model: type[T],
        deployment: str | None = None,
        temperature: float | None = None,
    ) -> T: ...

    async def extract_json(
        self,
        *,
        system: str,
        user: str,
        image_b64: str,
        json_schema: dict[str, Any] | None = None,
        deployment: str | None = None,
    ) -> dict[str, Any]: ...

    async def chat(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        deployment: str | None = None,
    ) -> AssistantTurn: ...


class AzureOpenAIClient:
    """Async Azure OpenAI client with structured output, vision, and tool calling."""

    def __init__(self, settings: Settings | None = None) -> None:
        # Imported lazily so importing this module never hard-requires the SDK
        # until a real client is actually constructed.
        from openai import AsyncAzureOpenAI  # noqa: PLC0415

        self._s = settings or get_settings()
        self.model_name = self._s.model_name
        self._client = AsyncAzureOpenAI(
            azure_endpoint=self._s.azure_openai_endpoint,
            api_key=self._s.azure_openai_api_key,
            api_version=self._s.azure_openai_api_version,
            max_retries=0,  # we run our own Retry-After-aware loop
        )
        self._sem = asyncio.Semaphore(self._s.max_concurrency)

    # --- resilience ---

    @staticmethod
    def _retry_after(exc: Exception) -> float | None:
        resp = getattr(exc, "response", None)
        if resp is None:
            return None
        try:
            val = resp.headers.get("retry-after")
        except Exception:  # noqa: BLE001 - header access is best-effort
            return None
        if not val:
            return None
        try:
            return float(val)
        except ValueError:
            return None

    async def _run(self, factory: Any) -> Any:
        """Execute ``factory()`` with concurrency cap, timeout, and retries."""
        from openai import APIConnectionError  # noqa: PLC0415
        from openai import APIStatusError  # noqa: PLC0415
        from openai import APITimeoutError  # noqa: PLC0415
        from openai import RateLimitError  # noqa: PLC0415

        attempt = 0
        last_exc: Exception | None = None
        while True:
            try:
                async with self._sem:
                    return await asyncio.wait_for(factory(), timeout=self._s.request_timeout_s)
            except (RateLimitError, APITimeoutError, APIConnectionError, asyncio.TimeoutError) as exc:
                last_exc = exc
                if attempt >= self._s.max_retries:
                    break
                delay = self._retry_after(exc) or self._s.retry_base_delay_s * (2**attempt)
                logger.warning("LLM call retry %d after %.1fs (%s)", attempt + 1, delay, type(exc).__name__)
                await asyncio.sleep(delay)
                attempt += 1
            except APIStatusError as exc:
                status = getattr(exc, "status_code", None)
                if status is not None and 500 <= status < 600 and attempt < self._s.max_retries:
                    last_exc = exc
                    delay = self._retry_after(exc) or self._s.retry_base_delay_s * (2**attempt)
                    await asyncio.sleep(delay)
                    attempt += 1
                    continue
                raise
        assert last_exc is not None
        raise last_exc

    def _sampling_kwargs(
        self, temperature_override: float | None = None, effort_override: str | None = None
    ) -> dict[str, Any]:
        """Model-specific sampling kwargs.

        Temperature is optional, not required. Standard models take the configured value
        (default 0.0) for deterministic, reproducible triage. Reasoning models (o-series /
        GPT-5 family) reject an explicit temperature and instead expose a reasoning_effort
        knob; we run them at the configured effort ("low" by default) to keep lightweight
        triage fast, since the benchmark cost tier is keyed off the model name and is
        unaffected by effort. ``effort_override`` lets a heavier call shape (orchestration)
        ask for more reasoning without slowing triage.
        """
        if _is_reasoning_model(self._s.model_name):
            effort = (effort_override or self._s.reasoning_effort).strip().lower()
            return {"reasoning_effort": effort} if effort else {}
        temp = self._s.llm_temperature if temperature_override is None else temperature_override
        return {"temperature": temp}

    # --- call shapes ---

    async def parse(
        self,
        *,
        system: str,
        user: str,
        response_model: type[T],
        deployment: str | None = None,
        temperature: float | None = None,
    ) -> T:
        async def factory() -> Any:
            return await self._client.chat.completions.parse(
                model=deployment or self._s.aoai_deployment,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                response_format=response_model,
                **self._sampling_kwargs(temperature),
            )

        completion = await self._run(factory)
        parsed = completion.choices[0].message.parsed
        if parsed is None:
            msg = "Model returned no parsed structured output"
            raise ValueError(msg)
        return parsed

    async def extract_json(
        self,
        *,
        system: str,
        user: str,
        image_b64: str,
        json_schema: dict[str, Any] | None = None,
        deployment: str | None = None,
    ) -> dict[str, Any]:
        content: list[dict[str, Any]] = [
            {"type": "text", "text": user},
            {
                "type": "image_url",
                "image_url": {
                    "url": f"data:image/png;base64,{image_b64}",
                    "detail": self._s.vision_detail,
                },
            },
        ]
        if json_schema is not None:
            response_format: dict[str, Any] = {
                "type": "json_schema",
                "json_schema": {"name": "extraction", "schema": json_schema, "strict": False},
            }
        else:
            response_format = {"type": "json_object"}

        async def factory() -> Any:
            return await self._client.chat.completions.create(
                model=deployment or self._s.vision_deployment,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": content},
                ],
                response_format=response_format,
                **self._sampling_kwargs(),
            )

        completion = await self._run(factory)
        text = completion.choices[0].message.content or "{}"
        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            logger.warning("Vision model returned non-JSON content")
            return {}
        return result if isinstance(result, dict) else {}

    async def chat(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        deployment: str | None = None,
    ) -> AssistantTurn:
        async def factory() -> Any:
            kwargs: dict[str, Any] = {
                "model": deployment or self._s.aoai_deployment,
                "messages": messages,
            }
            kwargs.update(self._sampling_kwargs(effort_override=self._s.orchestrate_reasoning_effort))
            if tools:
                kwargs["tools"] = tools
                kwargs["tool_choice"] = "auto"
            return await self._client.chat.completions.create(**kwargs)

        completion = await self._run(factory)
        message = completion.choices[0].message
        calls: list[ToolCall] = []
        for tc in message.tool_calls or []:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            calls.append(ToolCall(id=tc.id, name=tc.function.name, arguments=args))
        return AssistantTurn(content=message.content or "", tool_calls=calls, raw_message=message)


def build_client(settings: Settings | None = None) -> AzureOpenAIClient | None:
    """Construct an Azure client, or ``None`` when credentials are absent.

    Returning ``None`` lets services skip a guaranteed-to-fail network call and go
    straight to their deterministic fallback for offline / unconfigured runs.
    """
    s = settings or get_settings()
    if not s.configured:
        logger.warning(
            "Azure OpenAI not configured (set AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY); "
            "services will use deterministic fallback."
        )
        return None
    return AzureOpenAIClient(s)


__all__ = [
    "AssistantTurn",
    "AzureOpenAIClient",
    "LLMClient",
    "ToolCall",
    "build_client",
]
