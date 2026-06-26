"""Deterministic in-memory LLM double for tests and offline runs.

Implements the ``LLMClient`` protocol structurally without any network. Each call shape
delegates to a handler you provide, so a test can pin exact model behavior and assert on
the surrounding rules / merge / loop logic. Calls are recorded for inspection.
"""

from __future__ import annotations

from typing import Any
from typing import Callable
from typing import TypeVar

from pydantic import BaseModel

from fde.llm.client import AssistantTurn

T = TypeVar("T", bound=BaseModel)

ParseHandler = Callable[..., BaseModel]
ExtractHandler = Callable[..., dict[str, Any]]
ChatHandler = Callable[..., AssistantTurn]


class FakeLLMClient:
    """A configurable, deterministic stand-in for ``AzureOpenAIClient``."""

    def __init__(
        self,
        *,
        parse_handler: ParseHandler | None = None,
        extract_handler: ExtractHandler | None = None,
        chat_handler: ChatHandler | None = None,
        model_name: str = "fake-model",
    ) -> None:
        self.model_name = model_name
        self._parse_handler = parse_handler
        self._extract_handler = extract_handler
        self._chat_handler = chat_handler
        self.parse_calls: list[dict[str, Any]] = []
        self.extract_calls: list[dict[str, Any]] = []
        self.chat_calls: list[dict[str, Any]] = []

    async def parse(
        self,
        *,
        system: str,
        user: str,
        response_model: type[T],
        deployment: str | None = None,
        temperature: float | None = None,
    ) -> T:
        self.parse_calls.append({"system": system, "user": user, "response_model": response_model})
        if self._parse_handler is None:
            msg = "FakeLLMClient.parse called without a parse_handler"
            raise NotImplementedError(msg)
        result = self._parse_handler(system=system, user=user, response_model=response_model)
        return result  # type: ignore[return-value]

    async def extract_json(
        self,
        *,
        system: str,
        user: str,
        image_b64: str,
        json_schema: dict[str, Any] | None = None,
        deployment: str | None = None,
    ) -> dict[str, Any]:
        self.extract_calls.append({"system": system, "user": user, "json_schema": json_schema})
        if self._extract_handler is None:
            return {}
        return self._extract_handler(system=system, user=user, image_b64=image_b64, json_schema=json_schema)

    async def chat(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        deployment: str | None = None,
    ) -> AssistantTurn:
        self.chat_calls.append({"messages": messages, "tools": tools})
        if self._chat_handler is None:
            return AssistantTurn(content="", tool_calls=[])
        return self._chat_handler(messages=messages, tools=tools)


__all__ = ["FakeLLMClient"]
