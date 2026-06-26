"""LLM client layer: protocol, Azure OpenAI implementation, and a deterministic fake."""

from fde.llm.client import AssistantTurn
from fde.llm.client import AzureOpenAIClient
from fde.llm.client import LLMClient
from fde.llm.client import ToolCall
from fde.llm.client import build_client
from fde.llm.fake import FakeLLMClient

__all__ = [
    "AssistantTurn",
    "AzureOpenAIClient",
    "FakeLLMClient",
    "LLMClient",
    "ToolCall",
    "build_client",
]
