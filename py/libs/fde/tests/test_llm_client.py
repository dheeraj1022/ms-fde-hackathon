"""Unit tests for LLM-client retry timing helpers."""

from types import SimpleNamespace

from fde.llm.client import AzureOpenAIClient


class _ResponseError(Exception):
    def __init__(self, headers: dict[str, str]) -> None:
        super().__init__("response error")
        self.response = SimpleNamespace(headers=headers)


def test_retry_after_ms_header_is_supported_and_capped() -> None:
    exc = _ResponseError({"retry-after-ms": "15000"})
    assert AzureOpenAIClient._retry_after(exc) == 10.0


def test_retry_after_header_is_supported_and_capped() -> None:
    exc = _ResponseError({"retry-after": "12"})
    assert AzureOpenAIClient._retry_after(exc) == 10.0
