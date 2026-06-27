"""Unit tests for Task 2 extraction: schema-guided field passthrough, null-sentinel
coercion, document_id authority, and the offline / failure fallbacks (via FakeLLMClient,
no network)."""

import asyncio

from fde.contracts import ExtractRequest
from fde.extract import build_user
from fde.extract import extract
from fde.llm import FakeLLMClient

_SCHEMA = (
    '{"type":"object","properties":'
    '{"company":{"type":"string"},"phone":{"type":"string"},'
    '"signedDate":{"type":"string"},"rows":{"type":"array"}}}'
)


def _req(**overrides: object) -> ExtractRequest:
    base: dict[str, object] = {
        "document_id": "DOC-1",
        "content": "Zm9v",  # base64("foo"); the fake client ignores image bytes
        "content_format": "image_base64",
        "json_schema": _SCHEMA,
    }
    base.update(overrides)
    return ExtractRequest(**base)  # type: ignore[arg-type]


def test_returns_fields_and_enforces_document_id() -> None:
    client = FakeLLMClient(
        extract_handler=lambda **_: {"document_id": "WRONG", "company": "CLEARPOINT", "phone": "+1-652-712-8471"},
    )
    resp = asyncio.run(extract(_req(), client))
    dumped = resp.model_dump()
    assert dumped["document_id"] == "DOC-1"  # our id wins, never the model's
    assert dumped["company"] == "CLEARPOINT"
    assert dumped["phone"] == "+1-652-712-8471"


def test_null_sentinels_coerced_to_none() -> None:
    client = FakeLLMClient(
        extract_handler=lambda **_: {
            "company": "ACME",
            "signedDate": "N/A",
            "phone": "  not present ",
            "rows": [{"name": "X", "votes": "unknown"}],
        },
    )
    dumped = asyncio.run(extract(_req(), client)).model_dump()
    assert dumped["signedDate"] is None
    assert dumped["phone"] is None
    assert dumped["rows"][0]["votes"] is None
    assert dumped["rows"][0]["name"] == "X"


def test_offline_returns_document_id_only() -> None:
    dumped = asyncio.run(extract(_req(), None)).model_dump()
    assert dumped["document_id"] == "DOC-1"
    assert "company" not in dumped  # no fabrication when no model is configured


def test_model_failure_degrades_to_safe_floor() -> None:
    def boom(**_: object) -> dict[str, object]:
        raise RuntimeError("model down")

    client = FakeLLMClient(extract_handler=boom)
    dumped = asyncio.run(extract(_req(), client)).model_dump()
    assert dumped["document_id"] == "DOC-1"
    assert len(dumped) == 1  # document_id only


def test_build_user_embeds_schema() -> None:
    user = build_user({"type": "object", "properties": {"company": {"type": "string"}}})
    assert "SCHEMA:" in user
    assert "company" in user
    assert build_user(None).strip().endswith("Output JSON only.")
