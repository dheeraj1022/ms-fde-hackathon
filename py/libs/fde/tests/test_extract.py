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
    assert client.extract_calls[0]["json_schema"] == {
        "type": "object",
        "properties": {
            "company": {"type": "string"},
            "phone": {"type": "string"},
            "signedDate": {"type": "string"},
            "rows": {"type": "array"},
        },
    }


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


def test_schema_mode_failure_retries_json_object_mode() -> None:
    calls = {"n": 0}

    def handler(**kwargs: object) -> dict[str, object]:
        calls["n"] += 1
        if kwargs["json_schema"] is not None:
            raise RuntimeError("schema rejected")
        return {"company": "Fallback Corp"}

    client = FakeLLMClient(extract_handler=handler)
    dumped = asyncio.run(extract(_req(), client)).model_dump()

    assert dumped["company"] == "Fallback Corp"
    assert calls["n"] == 2
    assert client.extract_calls[0]["json_schema"] is not None
    assert client.extract_calls[1]["json_schema"] is None


def test_image_url_payloads_are_passed_through() -> None:
    seen = {}

    def handler(**kwargs: object) -> dict[str, object]:
        seen["image_b64"] = kwargs["image_b64"]
        return {"company": "URL Corp"}

    client = FakeLLMClient(extract_handler=handler)
    req = _req(content="https://example.test/doc.png", content_format="image_url")
    dumped = asyncio.run(extract(req, client)).model_dump()

    assert dumped["company"] == "URL Corp"
    assert seen["image_b64"] == "https://example.test/doc.png"


def test_build_user_embeds_schema() -> None:
    user = build_user({"type": "object", "properties": {"company": {"type": "string"}}})
    assert "SCHEMA:" in user
    assert "company" in user
    assert build_user(None).strip().endswith("Output JSON only.")
