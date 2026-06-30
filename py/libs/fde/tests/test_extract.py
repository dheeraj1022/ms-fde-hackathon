"""Unit tests for Task 2 extraction: schema-guided field passthrough, input image
envelope tolerance, sparse-output fallback, null-sentinel coercion, and the offline /
failure paths (via FakeLLMClient, no network)."""

import asyncio
import base64
import tempfile
from pathlib import Path

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


def test_base64_payload_is_converted_to_data_url_with_detected_mime() -> None:
    seen = {}
    jpeg = base64.b64encode(b"\xff\xd8\xff\xe0fake-jpeg").decode("ascii")

    def handler(**kwargs: object) -> dict[str, object]:
        seen["image_b64"] = kwargs["image_b64"]
        return {"company": "JPEG Corp"}

    client = FakeLLMClient(extract_handler=handler)
    dumped = asyncio.run(extract(_req(content=jpeg), client)).model_dump()

    assert dumped["company"] == "JPEG Corp"
    assert str(seen["image_b64"]).startswith("data:image/jpeg;base64,")


def test_data_url_payloads_are_not_double_wrapped() -> None:
    seen = {}
    payload = "data:image/webp;base64,UklGRg=="

    def handler(**kwargs: object) -> dict[str, object]:
        seen["image_b64"] = kwargs["image_b64"]
        return {"company": "WEBP Corp"}

    client = FakeLLMClient(extract_handler=handler)
    dumped = asyncio.run(extract(_req(content=payload, content_format="data_url"), client)).model_dump()

    assert dumped["company"] == "WEBP Corp"
    assert seen["image_b64"] == payload


def test_image_path_payloads_are_read_best_effort_with_detected_mime() -> None:
    seen = {}

    def handler(**kwargs: object) -> dict[str, object]:
        seen["image_b64"] = kwargs["image_b64"]
        return {"company": "Path Corp"}

    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as temp:
        temp.write(b"\xff\xd8\xff\xe0fake")
        temp_path = temp.name

    try:
        client = FakeLLMClient(extract_handler=handler)
        dumped = asyncio.run(extract(_req(content=temp_path, content_format="image_path"), client)).model_dump()
    finally:
        Path(temp_path).unlink(missing_ok=True)

    assert dumped["company"] == "Path Corp"
    assert str(seen["image_b64"]).startswith("data:image/jpeg;base64,")


def test_invalid_base64_is_forwarded_without_crashing() -> None:
    seen = {}

    def handler(**kwargs: object) -> dict[str, object]:
        seen["image_b64"] = kwargs["image_b64"]
        return {"company": "Odd Corp"}

    client = FakeLLMClient(extract_handler=handler)
    req = _req(content="not valid base64 !!", content_format="image_base64")
    dumped = asyncio.run(extract(req, client)).model_dump()

    assert dumped["company"] == "Odd Corp"
    assert seen["image_b64"] == "not valid base64 !!"


def test_schema_shaping_preserves_nested_keys_and_extra_values() -> None:
    schema = """
    {
      "type": "object",
      "required": ["invoice", "line_items"],
      "properties": {
        "invoice": {
          "type": "object",
          "required": ["number", "total"],
          "properties": {
            "number": {"type": "string"},
            "total": {"type": ["string", "null"]}
          }
        },
        "line_items": {
          "type": "array",
          "items": {
            "type": "object",
            "required": ["sku", "qty", "description"],
            "properties": {
              "sku": {"type": "string"},
              "qty": {"type": "string"},
              "description": {"type": ["string", "null"]}
            }
          }
        }
      }
    }
    """
    client = FakeLLMClient(
        extract_handler=lambda **_: {
            "document_id": "WRONG",
            "invoice": {"number": "INV-7", "extra": "drop me"},
            "line_items": [{"sku": "A-1", "qty": "2", "ignored": "drop me"}],
            "hallucinated": "drop me",
        },
    )

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped == {
        "document_id": "DOC-1",
        "invoice": {"number": "INV-7", "extra": "drop me", "total": None},
        "line_items": [{"sku": "A-1", "qty": "2", "ignored": "drop me", "description": None}],
        "hallucinated": "drop me",
    }


def test_schema_shaping_adds_required_keys_not_declared_in_properties() -> None:
    schema = '{"type":"object","required":["claim_id"],"properties":{"status":{"type":"string"}}}'
    client = FakeLLMClient(extract_handler=lambda **_: {"status": "Open", "extra": "drop me"})

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped == {"document_id": "DOC-1", "status": "Open", "extra": "drop me", "claim_id": None}


def test_schema_shaping_resolves_local_defs_and_singleton_arrays() -> None:
    schema = """
    {
      "type": "object",
      "$defs": {
        "row": {
          "type": "object",
          "properties": {
            "code": {"type": "string"},
            "value": {"type": "string"}
          },
          "required": ["code", "value"]
        }
      },
      "properties": {
        "rows": {"type": "array", "items": {"$ref": "#/$defs/row"}}
      }
    }
    """
    client = FakeLLMClient(extract_handler=lambda **_: {"rows": {"code": "A", "extra": "drop me"}})

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped == {"document_id": "DOC-1", "rows": [{"code": "A", "extra": "drop me", "value": None}]}


def test_schema_shaping_maps_case_and_punctuation_variants_to_schema_keys() -> None:
    schema = """
    {
      "type": "object",
      "properties": {
        "firstName": {"type": "string"},
        "totalAmount": {"type": "number"},
        "isNewTherapy": {"type": "boolean"}
      }
    }
    """
    client = FakeLLMClient(
        extract_handler=lambda **_: {
            "First Name": "Mira",
            "TOTAL_AMOUNT": "$1,234.50",
            "is new therapy": "checked",
        },
    )

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped["firstName"] == "Mira"
    assert dumped["totalAmount"] == 1234.5
    assert dumped["isNewTherapy"] is True


def test_schema_shaping_converts_decimal_percent_when_schema_requests_it() -> None:
    schema = """
    {
      "type": "object",
      "properties": {
        "menPct": {
          "type": "number",
          "description": "Decimal representation of the percentage of men"
        }
      }
    }
    """
    client = FakeLLMClient(extract_handler=lambda **_: {"menPct": "41%"})

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped["menPct"] == 0.41


def test_schema_shaping_converts_numeric_percent_when_schema_requests_decimal() -> None:
    schema = """
    {
      "type": "object",
      "properties": {
        "womenPct": {
          "type": "number",
          "description": "Decimal representation of the percentage of women"
        }
      }
    }
    """
    client = FakeLLMClient(extract_handler=lambda **_: {"womenPct": 49})

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped["womenPct"] == 0.49


def test_schema_shaping_converts_number_multipliers() -> None:
    schema = '{"type":"object","properties":{"naturalizedCitizens":{"type":"integer"}}}'
    client = FakeLLMClient(extract_handler=lambda **_: {"naturalizedCitizens": "24 million"})

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped["naturalizedCitizens"] == 24_000_000


def test_missing_array_shapes_to_empty_list_instead_of_null() -> None:
    schema = '{"type":"object","properties":{"rows":{"type":"array","items":{"type":"object"}}}}'
    client = FakeLLMClient(extract_handler=lambda **_: {})

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped["rows"] == []


def test_sparse_schema_output_retries_json_object_mode_and_merges() -> None:
    schema = """
    {
      "type": "object",
      "properties": {
        "company": {"type": "string"},
        "phone": {"type": "string"},
        "rows": {"type": "array", "items": {"type": "object"}}
      }
    }
    """
    calls = {"n": 0}

    def handler(**kwargs: object) -> dict[str, object]:
        calls["n"] += 1
        if kwargs["json_schema"] is not None:
            return {"company": None, "phone": None, "rows": []}
        return {"Company": "Fallback Corp", "phone": "+1-555-0100", "rows": [{"sku": "A1"}]}

    client = FakeLLMClient(extract_handler=handler)
    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert calls["n"] == 2
    assert client.extract_calls[0]["json_schema"] is not None
    assert client.extract_calls[1]["json_schema"] is None
    assert dumped["company"] == "Fallback Corp"
    assert dumped["phone"] == "+1-555-0100"
    assert dumped["rows"] == [{"sku": "A1"}]


def test_dynamic_object_without_properties_preserves_map_values() -> None:
    schema = (
        '{"type":"object","properties":'
        '{"scoresByGroup":{"type":"object","additionalProperties":{"type":"number"}}}}'
    )
    client = FakeLLMClient(extract_handler=lambda **_: {"scoresByGroup": {"A": "10", "B": "20"}})

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped["scoresByGroup"] == {"A": 10, "B": 20}


def test_pattern_properties_shape_dynamic_keys() -> None:
    schema = """
    {
      "type": "object",
      "properties": {
        "measurements": {
          "type": "object",
          "patternProperties": {
            "^vital_": {"type": "number"}
          }
        }
      }
    }
    """
    client = FakeLLMClient(
        extract_handler=lambda **_: {
            "measurements": {"vital_o2": "98.5", "note": "stable"},
        },
    )

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped["measurements"] == {"vital_o2": 98.5, "note": "stable"}


def test_generic_schema_keys_can_be_filled_from_description_source_keys() -> None:
    schema = """
    {
      "type": "object",
      "properties": {
        "answer_01": {
          "type": "string",
          "description": "Company name. Output this source field under key answer_01; source label/key is 'company'."
        },
        "answer_02": {
          "type": "object",
          "description": "Output this source field under key answer_02; source label/key is 'demographics'.",
          "properties": {
            "answer_03": {
              "type": "number",
              "description": "Decimal representation. source label/key is 'menPct'."
            }
          }
        }
      }
    }
    """
    client = FakeLLMClient(
        extract_handler=lambda **_: {
            "company": "Pew Research Center",
            "demographics": {"menPct": "41%"},
        },
    )

    dumped = asyncio.run(extract(_req(json_schema=schema), client)).model_dump()

    assert dumped["answer_01"] == "Pew Research Center"
    assert dumped["answer_02"]["answer_03"] == 0.41


def test_build_user_embeds_schema() -> None:
    user = build_user({"type": "object", "properties": {"company": {"type": "string"}}})
    assert "SCHEMA:" in user
    assert "company" in user
    assert build_user(None).strip().endswith("Output JSON only.")
