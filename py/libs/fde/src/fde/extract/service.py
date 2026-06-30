"""Document-extraction service: vision OCR against a request-provided JSON schema.

Transport-agnostic. Given a request and an optional LLM client it returns a complete
``ExtractResponse`` for every input. When no model is configured or the call fails it
returns just the ``document_id``: the scorer treats absent fields as null, so this is the
safe floor (it still earns credit for every field whose gold value is null) and a document
is never dropped — dropping scores 0 for the whole document.
"""

import base64
import binascii
import json
import logging
import re
from pathlib import Path
from typing import Any

from fde.contracts import ExtractRequest
from fde.contracts import ExtractResponse
from fde.extract.prompt import SYSTEM
from fde.extract.prompt import build_user
from fde.llm import LLMClient

logger = logging.getLogger(__name__)

# Leaf strings that mean "no value". Coerced to null because the scorer gives full credit
# for a correct null but zero for a non-null placeholder against a null gold value, and
# never less than the placeholder would have scored against a non-null gold value.
_NULL_SENTINELS = frozenset(
    {
        "",
        "null",
        "none",
        "n/a",
        "na",
        "nil",
        "not present",
        "not available",
        "not specified",
        "not provided",
        "not applicable",
        "not legible",
        "not visible",
        "unknown",
        "--",
        "-",
    }
)

# Keys the scorer ignores; we always set document_id ourselves, so drop any from the model.
_RESERVED_KEYS = frozenset({"document_id", "difficulty"})
_MISSING = object()
_SPARSE_RETRY_THRESHOLD = 0.50


def _parse_schema(raw: str | None) -> dict[str, Any] | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        logger.warning("Could not parse json_schema; proceeding without a schema")
        return None
    return parsed if isinstance(parsed, dict) else None


def _nullify(value: Any) -> Any:
    """Recursively coerce null-sentinel strings to None (boosts correct-null credit)."""
    if isinstance(value, str):
        return None if value.strip().lower() in _NULL_SENTINELS else value
    if isinstance(value, list):
        return [_nullify(v) for v in value]
    if isinstance(value, dict):
        return {k: _nullify(v) for k, v in value.items()}
    return value


def _clean(raw: dict[str, Any]) -> dict[str, Any]:
    return {k: _nullify(v) for k, v in raw.items() if k not in _RESERVED_KEYS}


def _key_token(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", key.lower())


def _has_signal(value: Any) -> bool:
    value = _nullify(value)
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, list):
        return any(_has_signal(item) for item in value)
    if isinstance(value, dict):
        return any(_has_signal(v) for k, v in value.items() if k not in _RESERVED_KEYS)
    return True


def _find_value_for_key(raw: dict[str, Any], key: str) -> Any:
    if key in raw and _has_signal(raw[key]):
        return raw[key]
    target = _key_token(key)
    fallback = _MISSING
    for raw_key, value in raw.items():
        if _key_token(str(raw_key)) != target:
            continue
        if _has_signal(value):
            return value
        if fallback is _MISSING:
            fallback = value
    if key in raw:
        return raw[key]
    return fallback


def _description_source_keys(schema: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    for attr in ("title", "description"):
        text = schema.get(attr)
        if not isinstance(text, str):
            continue
        for pattern in (
            r"source (?:label/)?key is ['\"]([^'\"]+)['\"]",
            r"source field(?: under key [^;,.]+)?(?: is|:)\s*['\"]?([A-Za-z0-9_. -]+)['\"]?",
            r"field(?: named)? ['\"]([^'\"]+)['\"]",
        ):
            for match in re.finditer(pattern, text, re.IGNORECASE):
                candidate = match.group(1).strip(" .,:;\"'")
                if candidate and candidate not in keys:
                    keys.append(candidate)
    return keys


def _find_value_for_property(raw: dict[str, Any], key: str, schema: dict[str, Any]) -> Any:
    value = _find_value_for_key(raw, key)
    if value is not _MISSING:
        return value
    for source_key in _description_source_keys(schema):
        value = _find_value_for_key(raw, source_key)
        if value is not _MISSING:
            return value
    return _MISSING


def _lookup_ref(root: dict[str, Any], ref: str) -> dict[str, Any] | None:
    if not ref.startswith("#/"):
        return None
    cur: Any = root
    for part in ref[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(cur, dict) or key not in cur:
            return None
        cur = cur[key]
    return cur if isinstance(cur, dict) else None


def _resolve_schema(schema: Any, root: dict[str, Any], seen: frozenset[str] = frozenset()) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref not in seen:
        target = _lookup_ref(root, ref)
        if target is not None:
            overrides = {k: v for k, v in schema.items() if k != "$ref"}
            return _resolve_schema({**target, **overrides}, root, seen | {ref})
    return schema


def _merge_all_of(schema: dict[str, Any], root: dict[str, Any]) -> dict[str, Any]:
    parts = schema.get("allOf")
    if not isinstance(parts, list):
        return schema
    merged = {k: v for k, v in schema.items() if k != "allOf"}
    properties: dict[str, Any] = {}
    required: list[str] = []
    for part in parts:
        resolved = _resolve_schema(part, root)
        if isinstance(resolved.get("properties"), dict):
            properties.update(resolved["properties"])
        if isinstance(resolved.get("required"), list):
            required.extend(str(k) for k in resolved["required"])
        for key, value in resolved.items():
            if key not in {"properties", "required"}:
                merged.setdefault(key, value)
    if properties:
        properties.update(merged.get("properties", {}) if isinstance(merged.get("properties"), dict) else {})
        merged["properties"] = properties
    if required:
        existing = merged.get("required", [])
        required.extend(str(k) for k in existing if isinstance(k, str))
        merged["required"] = list(dict.fromkeys(required))
    return merged


def _schema_types(schema: dict[str, Any]) -> set[str]:
    raw = schema.get("type")
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(t) for t in raw if isinstance(t, str)}
    if isinstance(schema.get("properties"), dict):
        return {"object"}
    if "items" in schema:
        return {"array"}
    return set()


def _allows_null(schema: dict[str, Any]) -> bool:
    return "null" in _schema_types(schema)


def _kind_matches(value: Any, schema: dict[str, Any]) -> bool:
    types = _schema_types(schema)
    if not types:
        return True
    if value is None:
        return "null" in types
    if isinstance(value, dict):
        return "object" in types
    if isinstance(value, list):
        return "array" in types
    if isinstance(value, bool):
        return "boolean" in types
    if isinstance(value, int | float):
        return bool(types & {"number", "integer"})
    if isinstance(value, str):
        return "string" in types
    return False


def _select_variant(schema: dict[str, Any], value: Any, root: dict[str, Any]) -> dict[str, Any]:
    for key in ("oneOf", "anyOf"):
        variants = schema.get(key)
        if not isinstance(variants, list):
            continue
        resolved = [_merge_all_of(_resolve_schema(v, root), root) for v in variants if isinstance(v, dict)]
        if value is None and any("null" in _schema_types(v) for v in resolved):
            return {"type": "null"}
        for variant in resolved:
            if "null" not in _schema_types(variant) and _kind_matches(value, variant):
                return variant
        for variant in resolved:
            if "null" not in _schema_types(variant):
                return variant
    return schema


def _schema_keys(schema: dict[str, Any]) -> list[str]:
    keys: list[str] = []
    properties = schema.get("properties")
    if isinstance(properties, dict):
        keys.extend(str(k) for k in properties)
    required = schema.get("required")
    if isinstance(required, list):
        keys.extend(str(k) for k in required if isinstance(k, str))
    return list(dict.fromkeys(keys))


def _schema_for_dynamic_key(schema: dict[str, Any], key: str) -> dict[str, Any] | None:
    pattern_properties = schema.get("patternProperties")
    if isinstance(pattern_properties, dict):
        for pattern, subschema in pattern_properties.items():
            if not isinstance(pattern, str) or not isinstance(subschema, dict):
                continue
            try:
                if re.search(pattern, key):
                    return subschema
            except re.error:
                continue
    additional = schema.get("additionalProperties")
    return additional if isinstance(additional, dict) else None


def _extract_list(value: dict[str, Any]) -> list[Any] | None:
    for key in ("items", "rows", "line_items", "entries", "records", "data", "values"):
        candidate = value.get(key)
        if isinstance(candidate, list):
            return candidate
    return None


def _wants_decimal_percent(schema: dict[str, Any]) -> bool:
    text = " ".join(
        str(schema.get(key, "")).lower()
        for key in ("title", "description")
    )
    return "decimal representation" in text or "decimal form" in text


def _coerce_number(value: Any, schema: dict[str, Any]) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int | float):
        number = float(value)
        if _wants_decimal_percent(schema) and 1 < abs(number) <= 100:
            number /= 100
        return int(number) if "integer" in _schema_types(schema) else number
    if not isinstance(value, str):
        return value
    text = value.strip()
    if not text:
        return None
    negative = text.startswith("(") and text.endswith(")")
    match = re.search(r"-?\d[\d,]*(?:\.\d+)?", text)
    if not match:
        return value
    number = float(match.group(0).replace(",", ""))
    if negative:
        number = -abs(number)
    suffix = text[match.end():].strip().lower()
    if re.match(r"^(m|mn|million)\b", suffix):
        number *= 1_000_000
    elif re.match(r"^(b|bn|billion)\b", suffix):
        number *= 1_000_000_000
    elif re.match(r"^(k|thousand)\b", suffix):
        number *= 1_000
    if ("%" in text or re.search(r"\bpercent(?:age)?\b", suffix)) and _wants_decimal_percent(schema):
        number /= 100
    if "integer" in _schema_types(schema):
        return int(round(number))
    return number


def _coerce_boolean(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int | float):
        return bool(value)
    if not isinstance(value, str):
        return value
    token = value.strip().lower()
    if token in {"true", "yes", "y", "checked", "selected", "x", "1", "pass", "passed"}:
        return True
    if token in {"false", "no", "n", "unchecked", "unselected", "0", "fail", "failed"}:
        return False
    return value


def _coerce_scalar(value: Any, schema: dict[str, Any]) -> Any:
    types = _schema_types(schema)
    if types & {"number", "integer"}:
        return _coerce_number(value, schema)
    if "boolean" in types:
        return _coerce_boolean(value)
    return value


def _shape_to_schema(value: Any, schema: Any, root: dict[str, Any]) -> Any:
    resolved = _merge_all_of(_resolve_schema(schema, root), root)
    resolved = _select_variant(resolved, None if value is _MISSING else value, root)
    value = None if value is _MISSING else _nullify(value)
    types = _schema_types(resolved)

    if value is None:
        if "array" in types and not _allows_null(resolved):
            return []
        return None

    if "object" in types:
        if not isinstance(value, dict):
            return None
        preserved = _clean(value)
        properties = resolved.get("properties")
        shaped: dict[str, Any] = {}
        schema_key_set = set(_schema_keys(resolved))
        for raw_key, raw_value in preserved.items():
            dynamic_schema = None if raw_key in schema_key_set else _schema_for_dynamic_key(resolved, raw_key)
            shaped[raw_key] = (
                _shape_to_schema(raw_value, dynamic_schema, root)
                if dynamic_schema is not None
                else raw_value
            )
        if not isinstance(properties, dict) or not properties:
            return shaped
        for key in _schema_keys(resolved):
            prop_schema = properties.get(key, {})
            shaped[key] = _shape_to_schema(_find_value_for_property(preserved, key, prop_schema), prop_schema, root)
        return shaped

    if "array" in types:
        item_schema = resolved.get("items", {})
        if isinstance(value, list):
            return [_shape_to_schema(item, item_schema, root) for item in value]
        if isinstance(value, dict):
            nested = _extract_list(value)
            if nested is not None:
                return [_shape_to_schema(item, item_schema, root) for item in nested]
            return [_shape_to_schema(value, item_schema, root)]
        return None

    return _coerce_scalar(value, resolved)


def _shape(raw: dict[str, Any], schema: dict[str, Any] | None) -> dict[str, Any]:
    if schema is None:
        return _clean(raw)
    shaped = _shape_to_schema(raw, schema, schema)
    return _clean(shaped) if isinstance(shaped, dict) else {}


def _schema_slot_count(schema: Any, root: dict[str, Any]) -> int:
    resolved = _merge_all_of(_resolve_schema(schema, root), root)
    resolved = _select_variant(resolved, None, root)
    types = _schema_types(resolved)
    properties = resolved.get("properties")
    if "object" in types and isinstance(properties, dict) and properties:
        return sum(
            max(_schema_slot_count(properties.get(key, {}), root), 1)
            for key in _schema_keys(resolved)
        )
    if "array" in types:
        return 1
    return 1


def _present_slot_count(value: Any, schema: Any, root: dict[str, Any]) -> int:
    resolved = _merge_all_of(_resolve_schema(schema, root), root)
    resolved = _select_variant(resolved, value, root)
    types = _schema_types(resolved)
    properties = resolved.get("properties")
    if "object" in types and isinstance(properties, dict) and properties:
        if not isinstance(value, dict):
            return 0
        return sum(
            _present_slot_count(
                _find_value_for_property(value, key, properties.get(key, {})),
                properties.get(key, {}),
                root,
            )
            for key in _schema_keys(resolved)
        )
    return 1 if _has_signal(value) else 0


def _schema_coverage(raw: dict[str, Any], schema: dict[str, Any] | None) -> float:
    if schema is None:
        return 1.0 if _has_signal(raw) else 0.0
    total = _schema_slot_count(schema, schema)
    return _present_slot_count(raw, schema, schema) / total if total else 1.0


def _signal_count(value: Any) -> int:
    value = _nullify(value)
    if value is None:
        return 0
    if isinstance(value, dict):
        return sum(_signal_count(v) for k, v in value.items() if k not in _RESERVED_KEYS)
    if isinstance(value, list):
        return sum(_signal_count(v) for v in value)
    if isinstance(value, str):
        return 1 if value.strip() else 0
    return 1


def _merge_raw(primary: Any, fallback: Any) -> Any:
    if not _has_signal(primary) and _has_signal(fallback):
        return fallback
    if isinstance(primary, dict) and isinstance(fallback, dict):
        merged = dict(primary)
        for key, value in fallback.items():
            if key in _RESERVED_KEYS:
                continue
            merged[key] = _merge_raw(merged[key], value) if key in merged else value
        return merged
    if isinstance(primary, list) and isinstance(fallback, list):
        return fallback if _signal_count(fallback) > _signal_count(primary) else primary
    return primary


def _image_mime(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "image/webp"
    if data.startswith(b"BM"):
        return "image/bmp"
    if data.startswith((b"II*\x00", b"MM\x00*")):
        return "image/tiff"
    return "image/png"


def _base64_data_url(content: str) -> str:
    compact = "".join(content.split())
    try:
        data = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return content
    return f"data:{_image_mime(data)};base64,{compact}"


def _image_ref(req: ExtractRequest) -> str | None:
    """Return an image reference for the model, or None if unavailable.

    The production contract sends ``image_base64`` (the platform inlines the perturbed
    image bytes before POSTing). Hidden evals may use other formats, so URL/data-URL
    payloads are passed through. ``image_path`` is a local-dev convenience only; a deployed
    endpoint cannot read the caller's filesystem, so it is handled best-effort.
    """
    content = req.content or ""
    if not content:
        return None
    fmt = (req.content_format or "image_base64").strip().lower()
    if fmt in ("image_base64", "base64", ""):
        if content.startswith("data:"):
            return content
        return _base64_data_url(content)
    if fmt in ("image_url", "url", "data_url") or content.startswith(("http://", "https://", "data:")):
        return content
    if fmt == "image_path":
        try:
            data = Path(content).read_bytes()
        except OSError:
            logger.warning("image_path %r not readable by this endpoint", content)
            return None
        return f"data:{_image_mime(data)};base64,{base64.b64encode(data).decode('ascii')}"
    # Unknown format: assume the content is already base64-encoded image bytes.
    return _base64_data_url(content)


async def extract(req: ExtractRequest, client: LLMClient | None) -> ExtractResponse:
    """Extract structured fields from a document image per its request-provided schema."""
    schema = _parse_schema(req.json_schema)
    image_ref = _image_ref(req)
    fields: dict[str, Any] = {}

    if client is not None and image_ref:
        try:
            try:
                raw = await client.extract_json(
                    system=SYSTEM,
                    user=build_user(schema),
                    image_b64=image_ref,
                    json_schema=schema,
                )
                if (
                    isinstance(raw, dict)
                    and schema is not None
                    and _schema_coverage(raw, schema) < _SPARSE_RETRY_THRESHOLD
                ):
                    fallback = await client.extract_json(
                        system=SYSTEM,
                        user=build_user(schema),
                        image_b64=image_ref,
                        json_schema=None,
                    )
                    if isinstance(fallback, dict):
                        raw = _merge_raw(raw, fallback)
            except Exception:
                if schema is None:
                    raise
                logger.warning(
                    "Schema-constrained extraction failed for %s; retrying JSON-object mode",
                    req.document_id,
                    exc_info=True,
                )
                raw = await client.extract_json(
                    system=SYSTEM,
                    user=build_user(schema),
                    image_b64=image_ref,
                    json_schema=None,
                )
            if isinstance(raw, dict):
                fields = _shape(raw, schema)
        except Exception:  # noqa: BLE001 - any failure must degrade to the safe floor, never 500
            logger.exception("Extraction failed for %s; returning document_id only", req.document_id)
            fields = {}

    # model_validate (not **kwargs) so arbitrary schema keys — including ones that are not
    # valid Python identifiers — are accepted; extra fields are kept (model has extra=allow).
    return ExtractResponse.model_validate({"document_id": req.document_id, **fields})
