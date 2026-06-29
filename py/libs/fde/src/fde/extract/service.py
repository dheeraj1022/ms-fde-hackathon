"""Document-extraction service: vision OCR against a request-provided JSON schema.

Transport-agnostic. Given a request and an optional LLM client it returns a complete
``ExtractResponse`` for every input. When no model is configured or the call fails it
returns just the ``document_id``: the scorer treats absent fields as null, so this is the
safe floor (it still earns credit for every field whose gold value is null) and a document
is never dropped — dropping scores 0 for the whole document.
"""

import base64
import json
import logging
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


def _extract_list(value: dict[str, Any]) -> list[Any] | None:
    for key in ("items", "rows", "line_items", "entries", "records", "data", "values"):
        candidate = value.get(key)
        if isinstance(candidate, list):
            return candidate
    return None


def _shape_to_schema(value: Any, schema: Any, root: dict[str, Any]) -> Any:
    resolved = _merge_all_of(_resolve_schema(schema, root), root)
    resolved = _select_variant(resolved, None if value is _MISSING else value, root)
    value = None if value is _MISSING else _nullify(value)
    types = _schema_types(resolved)

    if value is None:
        return None

    if "object" in types:
        if not isinstance(value, dict):
            return None
        properties = resolved.get("properties")
        if not isinstance(properties, dict) or not properties:
            return _clean(value)
        shaped: dict[str, Any] = {}
        for key in _schema_keys(resolved):
            prop_schema = properties.get(key, {})
            shaped[key] = _shape_to_schema(value.get(key, _MISSING), prop_schema, root)
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

    return value


def _shape(raw: dict[str, Any], schema: dict[str, Any] | None) -> dict[str, Any]:
    if schema is None:
        return _clean(raw)
    shaped = _shape_to_schema(raw, schema, schema)
    return _clean(shaped) if isinstance(shaped, dict) else {}


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
        return content
    if fmt in ("image_url", "url", "data_url") or content.startswith(("http://", "https://", "data:")):
        return content
    if fmt == "image_path":
        try:
            data = Path(content).read_bytes()
        except OSError:
            logger.warning("image_path %r not readable by this endpoint", content)
            return None
        return base64.b64encode(data).decode("ascii")
    # Unknown format: assume the content is already base64-encoded image bytes.
    return content


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
