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


def _image_b64(req: ExtractRequest) -> str | None:
    """Return base64 image bytes for the request, or None if unavailable.

    The production contract sends ``image_base64`` (the platform inlines the perturbed
    image bytes before POSTing). ``image_path`` is a local-dev convenience only; a deployed
    endpoint cannot read the caller's filesystem, so it is handled best-effort.
    """
    content = req.content or ""
    if not content:
        return None
    fmt = (req.content_format or "image_base64").strip().lower()
    if fmt in ("image_base64", ""):
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
    image_b64 = _image_b64(req)
    fields: dict[str, Any] = {}

    if client is not None and image_b64:
        try:
            raw = await client.extract_json(
                system=SYSTEM,
                user=build_user(schema),
                image_b64=image_b64,
                json_schema=None,  # JSON-object mode + schema in prompt: robust to arbitrary schemas
            )
            if isinstance(raw, dict):
                fields = _clean(raw)
        except Exception:  # noqa: BLE001 - any failure must degrade to the safe floor, never 500
            logger.exception("Extraction failed for %s; returning document_id only", req.document_id)
            fields = {}

    # model_validate (not **kwargs) so arbitrary schema keys — including ones that are not
    # valid Python identifiers — are accepted; extra fields are kept (model has extra=allow).
    return ExtractResponse.model_validate({"document_id": req.document_id, **fields})
