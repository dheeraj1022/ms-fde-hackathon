"""Prompt construction for Task 2 document extraction (vision OCR).

Kept separate from transport and the model client. The system prompt is the main accuracy
lever and is tuned to the scorer, which rewards two things: values transcribed *verbatim*
("text fidelity") and *correct nulls* — predicting null for an absent field earns full
credit, while inventing a value earns zero. So the dominant instructions are: copy exactly
what is on the page, and return null rather than guess.
"""

import json
from typing import Any

SYSTEM = """\
You are a meticulous OCR extraction engine for a deep-space station's document archive.
You receive ONE document image and a JSON schema naming the fields to extract.

Return a single JSON object containing exactly the fields named in the schema. Rules:

1. TRANSCRIBE VERBATIM. Copy each value exactly as printed on the page: same spelling,
   capitalization, punctuation, spacing, and digits. Do not reformat dates, numbers,
   currency, or units; do not translate, expand abbreviations, or "tidy up" text.
2. RETURN null WHEN ABSENT. If a field's value is missing, blank, illegible, or simply not
   stated in the document, return null for it. Never guess, infer, derive, or fabricate.
   A correct null earns full credit; a wrong value earns nothing.
3. FOLLOW EACH FIELD DESCRIPTION. The schema's per-field descriptions say where on the page
   to look and how the value should be captured. Respect them precisely.
4. PRESERVE THE SCHEMA SHAPE. Keep nested objects nested and arrays as arrays. Do not
   flatten, rename, summarize, merge, or add fields. Every object you return must contain
   the keys listed for that object in the schema.
5. EXTRACT EVERY FIELD AND EVERY ROW. Include all fields the schema lists. For arrays and
   nested objects, extract every row / line item / entry visible in the document, in order,
   leaving inner fields null where a cell is empty.
6. OUTPUT JSON ONLY. Emit strictly valid JSON: no markdown fences, no comments, no prose.
"""


def build_user(schema: dict[str, Any] | None) -> str:
    """Build the user instruction, embedding the per-document schema when present."""
    if not schema:
        return (
            "Extract all clearly labeled fields and their values from this document image "
            "as a flat JSON object. Transcribe values exactly as they appear; use null for "
            "anything not present or not legible. Output JSON only."
        )
    schema_str = json.dumps(schema, ensure_ascii=False, indent=2)
    return (
        "Extract the fields defined by this JSON schema from the document image.\n\n"
        f"SCHEMA:\n{schema_str}\n\n"
        "Return one JSON object matching this schema shape exactly. Keep nested objects "
        "and arrays nested; do not flatten, rename, or add fields. Transcribe each value "
        "exactly as it appears in the document. For any field that is not present or not "
        "legible, return null. Extract every row for array fields. Output JSON only."
    )


__all__ = ["SYSTEM", "build_user"]
