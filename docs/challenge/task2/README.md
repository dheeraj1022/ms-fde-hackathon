# Task 2: Document Extraction

`POST /extract`

Given a document image (receipt, invoice, form, financial statement, etc.) and a JSON schema describing the expected output structure, extract all relevant data into structured JSON. The scoring cares about getting the right values with the right structure, not about how the output reads.

Read the background:

- [customer_brief.md](customer_brief.md) — what the customer needs
- [field_guide.md](field_guide.md) — practical extraction tips
- [engineering_review.md](engineering_review.md) — what judges look for

## Request contract

Input fields:

- `document_id`
- `content` — relative path to the document image file (e.g., `images/DOC-OCR-0869.png`), resolved against the directory containing `public_eval_50.json`
- `content_format` — `"image_path"` (the hidden eval may use other formats)
- `json_schema` — JSON schema describing the expected output structure (each document has a different schema)

The public-eval images live next to the input file at [`py/data/task2/images/`](../../../py/data/task2/images/) and are loaded directly from disk:

```python
from pathlib import Path
import json

task2_dir = Path("py/data/task2")
records = json.loads((task2_dir / "public_eval_50.json").read_text())
image_bytes = (task2_dir / records[0]["content"]).read_bytes()
```

See [../../../py/data/task2/input_schema.json](../../../py/data/task2/input_schema.json) for the formal schema.

## Response contract

Required output fields:

- `document_id` — must match the input
- All fields specified in the `json_schema` from the request

The output schema varies per document. One document might ask for `firstName`, `address`, `phone`. Another might ask for `tableData`, `institution`, `portfolioSummary`. Your endpoint must read the `json_schema` and return matching structured JSON.

See [../../../py/data/task2/output_schema.json](../../../py/data/task2/output_schema.json) for the formal schema.

## Resolution scoring

```
resolution = (0.70 x information_accuracy + 0.30 x text_fidelity) x 100
```

| Dimension | Weight | Metric |
|---|---|---|
| `information_accuracy` | 70% | Recursive field F1 with value normalization — did you extract the correct data? |
| `text_fidelity` | 30% | Recursive field exact-match — did you preserve exact formatting? |

**Information Accuracy** uses a format-stripping normalizer: `$1,234.56` becomes `1234.56`, `10%` becomes `10`. If you extract the right value in a different format, you still get credit.

**Text Fidelity** uses a light normalizer (lowercase, collapse whitespace). If you also match the exact formatting, you get the full score.

**Per-field scoring by type:**
- Strings: token F1 (information) / exact match (fidelity)
- Numbers: 1% relative tolerance
- Booleans: exact match
- Lists: set F1 with fuzzy element alignment (information) / strict set F1 (fidelity)
- Nested objects: recursive field-mean

## What's hard

Every document has a different schema, so you can't hardcode field names. Receipts, invoices, medical forms, financial statements, charts. Some have tables, some have nested sections. ~36% of documents are adversarial: photographed, scanned, handwritten, degraded image quality.

## Tips

- Read the `json_schema` from the request. It tells you exactly what fields to extract.
- Use a vision model (the input is an image, not text).
- Return `null` for fields you can't extract. Don't hallucinate.
- Tables are common. Financial data, medical forms, and invoices all have tabular content.
