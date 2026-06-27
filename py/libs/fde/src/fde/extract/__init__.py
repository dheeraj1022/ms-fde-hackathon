"""Task 2 — Document Extraction (vision OCR).

Public surface: ``extract`` (the service) and the prompt builders. The pipeline is a
single schema-guided vision call with light, scorer-aligned post-processing (null-sentinel
coercion), degrading to a document_id-only response when no model is configured or a call
fails so a document is never dropped.
"""

from fde.extract.prompt import SYSTEM
from fde.extract.prompt import build_user
from fde.extract.service import extract

__all__ = [
    "SYSTEM",
    "build_user",
    "extract",
]
