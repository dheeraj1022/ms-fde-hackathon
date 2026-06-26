"""Deep-space FDEBench solution library.

Shared building blocks for the three task services (triage / extract / orchestrate):

- ``fde.contracts`` — the official Pydantic task contracts (single source of truth).
- ``fde.config``    — settings (Azure OpenAI deployment, resilience knobs) via env / ``.env``.
- ``fde.llm``       — swappable async LLM client (Azure OpenAI) + a deterministic fake.
"""

__version__ = "0.1.0"

__all__ = ["__version__"]
