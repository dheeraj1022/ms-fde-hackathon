"""Runtime configuration for the FDE solution.

Settings come from environment variables (production: injected by the host / Key Vault)
or a local ``.env`` file (development). Secrets never live in source control — commit
``.env.example`` and keep your real ``.env`` gitignored.

The model is intentionally *configurable*: a single multimodal Azure OpenAI deployment
(default ``gpt-4.1-mini``) powers all three tasks, and ``AOAI_VISION_DEPLOYMENT`` can
override the deployment used for the vision-based ``/extract`` task if you have a separate
one. Smaller/cheaper models score better on the benchmark's efficiency dimension, so the
default leans small.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings
from pydantic_settings import SettingsConfigDict


class Settings(BaseSettings):
    """Process configuration, read from env vars / ``.env`` (case-insensitive)."""

    model_config = SettingsConfigDict(
        # Local dev: read .env from the run cwd (apps/sample) or the py root (../../).
        # Production: real environment variables (injected by the host) take precedence.
        env_file=(".env", "../../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
        protected_namespaces=(),
    )

    # --- Azure OpenAI connection ---
    azure_openai_endpoint: str = ""          # AZURE_OPENAI_ENDPOINT
    azure_openai_api_key: str = ""           # AZURE_OPENAI_API_KEY
    azure_openai_api_version: str = "2024-10-21"  # AZURE_OPENAI_API_VERSION

    # --- Deployments ---
    aoai_deployment: str = "gpt-4.1-mini"    # AOAI_DEPLOYMENT (used for triage + orchestrate)
    aoai_vision_deployment: str = ""         # AOAI_VISION_DEPLOYMENT (override for /extract)

    # Reported in the X-Model-Name header for the platform's cost scoring.
    model_name: str = "gpt-4.1-mini"         # MODEL_NAME

    # --- Resilience / efficiency knobs ---
    request_timeout_s: float = 30.0          # REQUEST_TIMEOUT_S (per-attempt deadline)
    max_retries: int = 3                     # MAX_RETRIES (on 429/timeout/5xx)
    retry_base_delay_s: float = 1.0          # RETRY_BASE_DELAY_S (exponential backoff base)
    max_concurrency: int = 8                 # MAX_CONCURRENCY (in-flight LLM calls)
    llm_temperature: float = 0.0             # LLM_TEMPERATURE

    @property
    def configured(self) -> bool:
        """True when Azure OpenAI credentials are present (else use deterministic fallback)."""
        return bool(self.azure_openai_endpoint and self.azure_openai_api_key)

    @property
    def vision_deployment(self) -> str:
        """Deployment to use for vision; falls back to the primary deployment."""
        return self.aoai_vision_deployment or self.aoai_deployment


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
