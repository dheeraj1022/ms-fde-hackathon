# syntax=docker/dockerfile:1
#
# Container image for the FDEBench served app (apps/sample), which exposes all four
# endpoints (/health /triage /extract /orchestrate). This is a uv *workspace*: the app
# depends on workspace members (fde -> ms-common-models), so the whole py/ tree is the
# build context and is installed together from the committed uv.lock for reproducibility.
#
# Secrets (Azure OpenAI key, etc.) are NOT baked in — they are injected at runtime as
# Container App env vars / secrets. See .env.example for the full list.

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy the entire workspace (app + libs + common members) so uv can resolve the graph.
COPY . /app

# Install exactly the sample app's dependency closure (sample -> fde -> ms-common-models
# + fastapi/uvicorn/openai/...), from the frozen lockfile, without dev/test deps.
RUN uv sync --frozen --no-dev --package sample

# Put the workspace venv on PATH so uvicorn is the container entrypoint directly.
ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /app/apps/sample

EXPOSE 8000

# --timeout-keep-alive 75 keeps idle keep-alive connections open long enough to survive the
# benchmark's slow_followup resilience probe.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "75"]
