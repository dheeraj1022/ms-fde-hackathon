# Architecture

## System overview

One HTTPS service exposes all four endpoints required by FDEBench: `/health`,
`/triage`, `/extract`, `/orchestrate`. It is deployed as a single container on
Azure Container Apps and is intentionally small, layered, and degrade-safe — a
wrong route here is "a depressurized airlock", so every path has a
deterministic fallback.

```
Client ──HTTPS──▶ Azure Container App (FastAPI, uvicorn)
                    │
                    ├─ fde.platform   observability headers + uniform error envelope
                    ├─ fde.contracts  request/response validation (pydantic)
                    ├─ fde.triage     Task 1: classify / prioritize / route / gaps
                    ├─ fde.extract    Task 2: document → structured fields + fidelity
                    ├─ fde.orchestrate Task 3: deterministic planner + agent fallback
                    └─ fde.llm        Azure OpenAI client + resilience/fallback
                                         │
                                         └─▶ Azure OpenAI (gpt-5.4-mini, vision)
```

## Layers

- **Transport (`apps/sample/main.py`)** — thin FastAPI app. No business logic;
  it validates with shared contracts and delegates to one function per task.
- **Contracts (`fde.contracts`/`models`)** — pydantic request/response models,
  the single source of truth for I/O shape across server, tests, and eval.
- **Domain (`fde.triage` / `fde.extract` / `fde.orchestrate`)** — pure logic per
  task. Each accepts an optional LLM client; if it's `None` (no creds) it falls
  back to deterministic heuristics so the service never hard-fails. Task 3 uses
  a template planner before the LLM loop for scorer-stable workflows.
- **LLM (`fde.llm`)** — builds the Azure OpenAI client once at startup, owns
  sampling/reasoning-effort per task, retries, and timeouts.
- **Platform (`fde.platform`)** — installs latency/observability headers and a
  uniform error envelope so malformed input returns structured 4xx, not 500s.

## Endpoints

| Endpoint | Task | Output |
|---|---|---|
| `GET /health` | — | `{"status":"ok"}` |
| `POST /triage` | 1 | category, priority, owning team, missing info |
| `POST /extract` | 2 | structured fields + verbatim text fidelity |
| `POST /orchestrate` | 3 | tool-call trace satisfying workflow constraints |

## Design principles

- **Judgment over keywords** — the LLM decides category/priority/owner; hard
  rules only force escalation for non-negotiables (hull breach, atmospheric
  compromise, restricted-zone access).
- **Degrade-safe** — every endpoint returns a valid contract even with no
  credentials, malformed input, or upstream failure.
- **One service, one image** — simplest possible deploy + cold start; all tasks
  share the same client and platform middleware.

## Azure topology

- **Azure Container Apps** — public HTTPS, single revision, scales to handle
  the benchmark's concurrent burst.
- **Azure Container Registry** (`fdehackdyh8j`) — image `fde-triage:v4`.
- **Azure OpenAI** — vision-capable `gpt-5.4-mini` deployment; key injected as a
  Container App secret. Infra is codified in `infra/app` (Pulumi).
