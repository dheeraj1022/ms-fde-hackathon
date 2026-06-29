# Architecture

## System overview

One HTTPS service exposes all four endpoints required by FDEBench: `/health`,
`/triage`, `/extract`, `/orchestrate`, plus operational surfaces
`/metrics`, `/metrics.json`, and `/dashboard`. It is deployed as a single
container on Azure Container Apps and is intentionally small, layered, and
degrade-safe — a wrong route here is "a depressurized airlock", so every path
has a deterministic fallback.

```
Client ──HTTPS──▶ Azure Container App (FastAPI, uvicorn)
                    │
                    ├─ fde.platform   observability headers + uniform error envelope
                    ├─ fde.metrics    Prometheus + live dashboard snapshots
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
  back to deterministic heuristics so the service never hard-fails. Task 1 adds
  deterministic post-model calibration for recurring adversarial triage traps;
  Task 3 uses a template planner before the LLM loop for scorer-stable workflows.
- **LLM (`fde.llm`)** — builds the Azure OpenAI client once at startup, owns
  sampling/reasoning-effort per task, Retry-After-aware retries, bounded
  concurrency, and short per-attempt timeouts that fit inside the platform's
  60s deadline.
- **Platform (`fde.platform`)** — installs latency/observability headers and a
  uniform error envelope so malformed input returns structured 4xx, not 500s.
- **Metrics (`fde.metrics`)** — keeps in-process route counts and latency
  summaries for `/metrics.json` and `/dashboard`; Prometheus exposition is
  available at `/metrics`, with Application Insights/Azure Monitor wired when
  configured.

## Endpoints

| Endpoint | Task | Output |
|---|---|---|
| `GET /health` | — | `{"status":"ok"}` |
| `GET /metrics` | Ops | Prometheus metrics |
| `GET /metrics.json` | Ops | Route counts, P50/P95 latency snapshot |
| `GET /dashboard` | Ops | Live HTML dashboard polling `/metrics.json` |
| `POST /triage` | 1 | category, priority, owning team, missing info |
| `POST /extract` | 2 | structured fields + verbatim text fidelity |
| `POST /orchestrate` | 3 | tool-call trace satisfying workflow constraints |

## Design principles

- **Judgment over keywords** — the LLM decides category/priority/owner; hard
  rules only force escalation for non-negotiables (hull breach, atmospheric
  compromise, restricted-zone access).
- **Degrade-safe** — every endpoint returns a valid contract even with no
  credentials, malformed input, or upstream failure.
- **Platform-aware retries** — AOAI calls honor `Retry-After` and
  `Retry-After-Ms` with capped delays; orchestration tool calls retry transient
  429/5xx responses and record durable failure traces instead of crashing.
- **One service, one image** — simplest possible deploy + cold start; all tasks
  share the same client and platform middleware.

## Trade-offs and scaling

- **Single service instead of per-task microservices.** The benchmark sends one
  endpoint URL and values cold-start/reliability more than independent task
  scaling. A single FastAPI process keeps deployment, health checks, headers,
  secrets, and middleware consistent. If extraction load dominated production
  traffic, `/extract` would be the first candidate to split because vision calls
  are the slowest and most quota-intensive path.
- **Deterministic planner before agent loop for Task 3.** A pure tool-calling
  agent was flexible but slower and less stable on generated workflow families.
  The template planner encodes the known workflow shapes, still executes the
  supplied tools for evidence, and falls back to the LLM loop for unknown goals.
- **Truthful traces over synthetic speed.** We deliberately do not skip action
  tool calls just to reduce latency. The orchestration response records only
  attempted tool work, with failed tools captured as failed steps, so the trace
  remains auditable.
- **Quota-aware AI calls.** Azure OpenAI work is bounded by a process-level
  semaphore, 25s per-attempt timeout, one retry, and capped `Retry-After` delays.
  Triage uses minimal reasoning effort; orchestration can request more reasoning
  only on the fallback path.
- **Stateless horizontal scale.** Request handling state is local to each request;
  the only process-local state is a bounded metrics ring buffer. Container Apps
  runs with min replicas for cold-start protection and max replicas for burst
  handling. `/metrics.json` is intentionally a per-replica live view; durable
  fleet telemetry goes to Log Analytics/Application Insights.

## Azure topology

- **Azure Container Apps** — public HTTPS, single revision, scales to handle
  the benchmark's concurrent burst. Current deployed image: `fde-triage:v9`.
- **Azure Container Registry** (`fdehackdyh8j`) — submission image repository
  `fde-triage`.
- **Log Analytics + Application Insights** — centralized telemetry when the
  deployment injects `APPLICATIONINSIGHTS_CONNECTION_STRING`; local/dev runs
  no-op if the SDK or connection string is absent.
- **Azure OpenAI** — vision-capable `gpt-5.4-mini` deployment; key injected as a
  Container App secret. Image pulls use managed identity with `AcrPull`; infra is
  codified in `infra/app` (Pulumi).
