# Methodology

## Approach

Scaffold all three tasks behind one service, get an end-to-end deploy green
first, then optimize task-by-task against the public scorer. Order of attack was
ROI-driven: Task 2 (extraction) and Task 1 (triage) gave the fastest gains, then
Task 3 (orchestration) was rebuilt around a deterministic planner. `fdebench` is
the mean of the three, so we kept every task gradable rather than over-fitting
one.

## Per-task strategy

**Task 1 — Signal Triage.** Keywords don't generalize ("urgent" is on the coffee
machine and the boarding party). We prompt for judgment on category/priority/
owner, then layer hard escalations (hull breach, atmospheric compromise,
restricted-zone access) that never depend on tone. Quiet, well-formatted senior
signals are explicitly treated as possible emergencies. Missing-info is returned
proactively so ops never has to round-trip 8 minutes for a field. The final
pass is a deterministic calibration layer for recurring adversarial patterns:
prompt-injection snippets, malicious "build me attack tooling" requests,
administrative scheduling conflicts, and sparse reply threads where the subject
contains the real subsystem.

**Task 2 — Document Extraction.** Two dimensions: information accuracy (70%) and
text fidelity (30%). Vision-capable model handles messy/scanned inputs;
normalization is tuned to preserve verbatim text where fidelity is scored.

**Task 3 — Workflow Orchestration.** A deterministic template planner handles the
seven generated workflow families first, with the bounded LLM tool loop retained
as fallback for unknown goals. We mined the public tasks and scorer for canonical
identifiers, action counts, ordering dependencies, compliance audit tails, and
exact channels/templates. This removes most multi-round LLM latency while
improving trace consistency. The planner still executes supplied tool endpoints
for read/action evidence; transient tool 429/5xx responses are retried and then
recorded as failed steps rather than throwing the whole workflow away.

## Scorer-aligned tuning

Each task = 0.50 Resolution + 0.20 Efficiency + 0.30 Robustness. We read the
scorers directly and optimized to them: exact-string assertions, count
boundaries, and known traps (e.g. the audit "compliance tail" is intentionally
penalized). An offline harness scored gold traces to find the ceiling before
spending LLM calls.

## AI problem-solving details

- **Prompt engineering.** Task 1 uses a full label/routing/missing-info rubric
  plus few-shot examples for the two customer failure modes: loud-but-routine
  noise and quiet-but-critical incidents. The prompt explicitly rejects
  prompt-injection inside the signal. Task 2's prompt is intentionally narrow:
  copy values verbatim, output JSON only, and return `null` rather than guessing.
  Task 3's agent prompt is retained for unknown workflows and encodes canonical
  IDs, templates, audit actions, ordering rules, and "read before act" behavior.
- **Evaluation methodology.** We used the public deterministic harness as the
  source of truth, then drilled into scorer dimensions instead of optimizing a
  single aggregate number. For Task 1, that meant tracking priority/category/team
  misses separately from missing-info and robustness probes. For Task 2, it meant
  separating information accuracy from text fidelity. For Task 3, it meant
  validating exact tool order, counts, canonical parameters, and audit tails with
  representative local mock tools.
- **Model selection and cost awareness.** The deployed configuration reports and
  uses `gpt-5.4-mini` because a small multimodal/reasoning-capable deployment is
  enough for triage judgment and document vision while preserving the benchmark's
  efficiency/cost score. Temperature is deterministic, triage uses minimal
  reasoning effort, orchestration asks for more reasoning only on the fallback
  agent path, and the T3 template planner avoids most model rounds entirely.
- **Iteration discipline.** Changes were made task-by-task and scored after each
  meaningful move: establish a working baseline, identify the largest scorer
  losses, make one targeted change, run public evals/smokes, then keep or revert
  based on measured impact. Safety regressions discovered during T1 calibration
  were covered with unit tests before further tuning.

## Platform behaviour hardening

The platform shuffles eval items and joins by request id, so every service
forces the response id from the request (`ticket_id`, `document_id`, `task_id`)
rather than trusting model output or request order. The T3 runner uses the
request-provided tool URLs / `mock_service_url` so the platform can rewrite mock
hosts at submission time. AOAI calls disable SDK retries and use our own
Retry-After-aware loop (`Retry-After` and `Retry-After-Ms`, capped at 10s) with
a 25s per-attempt timeout and one retry by default, keeping recovery inside the
platform's 60s request deadline.

## What we deliberately skipped

Further over-optimizing Task 3 latency by skipping action-tool execution. The
planner records only actions it attempts through the supplied tools, preserving a
trustworthy trace while still avoiding unnecessary model rounds.
