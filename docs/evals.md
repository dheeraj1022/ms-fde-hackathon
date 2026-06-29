# Evaluation Results

Composite = mean(Task1, Task2, Task3); each = 0.50 Resolution + 0.20 Efficiency
+ 0.30 Robustness. Numbers below are from the official public-50 harness
([py/apps/eval/run_eval.py](../py/apps/eval/run_eval.py)). Task 1 and Task 2
were run against the deployed HTTPS service. Task 3 is scored against a local
server because the harness rewrites tool endpoints to `127.0.0.1:9090`, which a
remote Container App cannot reach.

## Headline

| Task | Tier 1 | Resolution | Efficiency | Robustness | Errored |
|---|---|---|---|---|---|
| Signal Triage | **84.3** | **87.5** | **64.1** | **92.5** | 0 |
| Document Extraction | **86.4** | **85.6** | **81.1** | **91.4** | 0 |
| Workflow Orchestration | **98.1** | **98.4** | **96.0** | **99.0** | 0 |
| **FDEBench composite** | **~89.6** | | | | |

## Notes per task

**Task 1 — Triage.** Latest measured live public-50 run: Tier 1 84.3,
Resolution 87.5, Efficiency 64.1, Robustness 92.5, P95 2125ms, 0 errored. Hard
escalations (hull breach / atmospheric / restricted zone) always fire; judgment
on category/priority/owner comes from the model, then a deterministic
calibration layer corrects recurring adversarial patterns such as prompt
injection, harmful tooling requests, admin scheduling noise, and sparse reply
threads. Missing-info returned proactively. All robustness probes pass.

**Task 2 — Extraction.** Latest measured live public-50 run: Tier 1 86.4,
Resolution 85.6, Efficiency 81.1, Robustness 91.4, P95 10281ms, 0 errored.
Vision model on messy/scanned docs; resolution split was information accuracy
0.873 and text fidelity 0.814.

**Task 3 — Orchestration.** Deterministic template planner first, LLM fallback
for unknown goals. The planner covers the seven generated workflow families,
executes required read/action tools, enforces exact canonical IDs/channels/audit
actions, and emits ordered traces. Latest representative local public-50 run
with official mock tools: Tier 1 98.1, Resolution 98.4, Efficiency 96.0,
Robustness 99.0, P95 234ms, 0 errored.

## Known limitations / next

- Task 1 is above 80 on the deployed public-50 run; remaining losses are mostly
  priority and missing-info nuance.
- Task 3 is comfortably above 80 without relying on multi-round model judgment.
- Current deployed v9 keeps the measured prediction logic and adds platform
  checklist hardening: shorter AOAI timeout/retry budget, `Retry-After-Ms`
  support, capped retry delays, and transient T3 tool retries.
