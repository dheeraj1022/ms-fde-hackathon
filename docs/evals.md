# Evaluation Results

Composite = mean(Task1, Task2, Task3); each = 0.50 Resolution + 0.20 Efficiency
+ 0.30 Robustness. Numbers below are from the local harness
([py/apps/eval/run_eval.py](../py/apps/eval/run_eval.py)); Task 3 is scored
against a local server because the harness rewrites tool endpoints to
`127.0.0.1:9090`.

## Headline

| Task | Tier 1 | Resolution | Efficiency | Robustness | Errored |
|---|---|---|---|---|---|
| Signal Triage | ~74 | strong | good | strong | 0 |
| Document Extraction | ~86 | 0.85+ | good | strong | 0 |
| Workflow Orchestration | **98.1** | **98.4** | **96.0** | **99.0** | 0 |
| **FDEBench composite** | **~86.0** | | | | |

## Notes per task

**Task 1 — Triage.** Hard escalations (hull breach / atmospheric / restricted
zone) always fire; judgment on category/priority/owner. Missing-info returned
proactively. All robustness probes pass.

**Task 2 — Extraction.** Vision model on messy/scanned docs; info accuracy 70% /
fidelity 30%. Best per-task score; main loss is occasional verbatim drift.

**Task 3 — Orchestration.** Deterministic template planner first, LLM fallback
for unknown goals. The planner covers the seven generated workflow families,
executes required read/action tools, enforces exact canonical IDs/channels/audit
actions, and emits ordered traces. Latest local public-50 run: Tier 1 98.1,
Resolution 98.4, Efficiency 96.0, Robustness 99.0, P95 234ms, 0 errored.

## Known limitations / next

- Task 1 remains the main non-80 task; misses concentrate in priority and
  missing-info calibration.
- Task 3 is now comfortably above 80 without relying on multi-round model
  judgment; remaining lift should focus on Task 1 priority/missing-info.
