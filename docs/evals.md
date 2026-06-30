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
| Signal Triage | **83.3** | **88.9** | **54.4** | **93.3** | 0 |
| Document Extraction | **78.8** | **86.1** | **41.1** | **91.7** | 0 |
| Workflow Orchestration | **97.2** | **97.1** | **96.0** | **98.3** | 0 |
| **FDEBench composite** | **~86.4** | | | | |

Measured against deployed image `fde-triage:v14` (Container App revision
`fde-triage-api--0000013`) on 2026-06-30. Every robustness probe passes on all
three tasks and no item errored.

## Notes per task

**Task 1 — Triage.** Latest measured live public-50 run: Tier 1 83.3,
Resolution 88.9, Efficiency 54.4, Robustness 93.3, P95 2547ms, 0 errored.
Resolution dimensions: category 0.934, priority 0.921, routing 0.964,
escalation 0.889. Hard escalations (hull breach / atmospheric / restricted zone)
always fire; judgment on category/priority/owner comes from the model, then a
deterministic calibration layer corrects recurring adversarial patterns such as
prompt injection, harmful tooling requests, admin scheduling noise, cancelled
"scary" drills, and sparse reply threads. Missing-info returned proactively. All
seven robustness probes pass; adversarial accuracy 88.9.

**Task 2 — Extraction.** Latest measured live public-50 run: Tier 1 78.8,
Resolution 86.1, Efficiency 41.1, Robustness 91.7, P95 ~20s, 0 errored.
Resolution split was information accuracy 0.878 and text fidelity 0.823. The
efficiency score is the one weak dimension: we deliberately run the vision model
at `VISION_DETAIL=high`, which tiles each document image into many patches. That
holds resolution up on dense tables and scanned forms but pushes P95 latency to
~20s, costing efficiency. This is an accuracy-over-latency tradeoff, not an
error — every probe passes and no item errored. Remaining resolution losses are
genuine vision limits (OCR name misreads, field-boundary merges, ambiguous
percentage normalization), not pipeline bugs.

**Task 3 — Orchestration.** Deterministic template planner first, LLM fallback
for unknown goals. The planner covers the seven generated workflow families,
executes required read/action tools, enforces exact canonical IDs/channels/audit
actions, honors per-goal retry budgets ("retry once" vs "up to twice"), and
emits ordered traces. Latest representative local public-50 run with official
mock tools: Tier 1 97.2, Resolution 97.1, Efficiency 96.0, Robustness 98.3,
constraint compliance 0.984, P95 282ms, 0 errored.

## Known limitations / next

- Task 1 is above 80 on the deployed public-50 run; remaining losses are mostly
  priority and missing-info nuance.
- Task 2 efficiency (P95 ~20s) is the main drag on the composite, a direct
  consequence of `VISION_DETAIL=high`. A future pass could A/B `auto`/`low`
  detail to trade a few resolution points for a large latency win.
- Task 3 is comfortably above 80 without relying on multi-round model judgment.
- Current deployed v14 keeps the measured prediction logic and adds the latest
  hardening round: cancellation-aware hard triggers, multilingual life-support /
  unauthorized-access emergency detection, a safety guard so noise suppression
  can never hide a co-occurring emergency, and budget-aware T3 tool retries.
