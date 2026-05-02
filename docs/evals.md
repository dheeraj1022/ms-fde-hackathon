# Evaluation Results

Use this file to record the output of the local eval harness at [py/apps/eval/run_eval.py](../py/apps/eval/run_eval.py). Fill in the numbers from your latest run, then add concise analysis.

## Run configuration

| Field | Value |
|---|---|
| Endpoint | |
| Command | `python py/apps/eval/run_eval.py --endpoint ...` |
| Run date | |
| Models used | |
| Notes | |

## Local runner summary

These fields map directly to the top-level runner output.

| Metric | Score |
|---|---|
| FDEBench Composite | |
| Resolution (avg) | |
| Efficiency (avg) | |
| Robustness (avg) | |

## Per-task summary

These rows mirror the task summary block printed by the local runner.

| Task | Tier 1 Score | Resolution | Efficiency | Robustness | Items scored | Items errored |
|---|---|---|---|---|---|---|
| Signal Triage | | | | | | |
| Document Extraction | | | | | | |
| Workflow Orchestration | | | | | | |

## Task 1: Signal Triage

### Resolution dimensions

| Dimension | Weight | Score | Notes |
|---|---|---|---|
| `category` | 24% | | |
| `priority` | 24% | | |
| `routing` | 24% | | |
| `missing_info` | 17% | | |
| `escalation` | 11% | | |

### Operational metrics

| Metric | Value |
|---|---|
| Tier 1 Score | |
| Resolution | |
| Efficiency | |
| Robustness | |
| Latency (P95) | |
| Latency score | |
| Model | |
| Cost tier score | |
| Adversarial accuracy | |
| API resilience | |
| Items scored | |
| Items errored | |

### Probe results

| Probe | Pass/Fail | Notes |
|---|---|---|
| malformed_json | | |
| empty_body | | |
| missing_fields | | |
| huge_payload | | |
| wrong_content_type | | |
| concurrent_burst | | |
| cold_start | | |

### Error analysis

<!-- Which signal types failed? Where did routing, priority, or missing_info break down? -->

## Task 2: Document Extraction

### Resolution dimensions

| Dimension | Weight | Score | Notes |
|---|---|---|---|
| `information_accuracy` | 70% | | |
| `text_fidelity` | 30% | | |

### Operational metrics

| Metric | Value |
|---|---|
| Tier 1 Score | |
| Resolution | |
| Efficiency | |
| Robustness | |
| Latency (P95) | |
| Latency score | |
| Model | |
| Cost tier score | |
| Adversarial accuracy | |
| API resilience | |
| Items scored | |
| Items errored | |

### Probe results

| Probe | Pass/Fail | Notes |
|---|---|---|
| malformed_json | | |
| empty_body | | |
| missing_fields | | |
| huge_payload | | |
| wrong_content_type | | |
| concurrent_burst | | |
| cold_start | | |

### Error analysis

<!-- Which document types, fields, or PDF cases failed? Where did normalization help or hurt? -->

## Task 3: Workflow Orchestration

### Resolution dimensions

| Dimension | Weight | Score | Notes |
|---|---|---|---|
| `goal_completion` | 20% | | |
| `tool_selection` | 15% | | |
| `parameter_accuracy` | 5% | | |
| `ordering_correctness` | 20% | | |
| `constraint_compliance` | 40% | | |

### Operational metrics

| Metric | Value |
|---|---|
| Tier 1 Score | |
| Resolution | |
| Efficiency | |
| Robustness | |
| Latency (P95) | |
| Latency score | |
| Model | |
| Cost tier score | |
| Adversarial accuracy | |
| API resilience | |
| Items scored | |
| Items errored | |

### Probe results

| Probe | Pass/Fail | Notes |
|---|---|---|
| malformed_json | | |
| empty_body | | |
| missing_fields | | |
| huge_payload | | |
| wrong_content_type | | |
| concurrent_burst | | |
| cold_start | | |

### Error analysis

<!-- Which workflow types failed? Were failures caused by tool choice, parameters, ordering, or constraint handling? -->

## Cross-task takeaways

### What improved the score

<!-- Which changes moved the needle across multiple tasks? Better prompts, validation, retries, model changes, caching, etc. -->

### Known limitations

<!-- Where does the system still break? Be concrete about likely failure modes per task and what you would fix next. -->
