# Architecture

## System overview

<!-- High-level description of your solution. What components does your system have? How do they interact? Diagram encouraged. -->

## Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check — returns 200 if the service is alive |
| `/triage` | POST | Task 1: Classify a spacecraft signal across 5 dimensions |
| `/extract` | POST | Task 2: Extract structured data from a document image |
| `/orchestrate` | POST | Task 3: Plan and execute a multi-step workflow |

## Task 1: Signal Triage — AI Pipeline

<!-- How does the triage logic work? What model, what prompt strategy? Tool calling or content parsing? How is the system prompt structured? -->

## Task 2: Document Extraction — AI Pipeline

<!-- How does extraction work? What vision model do you use? How do you handle the per-document json_schema? What normalization steps run after the LLM call? -->

## Task 3: Workflow Orchestration — AI Pipeline

<!-- How does the planner work? Single upfront plan or iterative re-planning? How do you handle tool failures? Parallel vs. sequential execution? -->

## Cross-Task Design Decisions

<!-- What is shared across tasks? Model selection, error handling, response header generation, configuration? What is task-specific? -->

## Infrastructure

<!-- How is your solution deployed? What cloud services, containers, or platforms? -->

## Key tradeoffs

<!-- What decisions did you make and why? Model size vs. latency? Accuracy vs. cost? Single model vs. model-per-task? What would you change for production? -->
