"""Task 3 — Workflow Orchestration.

Public surface: ``orchestrate`` (the service) and the prompt builders. A bounded
tool-calling loop reads the goal/constraints/tools, plans, executes tools over HTTP,
and returns the executed trace. Degrades to an empty completed/failed trace when no
model is configured so the endpoint never errors.
"""

from fde.orchestrate.prompt import SYSTEM
from fde.orchestrate.prompt import build_user
from fde.orchestrate.service import orchestrate

__all__ = [
    "SYSTEM",
    "build_user",
    "orchestrate",
]
