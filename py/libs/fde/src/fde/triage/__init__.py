"""Task 1 — Signal Triage.

Public surface: ``triage`` (the service), the prompt builders, and the deterministic
rules. The pipeline is a deterministic safety floor, a single structured LLM call, and a
deterministic merge enforcing the floor and consistency invariants.
"""

from fde.triage.prompt import build_system_prompt
from fde.triage.prompt import build_user_prompt
from fde.triage.rules import apply_floor_and_consistency
from fde.triage.rules import detect_hard_triggers
from fde.triage.service import triage

__all__ = [
    "apply_floor_and_consistency",
    "build_system_prompt",
    "build_user_prompt",
    "detect_hard_triggers",
    "triage",
]
