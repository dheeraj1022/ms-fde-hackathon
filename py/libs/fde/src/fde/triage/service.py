"""Triage service: deterministic safety floor + LLM judgment + deterministic merge.

Transport-agnostic. Given a request and an optional LLM client, it returns a complete,
valid ``TriageResponse`` for every input — falling back to a deterministic heuristic when
no model is configured or a model call fails, so a signal is never dropped (a dropped
ticket scores 0 in the benchmark). The heuristic lives here, not in the fake client, so the
``llm`` layer stays a pure model abstraction with no dependency on triage logic.
"""

import logging

from fde.contracts import Category
from fde.contracts import Team
from fde.contracts import TriageRequest
from fde.contracts import TriageResponse
from fde.llm import LLMClient
from fde.triage.knowledge import CATEGORY_TO_TEAM
from fde.triage.prompt import build_system_prompt
from fde.triage.prompt import build_user_prompt
from fde.triage.rules import apply_floor_and_consistency
from fde.triage.rules import detect_hard_triggers

logger = logging.getLogger(__name__)

# Keyword priors for the offline / degraded heuristic ONLY. The LLM is the primary path;
# this exists so an unconfigured or failing deployment still returns a best-effort answer
# rather than a blank or 500. Ordered most-specific first; ties keep the earlier category.
_KEYWORDS: list[tuple[Category, tuple[str, ...]]] = [
    (
        Category.THREAT,
        (
            "breach", "hostile", "intrus", "unauthor", "malware", "attack", "boarding",
            "weapon", "suspicious", "containment", "exploit", "phishing", "certificate", "spoof",
        ),
    ),
    (
        Category.HULL,
        (
            "hull", "pressure", "depressur", "atmospher", "seal", "bulkhead",
            "structural", "decompress", "micrometeor", "airlock seal", "rupture",
        ),
    ),
    (
        Category.ACCESS,
        (
            "biometric", "badge", "airlock access", "log in", "login", "authenticat",
            "credential", "identity", "provision", "access denied", " mfa", "sso", "directory sync",
        ),
    ),
    (
        Category.COMMS,
        (
            "relay", "antenna", "subspace", "comms", "beacon", "dns", "routing",
            "navigation", "transponder", "uplink", "downlink", "comms mesh",
        ),
    ),
    (
        Category.DATA,
        (
            "telemetry", "archive", "backup", "storage", "data core", "data bank",
            "retention", "pipeline", "dataset", "data store",
        ),
    ),
    (
        Category.SOFTWARE,
        (
            "software", "firmware", "version", "license", "licence", "crash", "bug",
            "calibrat", "integration", "shipos", "instrument", "console app", "update failed",
        ),
    ),
    (
        Category.BRIEFING,
        (
            "how do i", "how to", "request", "question", "briefing", "onboard",
            "new crew", "book a", "approved", "policy", "please advise", "can i use",
        ),
    ),
    (
        Category.NOT_SIGNAL,
        (
            "coffee", "newsletter", "unsubscribe", "spam", "lunch", "party",
            "out of office", "test message", "ignore this",
        ),
    ),
]

_GENERIC_STEPS: dict[Category, list[str]] = {
    Category.ACCESS: [
        "Verify the reporter's identity and current access bindings",
        "Check the airlock/biometric controller logs for the failed attempt",
    ],
    Category.HULL: [
        "Inspect the affected structural section and confirm seal integrity",
        "Pull habitat telemetry (pressure, temperature) for the area",
    ],
    Category.COMMS: [
        "Check relay/antenna status and routing tables for the affected link",
        "Confirm link health to the affected deck and failover if needed",
    ],
    Category.SOFTWARE: [
        "Reproduce the fault and capture the error message and software version",
        "Review recent changes to the affected app/firmware build",
    ],
    Category.THREAT: [
        "Contain and isolate the affected asset immediately",
        "Preserve logs and notify Threat Response Command",
    ],
    Category.DATA: [
        "Verify data-core/backup integrity for the affected store",
        "Check the telemetry pipeline for gaps or stalled jobs",
    ],
    Category.BRIEFING: [
        "Acknowledge the request and route to the owning team if action is needed",
        "Provide the requested information or complete the booking",
    ],
    Category.NOT_SIGNAL: [
        "No mission action required",
        "Close or redirect to the appropriate non-mission queue",
    ],
}


def _heuristic(req: TriageRequest, hard_triggers: list[str]) -> TriageResponse:
    """Deterministic best-effort triage for the unconfigured / failed-model path."""
    text = f"{req.subject}\n{req.description}".lower()
    best = Category.SOFTWARE
    best_score = 0
    for category, words in _KEYWORDS:
        score = sum(1 for w in words if w in text)
        if score > best_score:
            best_score, best = score, category

    team = CATEGORY_TO_TEAM.get(best, Team.NONE)
    if hard_triggers:
        priority = "P1"
    elif best in (Category.NOT_SIGNAL, Category.BRIEFING):
        priority = "P4"
    else:
        priority = "P3"

    next_action = (
        "Escalate immediately — " + ", ".join(hard_triggers)
        if hard_triggers
        else "Review the signal and route to the owning team for first response."
    )
    fallback_steps = ["Review the signal details", "Route to the appropriate team"]
    return TriageResponse(
        ticket_id=req.ticket_id,
        category=best,
        priority=priority,  # type: ignore[arg-type]
        assigned_team=team,
        needs_escalation=bool(hard_triggers),
        missing_information=[],
        next_best_action=next_action,
        remediation_steps=_GENERIC_STEPS.get(best, fallback_steps),
    )


async def triage(req: TriageRequest, client: LLMClient | None) -> TriageResponse:
    """Produce a triage decision for one signal.

    Pipeline: deterministic safety floor (from raw text) -> structured LLM call (or the
    heuristic when no client / on failure) -> deterministic merge enforcing the floor and
    consistency invariants. Always returns a valid response.
    """
    hard_triggers = detect_hard_triggers(f"{req.subject}\n{req.description}")
    base: TriageResponse | None = None

    if client is not None:
        try:
            base = await client.parse(
                system=build_system_prompt(),
                user=build_user_prompt(req),
                response_model=TriageResponse,
            )
            if base.ticket_id != req.ticket_id:
                # The scorer joins candidate to gold by ticket_id; never let the model drift it.
                base = base.model_copy(update={"ticket_id": req.ticket_id})
        except Exception:  # noqa: BLE001 - any model failure degrades to the heuristic
            logger.exception("LLM triage failed for %s; using heuristic fallback", req.ticket_id)
            base = None

    if base is None:
        base = _heuristic(req, hard_triggers)

    return apply_floor_and_consistency(base, hard_triggers=hard_triggers)


__all__ = ["triage"]
