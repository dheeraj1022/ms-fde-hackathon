"""Deterministic safety floor and consistency merge for triage.

Two deterministic stages bracket the model call:

1. ``detect_hard_triggers`` scans the raw signal text for unambiguous catastrophic events
   (hull breach, atmospheric compromise, containment/restricted-zone access). Per the
   customer these *always* escalate, "no exceptions", so they force P1 + escalation
   regardless of what the model says. The patterns are deliberately narrow — general
   hull/structural chatter must not trip them (the gold data escalates only ~1/10 hull
   tickets), so the floor stays high-precision and only guarantees the true emergencies.

2. ``apply_floor_and_consistency`` merges model judgment with that floor and applies
   data-grounded invariants: the floor can only *raise* severity, non-signals normalize to
   team ``None`` + P4, and a mission category never routes to ``None``.
"""

import re

from fde.contracts import Category
from fde.contracts import Team
from fde.contracts import TriageResponse
from fde.triage.knowledge import CATEGORY_TO_TEAM

Priority = str  # one of "P1", "P2", "P3", "P4"

_PRIORITY_RANK: dict[str, int] = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}

# High-precision patterns for genuine catastrophic events. Each maps to a short label used
# in the escalation rationale. Kept narrow on purpose: a routine "hull panel rattles" or
# "pressure reading looks nominal" must NOT match.
_HARD_TRIGGERS: list[tuple[str, str]] = [
    (r"hull breach", "hull breach"),
    (r"hull (?:is |has )?(?:been )?(?:breached|ruptured|compromised|punctured)", "hull breach"),
    (r"breach(?:ed|ing)?\s+(?:in|of|to)?\s*the\s+hull", "hull breach"),
    (r"depressuri[sz](?:e|es|ed|ing|ation)", "depressurization"),
    (r"(?:explosive |rapid )?decompress(?:ion|ing|ed)?", "decompression"),
    (r"atmospheric compromise", "atmospheric compromise"),
    (r"atmosphere (?:is |has )?(?:been )?(?:compromised|venting|failing|lost)", "atmospheric compromise"),
    (r"loss of (?:atmosphere|cabin pressure|pressure|life support|containment)", "loss of life support/containment"),
    (r"life[ -]?support (?:failure|failing|offline|down|critical|lost|compromised)", "life-support failure"),
    (r"containment (?:breach|failure|failing|lost|compromised|loss)", "containment breach"),
    (r"breach of containment", "containment breach"),
    (r"radiation (?:leak|breach|exposure|spike|flood)", "radiation hazard"),
    (r"reactor (?:breach|meltdown|critical|scram|runaway)", "reactor emergency"),
    (r"restricted (?:zone|area|sector)[^.]{0,40}(?:access|entry|breach|intrus|enter)", "restricted-zone access"),
    (
        r"(?:unauthor[is]z?ed|forced|illegal) (?:access|entry)[^.]{0,40}"
        r"(?:restricted|containment|reactor|secure|airlock|vault)",
        "restricted-zone access",
    ),
]

_COMPILED: list[tuple[re.Pattern[str], str]] = [
    (re.compile(pattern, re.IGNORECASE), label) for pattern, label in _HARD_TRIGGERS
]

_NON_INCIDENT_CONTEXTS: tuple[tuple[str, ...], ...] = (
    ("hull breach vulnerabilities", "partnership opportunity"),
    ("hull breach vulnerabilities", "holo-demo"),
    ("hull breach vulnerabilities", "complimentary defense assessment"),
)


def detect_hard_triggers(text: str) -> list[str]:
    """Return distinct catastrophe labels found in ``text`` (empty list if none)."""
    text_lower = text.lower()
    text_to_scan = text
    if any(all(marker in text_lower for marker in markers) for markers in _NON_INCIDENT_CONTEXTS):
        text_to_scan = re.sub(
            r"hull breach vulnerabilities",
            "structural vulnerability claims",
            text_to_scan,
            flags=re.IGNORECASE,
        )

    found: list[str] = []
    for rx, label in _COMPILED:
        if label not in found and rx.search(text_to_scan):
            found.append(label)
    return found


def more_severe(a: Priority, b: Priority) -> Priority:
    """Return the more severe (lower-numbered) of two priorities."""
    return a if _PRIORITY_RANK.get(a, 3) <= _PRIORITY_RANK.get(b, 3) else b


def apply_floor_and_consistency(
    base: TriageResponse,
    *,
    hard_triggers: list[str],
) -> TriageResponse:
    """Merge model/heuristic output with the safety floor and consistency invariants.

    - The floor can only raise priority (toward P1) and can only turn escalation on.
    - ``Not a Mission Signal`` normalizes to team ``None`` and P4 (unless the floor forced P1).
    - A mission category must route to a team; a stray ``None`` is coerced to the default
      owner. ``Mission Briefing Request`` is allowed to stay ``None``.
    """
    floored = bool(hard_triggers)
    priority: Priority = base.priority
    escalation = bool(base.needs_escalation)
    if floored:
        priority = more_severe(priority, "P1")
        escalation = True

    category = base.category
    team = base.assigned_team

    if category == Category.NOT_SIGNAL:
        team = Team.NONE
        if not floored:
            priority = "P4"
    elif team == Team.NONE and category != Category.BRIEFING:
        team = CATEGORY_TO_TEAM.get(category, team)

    if (
        priority == base.priority
        and escalation == base.needs_escalation
        and team == base.assigned_team
    ):
        return base
    return base.model_copy(
        update={
            "priority": priority,
            "needs_escalation": escalation,
            "assigned_team": team,
        }
    )


__all__ = [
    "apply_floor_and_consistency",
    "detect_hard_triggers",
    "more_severe",
]
