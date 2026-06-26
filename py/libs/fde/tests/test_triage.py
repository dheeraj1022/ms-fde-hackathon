"""Unit tests for Task 1 triage: hard-trigger precision, the merge/consistency rules,
and the service's LLM / fallback paths (via FakeLLMClient, no network)."""

import asyncio

from fde.contracts import Category
from fde.contracts import MissingInfo
from fde.contracts import Team
from fde.contracts import TriageRequest
from fde.contracts import TriageResponse
from fde.llm import FakeLLMClient
from fde.triage import build_system_prompt
from fde.triage import build_user_prompt
from fde.triage import detect_hard_triggers
from fde.triage import triage
from fde.triage.rules import apply_floor_and_consistency
from fde.triage.rules import more_severe


def _req(subject: str = "", description: str = "", ticket_id: str = "T1") -> TriageRequest:
    return TriageRequest(
        ticket_id=ticket_id,
        subject=subject,
        description=description,
        reporter={"name": "Officer", "email": "officer@station.gov", "department": "Ops"},
        created_at="2401-01-01T00:00:00Z",
        channel="bridge_terminal",
        attachments=[],
    )


def _resp(
    *,
    category: Category = Category.SOFTWARE,
    priority: str = "P3",
    team: Team = Team.SOFTWARE,
    escalation: bool = False,
    ticket_id: str = "T1",
    missing: list[MissingInfo] | None = None,
) -> TriageResponse:
    return TriageResponse(
        ticket_id=ticket_id,
        category=category,
        priority=priority,  # type: ignore[arg-type]
        assigned_team=team,
        needs_escalation=escalation,
        missing_information=missing or [],
        next_best_action="do the thing",
        remediation_steps=["step one"],
    )


# --- hard-trigger precision ---------------------------------------------------


def test_hard_triggers_fire_on_real_emergencies() -> None:
    for text in [
        "We have a hull breach in bay 4",
        "Rapid depressurization on deck 7",
        "Atmospheric compromise detected",
        "Life support failure in the medbay",
        "Containment breach in the bio lab",
        "Unauthorized entry into the restricted reactor zone",
        "Radiation leak near the core",
    ]:
        assert detect_hard_triggers(text), f"expected a trigger for: {text!r}"


def test_hard_triggers_stay_quiet_on_routine_text() -> None:
    for text in [
        "Hull inspection panel rattles slightly, please schedule a look",
        "Pressure reading on the gauge looks nominal",
        "URGENT!!! the coffee machine is broken",
        "Requesting access to the briefing room schedule",
        "Telemetry dashboard is a little slow today",
    ]:
        assert detect_hard_triggers(text) == [], f"unexpected trigger for: {text!r}"


# --- merge / consistency rules ------------------------------------------------


def test_more_severe_picks_lower_number() -> None:
    assert more_severe("P3", "P1") == "P1"
    assert more_severe("P4", "P2") == "P2"
    assert more_severe("P1", "P1") == "P1"


def test_floor_overrides_a_calm_model() -> None:
    base = _resp(category=Category.HULL, priority="P3", team=Team.SYSTEMS, escalation=False)
    merged = apply_floor_and_consistency(base, hard_triggers=["hull breach"])
    assert merged.priority == "P1"
    assert merged.needs_escalation is True


def test_floor_never_deescalates() -> None:
    base = _resp(category=Category.THREAT, priority="P1", team=Team.THREAT, escalation=True)
    merged = apply_floor_and_consistency(base, hard_triggers=[])
    assert merged.priority == "P1"
    assert merged.needs_escalation is True


def test_not_signal_normalizes_to_none_and_p4() -> None:
    base = _resp(category=Category.NOT_SIGNAL, priority="P2", team=Team.SOFTWARE, escalation=False)
    merged = apply_floor_and_consistency(base, hard_triggers=[])
    assert merged.assigned_team == Team.NONE
    assert merged.priority == "P4"


def test_not_signal_with_floor_keeps_p1() -> None:
    base = _resp(category=Category.NOT_SIGNAL, priority="P4", team=Team.SOFTWARE, escalation=False)
    merged = apply_floor_and_consistency(base, hard_triggers=["hull breach"])
    assert merged.priority == "P1"
    assert merged.needs_escalation is True
    assert merged.assigned_team == Team.NONE


def test_mission_category_none_team_is_coerced() -> None:
    base = _resp(category=Category.HULL, priority="P3", team=Team.NONE, escalation=False)
    merged = apply_floor_and_consistency(base, hard_triggers=[])
    assert merged.assigned_team == Team.SYSTEMS


def test_briefing_none_team_is_preserved() -> None:
    base = _resp(category=Category.BRIEFING, priority="P4", team=Team.NONE, escalation=False)
    merged = apply_floor_and_consistency(base, hard_triggers=[])
    assert merged.assigned_team == Team.NONE


# --- service paths ------------------------------------------------------------


def test_service_applies_floor_over_model() -> None:
    # Model is calm, but the raw text contains an unambiguous emergency.
    def handler(*, system: str, user: str, response_model: type) -> TriageResponse:
        return _resp(category=Category.HULL, priority="P3", team=Team.SYSTEMS, escalation=False)

    client = FakeLLMClient(parse_handler=handler)
    req = _req(subject="Pressure note", description="Slow hull breach in ring C, crew relocated quietly.")
    out = asyncio.run(triage(req, client))
    assert out.priority == "P1"
    assert out.needs_escalation is True
    assert len(client.parse_calls) == 1


def test_service_heuristic_without_client() -> None:
    req = _req(
        subject="Possible intrusion",
        description="Unauthorized intrusion detected, suspected malware on a console.",
    )
    out = asyncio.run(triage(req, None))
    assert out.category == Category.THREAT
    assert out.assigned_team == Team.THREAT


def test_service_falls_back_when_model_raises() -> None:
    def boom(*, system: str, user: str, response_model: type) -> TriageResponse:
        raise RuntimeError("model down")

    client = FakeLLMClient(parse_handler=boom)
    req = _req(subject="Antenna relay down", description="The subspace relay antenna lost its uplink.")
    out = asyncio.run(triage(req, client))
    assert isinstance(out, TriageResponse)
    assert out.category == Category.COMMS  # heuristic still routed it


def test_service_fixes_drifted_ticket_id() -> None:
    def handler(*, system: str, user: str, response_model: type) -> TriageResponse:
        return _resp(ticket_id="WRONG-ID", category=Category.DATA, team=Team.TELEMETRY)

    client = FakeLLMClient(parse_handler=handler)
    req = _req(ticket_id="SIG-9999", subject="Archive", description="Backup archive integrity check.")
    out = asyncio.run(triage(req, client))
    assert out.ticket_id == "SIG-9999"


# --- prompt sanity ------------------------------------------------------------


def test_system_prompt_covers_vocab_and_rules() -> None:
    prompt = build_system_prompt()
    assert "Not a Mission Signal" in prompt
    assert "loudness is NOT urgency" in prompt
    for label in [m.value for m in MissingInfo]:
        assert label in prompt


def test_user_prompt_includes_signal_fields() -> None:
    req = _req(subject="Relay fault", description="No uplink", ticket_id="SIG-1")
    user = build_user_prompt(req)
    assert "SIG-1" in user
    assert "Relay fault" in user
    assert "does NOT count as a stardate" in user
