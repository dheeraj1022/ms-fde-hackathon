"""Domain knowledge for signal triage: routing map, label definitions, rubrics.

Grounded in the customer brief (team ownership), the routing guide (gray areas), and the
distribution of the public gold data (e.g. "Not a Mission Signal" -> None/P4; the natural
1:1 category->team mapping that nonetheless has real overlaps). Kept free of FastAPI and
the LLM SDK so it can be imported by the prompt builder, the rules, and the tests alike.
"""

from fde.contracts import Category
from fde.contracts import MissingInfo
from fde.contracts import Team

# Default category -> owning team. Six mission categories map 1:1; the two non-incident
# categories map to None. Real overlaps exist (e.g. Flight Software sometimes lands on
# Spacecraft Systems Engineering), so for mission categories this is only the default the
# model may override; the consistency rules in ``rules.py`` enforce the hard invariants.
CATEGORY_TO_TEAM: dict[Category, Team] = {
    Category.ACCESS: Team.IDENTITY,
    Category.HULL: Team.SYSTEMS,
    Category.COMMS: Team.COMMS,
    Category.SOFTWARE: Team.SOFTWARE,
    Category.THREAT: Team.THREAT,
    Category.DATA: Team.TELEMETRY,
    Category.BRIEFING: Team.NONE,
    Category.NOT_SIGNAL: Team.NONE,
}

CATEGORY_DEFINITIONS: dict[Category, str] = {
    Category.ACCESS: "Biometric/identity access, badge or airlock authentication, provisioning, directory sync.",
    Category.HULL: (
        "Physical hull and structure: pressure, seals, bulkheads, airlock mechanics, "
        "habitat structural integrity."
    ),
    Category.COMMS: "Subspace relay, comms mesh, DNS beacons, routing, inter-deck links, navigation/transponder.",
    Category.SOFTWARE: (
        "Mission apps, ShipOS/flight software, firmware, instrument calibration, licensing, "
        "integrations, internal tools."
    ),
    Category.THREAT: "Hostile activity, intrusion, containment, suspicious access, data breaches, certificate issues.",
    Category.DATA: "Data cores, archives, backups, storage, telemetry pipelines.",
    Category.BRIEFING: (
        "A request or question (how-to, onboarding/offboarding setup, room booking, "
        "policy/approved-software) — not an incident."
    ),
    Category.NOT_SIGNAL: (
        "Noise: spam, automated chatter, personal/non-mission messages, anything not "
        "actionable by mission ops."
    ),
}

TEAM_OWNERSHIP: dict[Team, str] = {
    Team.IDENTITY: "Biometric access, identity, provisioning, directory sync.",
    Team.SYSTEMS: "Devices, workstation issues, ShipOS, peripherals, hardware faults, hull/structural hardware.",
    Team.COMMS: "Subspace relay, local comms mesh, DNS beacons, routing, inter-deck links.",
    Team.SOFTWARE: "Mission apps, licensing, integrations, internal tools.",
    Team.THREAT: "Hostile activity, containment, suspicious access, data breaches, certificate issues.",
    Team.TELEMETRY: "Data cores, archives, backups, storage, telemetry pipelines.",
    Team.NONE: "No team — non-mission signals, and most general briefing/how-to requests.",
}

# The 16 missing-information concepts, verbatim from the task README's definition table.
MISSING_INFO_DEFINITIONS: dict[MissingInfo, str] = {
    MissingInfo.AFFECTED_SUBSYSTEM: "Specific component, service, console, antenna, sensor, etc. that's failing",
    MissingInfo.ANOMALY_READOUT: "The actual error message, code, alarm name, or readout displayed",
    MissingInfo.SEQUENCE_TO_REPRODUCE: "Steps / trigger that reproduces the anomaly",
    MissingInfo.AFFECTED_CREW: "Who is impacted — named users, count, team, or shift",
    MissingInfo.HABITAT_CONDITIONS: "Environmental context — bay pressure, temperature, radiation, life-support mode",
    MissingInfo.STARDATE: "Concrete timestamp of when it started or last occurred (created_at does NOT count)",
    MissingInfo.PREVIOUS_SIGNAL_ID: "Prior ticket / incident reference",
    MissingInfo.CREW_CONTACT: "Working channel for follow-up with the reporter",
    MissingInfo.MODULE_SPECS: "Hardware / device / terminal model, serial, or build",
    MissingInfo.SOFTWARE_VERSION: "Software / firmware version of the affected app or subsystem",
    MissingInfo.SECTOR_COORDINATES: "Network or location context — VLAN, subnet, sector grid, docking bay",
    MissingInfo.MISSION_IMPACT: "Operational consequence — what mission, deadline, or operation is blocked",
    MissingInfo.RECURRENCE_PATTERN: "How often the anomaly recurs (cadence, intermittency)",
    MissingInfo.SENSOR_LOG_OR_CAPTURE: "Sensor logs, screenshots, telemetry dump, or attachments",
    MissingInfo.BIOMETRIC_METHOD: "How the user authenticated — biometric mode, MFA factor, SSO method",
    MissingInfo.SYSTEM_CONFIGURATION: "Configuration state — mode, profile, policy, role, permission",
}

PRIORITY_RUBRIC = """\
- P1 (critical): life-threatening or mission-ending; act immediately.
  Examples: hull breach, atmospheric/life-support compromise, hostile boarding, active intrusion causing impact.
- P2 (major): significant impact with no workaround; urgent but not life-threatening.
- P3 (standard): real impact but a workaround exists; handle in the normal queue. This is the most common priority.
- P4 (routine): minor or no operational impact — requests, questions, and noise."""

ESCALATION_RULES = """\
ALWAYS escalate (no exceptions): hull breach, atmospheric compromise, restricted-zone or containment access.
Also escalate: active hostile contact/boarding, intrusion or data breach in progress, repeated critical failures,
or command/VIP / compliance / safety escalations.
Do NOT escalate routine requests, how-to questions, or noise — even when the wording sounds urgent."""
