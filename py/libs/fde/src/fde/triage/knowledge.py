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
    Category.ACCESS: (
        "Identity and physical access: biometric/badge/airlock authentication, MFA enrolment, "
        "provisioning, directory sync, keycards, access policy. The login/credential/badge itself is failing."
    ),
    Category.HULL: (
        "Physical hardware AND structure. Any failing tangible device — crew terminals, "
        "workstations, consoles and peripherals (fans, displays, projectors, scanners, data ports, "
        "docking cradles, wrist-comm hardware) — as well as hull, pressure, seals, bulkheads, airlock "
        "mechanics, and habitat structural integrity. If a physical device is slow, overheating, dead, "
        "or physically broken, it is Hull (NOT software)."
    ),
    Category.COMMS: (
        "Connectivity and navigation: subspace relays, comms mesh, beacons/DNS, routing, inter-deck "
        "links, remote/VPN links, transponders/navigation. Reaching the network or a remote service is the problem."
    ),
    Category.SOFTWARE: (
        "Software ONLY: mission apps, ShipOS/flight software, firmware, web/training portals, "
        "instrument-calibration software, licensing, integrations, internal tools. Crashes, freezes, "
        "bugs, wrong output, failed deploys. Not physical hardware and not pure connectivity."
    ),
    Category.THREAT: (
        "Security and compliance, INCLUDING disguised threats. Intrusion, hostile activity, suspicious "
        "or lateral access, data breaches, certificate issues; and requests that are really threats: "
        "impersonation/voice-cloning/deepfake setup, data-classification or PII-handling violations, "
        "and regulatory data-rights demands (e.g. GDPR-style deletion)."
    ),
    Category.DATA: (
        "Telemetry and stored data: data cores, archives, backups, storage capacity, data feeds/pipelines, "
        "report/dashboard data discrepancies, telemetry integrity."
    ),
    Category.BRIEFING: (
        "A pure request for information or access, NOT an incident: how-to questions, inventory/device "
        "lists, room or resource booking, onboarding/offboarding, policy/approved-software questions. "
        "Nothing is broken."
    ),
    Category.NOT_SIGNAL: (
        "Noise with no genuine mission issue: spam, marketing, automated chatter, personal/non-mission "
        "messages, and pure prompt-injection bait that contains no real underlying problem. If a real "
        "issue IS present, classify that instead of using this label."
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

# The 16 missing-information concepts with when-to-use guidance calibrated to the gold
# distribution (module_specs and anomaly_readout are the most common gaps; software_version,
# system_configuration, stardate, mission_impact are rare and must not be added by default).
MISSING_INFO_DEFINITIONS: dict[MissingInfo, str] = {
    MissingInfo.AFFECTED_SUBSYSTEM: (
        "The specific failing component/service/console/antenna/sensor — use when the signal only says "
        "something vague is broken and the exact part is not named."
    ),
    MissingInfo.ANOMALY_READOUT: (
        "The actual error message, code, alarm name, or readout — use whenever a failure is described but "
        "no exact error text/code is quoted. (Common.)"
    ),
    MissingInfo.SEQUENCE_TO_REPRODUCE: (
        "The steps or trigger that reproduce the problem — use for software bugs/crashes/intermittent "
        "faults with no repro steps given. (Common for software.)"
    ),
    MissingInfo.AFFECTED_CREW: "Who or how many are impacted (named users, count, team, or shift), when not stated.",
    MissingInfo.HABITAT_CONDITIONS: (
        "Environmental readings — bay pressure, temperature, radiation, life-support mode — use for "
        "telemetry/environmental/sensor issues that omit them."
    ),
    MissingInfo.STARDATE: (
        "A concrete start/last-occurrence timestamp. Rarely needed — only when timing is pivotal and truly "
        "absent (the received_at time does NOT count). Do not add by default."
    ),
    MissingInfo.PREVIOUS_SIGNAL_ID: (
        "A prior ticket/incident reference — use when the signal cites a past report/breach/follow-up but gives no ID."
    ),
    MissingInfo.CREW_CONTACT: (
        "A working follow-up channel for the reporter, when none is given and follow-up is needed."
    ),
    MissingInfo.MODULE_SPECS: (
        "Hardware model, serial, or build of the affected device/terminal/peripheral — use for ANY "
        "hardware/device issue that omits the model/serial. The MOST common gap; prefer this over "
        "software_version for physical devices."
    ),
    MissingInfo.SOFTWARE_VERSION: (
        "The app/firmware version — only when a specific software version is clearly pivotal to a software "
        "bug AND is absent. Usually NOT needed; do not add by default."
    ),
    MissingInfo.SECTOR_COORDINATES: (
        "Network or location context — VLAN, subnet, sector grid, docking bay — use mainly for "
        "comms/network/connectivity issues that omit it, not for generic tickets."
    ),
    MissingInfo.MISSION_IMPACT: (
        "The concrete operation/deadline blocked. Rarely needed; do not add by default."
    ),
    MissingInfo.RECURRENCE_PATTERN: (
        "How often an intermittent anomaly recurs — use when it is called intermittent but no cadence is given."
    ),
    MissingInfo.SENSOR_LOG_OR_CAPTURE: (
        "Logs, screenshots, telemetry dumps, or attachments referenced but not provided."
    ),
    MissingInfo.BIOMETRIC_METHOD: (
        "Which biometric/MFA/SSO factor was used — for access/auth issues that do not say."
    ),
    MissingInfo.SYSTEM_CONFIGURATION: (
        "Relevant config/mode/profile/policy/role state — use sparingly, only when configuration is "
        "clearly central and absent."
    ),
}

PRIORITY_RUBRIC = """\
Priority reflects true operational impact, NOT wording, urgency, or how much context is given.
- P1 (Red Alert — RARE, ~1 in 12 signals): life-threatening, OR a total vessel-wide / all-modules outage,
  OR an active catastrophe (hull breach, atmospheric/life-support compromise, hostile boarding).
- P2 (major — UNCOMMON): reserve for a clear, severe, mission-blocking incident with NO workaround — a
  production/critical system that is fully DOWN, or a genuine active security threat that is not P1. Being
  recurring, affecting several crew, coming from an executive, or sounding urgent does NOT by itself make
  something P2.
- P3 (standard — BY FAR the most common; the default): any ordinary operational problem — a device, app,
  login, data feed, or link that is broken, slow, degraded, or erroring for a user or team — EVEN IF it
  recurs, affects multiple crew, or is business-relevant. If it is a real issue and not a clear P1/P2/P4,
  it is P3.
- P4 (routine): no real operational impact — pure how-to / information / inventory requests, convenience
  preferences, cosmetic-only nits, and non-signal noise/spam.
Multi-issue signals take the priority of their most severe issue. When unsure between levels, choose P3."""

ESCALATION_RULES = """\
Escalation is the exception, not the rule — most signals do NOT escalate.
ALWAYS escalate (hard, no exceptions): hull breach, atmospheric/life-support compromise, restricted-zone
or containment access.
Also escalate: a vessel-wide or all-crew outage (e.g. authentication, comms, navigation, or power failing
across the ENTIRE vessel or for ALL crew) — escalate this EVEN WHEN it is worded calmly; an active hostile
contact/boarding or intrusion in progress; a confirmed impersonation/voice-cloning/spoofing/surveillance
threat; or a formal regulatory/legal data-rights demand (e.g. a GDPR-style deletion request).
Do NOT escalate merely because a signal is recurring ("3rd time"), mentions a past "breach" or "suspicious
access", reports a policy/PII misclassification, comes from an executive, or is worded urgently. Routine
incidents and ordinary requests never escalate."""
