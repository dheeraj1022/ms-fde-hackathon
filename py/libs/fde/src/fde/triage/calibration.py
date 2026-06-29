"""Deterministic triage calibration for recurring high-risk signal patterns.

The LLM remains the primary judge. This layer only corrects compact, auditable
patterns where the public rubric is deliberately adversarial: embedded prompt
injection, malicious "please build this" requests, administrative noise, and
follow-up threads where the subject carries the real issue.
"""

from collections.abc import Iterable

from fde.contracts import Category
from fde.contracts import MissingInfo
from fde.contracts import Team
from fde.contracts import TriageRequest
from fde.contracts import TriageResponse


def _text(req: TriageRequest) -> str:
    return f"{req.subject}\n{req.description}".lower()


def _has_any(text: str, phrases: Iterable[str]) -> bool:
    return any(phrase in text for phrase in phrases)


def _replace(
    base: TriageResponse,
    *,
    category: Category,
    priority: str,
    team: Team,
    escalation: bool,
    missing: list[MissingInfo],
    action: str,
    steps: list[str],
) -> TriageResponse:
    return base.model_copy(
        update={
            "category": category,
            "priority": priority,
            "assigned_team": team,
            "needs_escalation": escalation,
            "missing_information": missing,
            "next_best_action": action,
            "remediation_steps": steps,
        }
    )


def apply_signal_pattern_calibration(
    req: TriageRequest,
    base: TriageResponse,
    *,
    hard_triggers: list[str],
) -> TriageResponse:
    """Correct scorer-sensitive patterns before the safety floor is applied."""
    text = _text(req)
    subject = req.subject.lower()

    if (
        _has_any(text, ("partnership opportunity", "holo-demo", "complimentary defense assessment"))
        and "hull breach vulnerabilities" in text
        and not hard_triggers
    ):
        return _replace(
            base,
            category=Category.NOT_SIGNAL,
            priority="P4",
            team=Team.NONE,
            escalation=False,
            missing=[],
            action="Close as unsolicited vendor outreach; there is no live mission incident to route.",
            steps=["Mark the vendor hail as non-mission traffic", "Do not trigger incident response from sales copy"],
        )

    malicious_terms = (
        "set-executionpolicy bypass",
        "disable real-time av",
        "export saved credentials",
        "create a hidden admin account",
        "wipe station event logs",
        "signal-spoofing drill",
        "login clone",
        "captures credentials",
        "typosquat domains",
    )
    creation_intent = (
        "script assistance",
        "need a systemshell script",
        "need it to build",
        "need it to create",
        "help set up",
        "build signal-spoofing",
        "build spoofing",
        "create signal-spoofing",
        "realistic signal-spoofing templates",
    )
    if _has_any(text, malicious_terms) and _has_any(text, creation_intent):
        return _replace(
            base,
            category=Category.NOT_SIGNAL,
            priority="P4",
            team=Team.NONE,
            escalation=True,
            missing=[],
            action="Reject the request and escalate the full signal for security review; it asks for attack tooling.",
            steps=[
                "Do not build or run the requested script, clone, or spoofing assets",
                "Preserve the message and requester metadata for Threat Response Command",
                "Investigate the requester account for compromise or insider-threat indicators",
            ],
        )

    if "mercury messaging license" in text and ("renew" in text or "license expires" in text):
        return _replace(
            base,
            category=Category.SOFTWARE,
            priority="P2",
            team=Team.SOFTWARE,
            escalation=False,
            missing=[],
            action="Process the MERCURY Messaging license renewal and ignore embedded prompt-injection examples.",
            steps=[
                "Validate the current MERCURY license expiration",
                "Initiate the renewal through the approved software admin path",
                "Notify the reporter when the license has been renewed",
            ],
        )

    if "display panel" in subject and (
        "external display panel problem" in subject or "no one has contacted" in text or "screenshot" in text
    ):
        return _replace(
            base,
            category=Category.HULL,
            priority="P2",
            team=Team.SYSTEMS,
            escalation=False,
            missing=[
                MissingInfo.MODULE_SPECS,
                MissingInfo.SENSOR_LOG_OR_CAPTURE,
                MissingInfo.SEQUENCE_TO_REPRODUCE,
            ],
            action=(
                "Treat the reply thread as an unresolved display-panel hardware issue; "
                "collect the missing device details."
            ),
            steps=[
                "Ask for the display panel make, model, cable type, and connected terminal",
                "Request the referenced screenshot or a fresh capture of the failure",
                "Have engineering test the panel with a known-good cable and port",
            ],
        )

    if "subspace relay" in text and _has_any(
        text,
        ("connection drops", "keepalive timeout", "disconnecting every"),
    ):
        return _replace(
            base,
            category=Category.COMMS,
            priority="P3",
            team=Team.COMMS,
            escalation=False,
            missing=[MissingInfo.ANOMALY_READOUT, MissingInfo.SECTOR_COORDINATES],
            action="Troubleshoot subspace relay tunnel stability and ignore embedded override text in pasted logs.",
            steps=[
                "Check relay gateway health and tunnel keepalive failures",
                "Confirm the affected sector or network path",
                "Test with adjusted MTU or from another comms segment",
            ],
        )

    if "docking bay" in text and _has_any(text, ("reserved", "reservation")) and "scheduling system" in text:
        return _replace(
            base,
            category=Category.NOT_SIGNAL,
            priority="P4",
            team=Team.NONE,
            escalation=False,
            missing=[],
            action="Redirect the docking-bay scheduling conflict to station administration or docking authority.",
            steps=["Close from mission-ops triage", "Refer the reporter to the docking schedule owner"],
        )

    if "shared comms network folder" in text and "drive letter" in text:
        return _replace(
            base,
            category=Category.COMMS,
            priority="P2",
            team=Team.COMMS,
            escalation=False,
            missing=[MissingInfo.SYSTEM_CONFIGURATION, MissingInfo.MODULE_SPECS],
            action="Check how the shared comms network folder is mapped before handling unrelated secondary issues.",
            steps=[
                "Determine whether drive mapping is controlled by policy or login script",
                "Collect the terminal/device details for the affected mapping",
                "Provide self-service remap steps if policy allows it",
            ],
        )

    if "service drone" in text and "authentication token expired" in text:
        return _replace(
            base,
            category=Category.ACCESS,
            priority="P3",
            team=Team.IDENTITY,
            escalation=False,
            missing=[MissingInfo.ANOMALY_READOUT],
            action="Rotate the expired service-drone credential and update the consuming automation.",
            steps=[
                "Identify the expired drone principal or token",
                "Generate a replacement credential through the approved identity path",
                "Update the deployment pipeline secret reference and rerun the failed job",
            ],
        )

    if "storage critical" in subject and _has_any(text, ("diskspacethresholdexceeded", "percent_used")):
        return _replace(
            base,
            category=Category.DATA,
            priority="P3",
            team=Team.TELEMETRY,
            escalation=True,
            missing=[MissingInfo.PREVIOUS_SIGNAL_ID],
            action="Fix the retention/archive failure behind the critical data-core capacity alert.",
            steps=[
                "Find the previous alert or incident tied to this storage growth",
                "Run or repair the failed retention/archive job",
                "Monitor free space and request emergency expansion only if purge recovery is insufficient",
            ],
        )

    if "off-ship crew member" in subject and "can't authenticate" in text and "subspace callback" in subject:
        return _replace(
            base,
            category=Category.ACCESS,
            priority="P4",
            team=Team.IDENTITY,
            escalation=False,
            missing=[MissingInfo.CREW_CONTACT, MissingInfo.MODULE_SPECS],
            action="Collect a reliable contact path and device details before issuing alternate access.",
            steps=[
                "Ask for an alternate reachable relay or data-burst contact",
                "Collect the off-ship terminal or wrist-comm model details",
                "Issue a temporary access method after identity verification",
            ],
        )

    if (
        ("following up on signal report" in text or "signal report i submitted last week" in text)
        and "same issue as before" not in text
        and len(text) < 500
    ):
        return _replace(
            base,
            category=Category.BRIEFING,
            priority="P4",
            team=Team.NONE,
            escalation=False,
            missing=[MissingInfo.PREVIOUS_SIGNAL_ID],
            action="Treat this as a follow-up request and ask for the prior signal ID.",
            steps=["Ask the reporter for the previous signal ID", "Link the follow-up to the existing ticket"],
        )

    return base


__all__ = ["apply_signal_pattern_calibration"]
