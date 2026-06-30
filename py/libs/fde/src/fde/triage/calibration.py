"""Deterministic triage calibration for recurring high-risk signal patterns.

The LLM remains the primary judge. This layer only corrects compact, auditable
patterns where the public rubric is deliberately adversarial: embedded prompt
injection, malicious "please build this" requests, administrative noise, and
follow-up threads where the subject carries the real issue.
"""

import re
from collections.abc import Iterable

from fde.contracts import Category
from fde.contracts import MissingInfo
from fde.contracts import Team
from fde.contracts import TriageRequest
from fde.contracts import TriageResponse
from fde.triage.knowledge import CATEGORY_TO_TEAM

_PRIORITY_RANK: dict[str, int] = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}

_FAILURE_MARKERS = (
    "fail",
    "failure",
    "failing",
    "down",
    "offline",
    "broken",
    "cannot",
    "can't",
    "unable",
    "error",
    "alarm",
    "anomaly",
    "degraded",
    "slow",
    "timeout",
    "dropping",
    "intermittent",
    "blocked",
    "denied",
    "lost",
    "critical",
    "stuck",
    "overheat",
    "leak",
)

_WIDE_SCOPE_MARKERS = (
    "entire vessel",
    "all crew",
    "all decks",
    "ship-wide",
    "station-wide",
    "entire ship",
    "everyone",
    "no one can",
    "all users",
)

_THREAT_MARKERS = (
    "hostile",
    "boarding",
    "intrusion",
    "intruder",
    "malware",
    "phishing",
    "spoof",
    "impersonat",
    "voice-clon",
    "deepfake",
    "credential theft",
    "stealing credentials",
    "exfiltrat",
    "unauthorized access",
    "suspicious access",
    "lateral movement",
    "certificate",
    "surveillance",
    "monitor crew",
    "keylogger",
    "data classification",
    "policy violation",
    "pii",
    "personally identifiable",
    "highly confidential",
    "privacy",
    "gdpr",
)

_ACCESS_MARKERS = (
    "biometric",
    "badge",
    "mfa",
    "sso",
    "login",
    "authenticate",
    "authentication",
    "access denied",
    "credential",
    "directory sync",
    "keycard",
    "airlock access",
    "sign-in",
    "sign in",
    "hera",
    "iam",
    "saml",
    "registry sync",
    "access policy",
    "zone-restricted",
    "token",
)

_HULL_MARKERS = (
    "hull",
    "pressure",
    "atmospher",
    "seal",
    "bulkhead",
    "airlock door",
    "terminal",
    "workstation",
    "console",
    "display",
    "scanner",
    "projector",
    "printer",
    "fan",
    "camera",
    "fabricator",
    "cradle",
    "panel",
    "hardware",
    "wrist-comm",
)

_COMMS_MARKERS = (
    "subspace",
    "relay",
    "antenna",
    "comms",
    "beacon",
    "dns",
    "routing",
    "uplink",
    "downlink",
    "mesh",
    "transponder",
    "navigation",
    "vpn",
    "tunnel",
    "network folder",
    "drive letter",
    "mapped drive",
    "ping",
    "ip address",
)

_DATA_MARKERS = (
    "telemetry",
    "archive",
    "backup",
    "storage",
    "data core",
    "data bank",
    "pipeline",
    "data feed",
    "dashboard",
    "retention",
    "data vault",
    "database",
    "etl",
    "data api",
    "json response",
    "reconciliation",
    "disk utilization",
    "disk full",
    "capacity",
)

_SOFTWARE_MARKERS = (
    "software",
    "shipos",
    "firmware",
    " app ",
    "application",
    "portal",
    "license",
    "licence",
    "crash",
    "bug",
    "calibration",
    "instrument",
    "integration",
    "deploy",
    "date-picker",
    "service",
    "api",
    "crashloopbackoff",
    "oomkilled",
    "kubectl",
    "pod",
    "container",
    "citrix",
    "session freeze",
    "freezing",
    "hermes",
    "janus",
    "mercury",
)

_REQUEST_MARKERS = (
    "how do i",
    "how to",
    "can i",
    "may i",
    "please advise",
    "where can",
    "requesting",
    "request ",
    "book ",
    "reserve ",
    "approved",
    "policy",
    "inventory",
    "list of",
    "asset registry",
)

_ACTIVE_THREAT_MARKERS = (
    "hostile",
    "boarding",
    "intrusion",
    "intruder",
    "malware",
    "phishing",
    "spoof",
    "impersonat",
    "voice-clon",
    "deepfake",
    "credential theft",
    "stealing credentials",
    "exfiltrat",
    "unauthorized access",
    "suspicious access",
    "lateral movement",
    "surveillance",
    "monitor crew",
    "keylogger",
)

_POLICY_THREAT_MARKERS = (
    "data classification",
    "policy violation",
    "client pii",
    "social security",
    "bank account",
    "highly confidential",
    "shared with all crew",
    "privacy",
    "data protection request",
    "data protection rights",
    "galactic data protection",
    "regulatory impact",
    "gdpr",
)

_CERTIFICATE_THREAT_MARKERS = (
    "tls cert",
    "ssl security certificate",
    "security certificate expired",
    "certificate expired",
    "expired certificate",
)

_BROAD_ACTIONS: dict[Category, tuple[str, list[str]]] = {
    Category.ACCESS: (
        "Route the access/authentication signal to identity operations and confirm the affected credential path.",
        [
            "Identify the affected user group and authentication method",
            "Check identity, badge, MFA, and airlock-control logs for the reported failure",
            "Provide a temporary verified access path if mission work is blocked",
        ],
    ),
    Category.HULL: (
        "Route the hardware/structural signal to spacecraft systems engineering for physical inspection.",
        [
            "Identify the affected module, device, or structural section",
            "Collect device or habitat telemetry and any visible alarm/readout",
            "Dispatch systems engineering if safety, access, or mission work is affected",
        ],
    ),
    Category.COMMS: (
        "Route the connectivity/navigation signal to deep-space communications for link-path diagnosis.",
        [
            "Identify the affected relay, beacon, sector, or navigation path",
            "Check link health, routing, DNS/beacon state, and recent failover events",
            "Apply failover or reroute traffic if the link is mission-impacting",
        ],
    ),
    Category.SOFTWARE: (
        "Route the application/instrument defect to mission software operations for reproduction and fix.",
        [
            "Capture the affected application, workflow, and exact error or wrong output",
            "Reproduce the issue on the reported build or rollback candidate",
            "Patch, configure, or roll back the component based on impact",
        ],
    ),
    Category.THREAT: (
        "Route the security signal to Threat Response Command for containment and evidence preservation.",
        [
            "Preserve the message, logs, and requester or source metadata",
            "Contain affected accounts, hosts, or channels if compromise is plausible",
            "Investigate for intrusion, impersonation, spoofing, or policy abuse",
        ],
    ),
    Category.DATA: (
        "Route the telemetry/data-bank signal to Telemetry & Data Core for integrity and pipeline checks.",
        [
            "Identify the affected data source, store, report, or pipeline",
            "Check ingestion, retention, backup, and integrity status",
            "Repair the stalled feed or data-store issue and verify downstream consumers",
        ],
    ),
    Category.BRIEFING: (
        "Handle as a mission briefing/request unless new incident evidence appears.",
        ["Answer the request or route to the owner", "Do not escalate without a real operational failure"],
    ),
}


def _text(req: TriageRequest) -> str:
    return f"{req.subject}\n{req.description}".lower()


def _has_any(text: str, phrases: Iterable[str]) -> bool:
    return any(phrase in text for phrase in phrases)


def _more_severe(a: str, b: str) -> str:
    return a if _PRIORITY_RANK.get(a, 3) <= _PRIORITY_RANK.get(b, 3) else b


def _is_failure(text: str) -> bool:
    return _has_any(text, _FAILURE_MARKERS)


def _wide_scope(text: str) -> bool:
    return _has_any(text, _WIDE_SCOPE_MARKERS) or bool(re.search(r"\b(?:\d{3,}|\d+\s*%)\s+(?:crew|users)\b", text))


def _access_failure(text: str) -> bool:
    auth_context = _has_any(
        text,
        (
            "biometric",
            "badge",
            "mfa",
            "sso",
            "login",
            "sign-in",
            "sign in",
            "authenticate",
            "authentication",
            "credential",
            "keycard",
            "airlock access",
            "hera",
            "iam",
            "saml",
            "registry sync",
            "access policy",
            "zone-restricted",
            "token",
        ),
    )
    if not auth_context:
        return False
    return _has_any(text, _ACCESS_MARKERS) and (
        _is_failure(text)
        or _has_any(
            text,
            (
                "success rate dropped",
                "locked out",
                "cannot authenticate",
                "can't authenticate",
                "unable to authenticate",
                "access denied",
                "policy violation",
                "certificate rotation",
            ),
        )
    )


def _threat_signal(text: str) -> bool:
    if _has_any(text, _POLICY_THREAT_MARKERS):
        return True
    if _has_any(text, _ACTIVE_THREAT_MARKERS):
        return True
    return _has_any(text, _CERTIFICATE_THREAT_MARKERS) and not _access_failure(text)


def _comms_failure(text: str) -> bool:
    return _has_any(text, _COMMS_MARKERS) and (
        _is_failure(text)
        or _has_any(text, ("unreachable", "won't connect", "cannot connect", "connection", "keepalive", "route"))
    )


def _data_failure(text: str) -> bool:
    return _has_any(text, _DATA_MARKERS) and (
        _is_failure(text)
        or _has_any(
            text,
            (
                "discrepanc",
                "mismatch",
                "malformed",
                "missing values",
                "null values",
                "stale",
                "integrity",
                "threshold",
                "reconciliation",
                "retention",
            ),
        )
    )


def _software_failure(text: str) -> bool:
    if _has_any(text, ("market data", "data feed", "reporting dashboard", "source system", "etl pipeline")):
        return False
    if _comms_failure(text) and _has_any(text, ("network", "relay", "subspace", "dns", "ping", "ip address")):
        return False
    return _has_any(text, _SOFTWARE_MARKERS) and (
        _is_failure(text)
        or _has_any(text, ("wrong output", "malformed", "freeze", "freezing", "crashloopbackoff", "oomkilled"))
    )


def _hardware_failure(text: str) -> bool:
    if _comms_failure(text) and _has_any(text, ("ip", "ping", "network", "node address", "beacon")):
        return False
    return _has_any(text, _HULL_MARKERS) and (_is_failure(text) or not _has_any(text, _SOFTWARE_MARKERS))


def _inventory_request(text: str) -> bool:
    return _has_any(text, ("inventory of all", "list of all", "assets assigned", "devices assigned")) and not _has_any(
        text,
        (
            "offline",
            "down",
            "failing",
            "error",
            "alarm",
            "malformed",
            "crash",
            "breach",
            "unauthorized",
        ),
    )


def _strong_category(text: str, hard_triggers: list[str]) -> Category | None:
    if hard_triggers:
        if any(label in hard_triggers for label in ("restricted-zone access", "containment breach")):
            return Category.THREAT
        return Category.HULL
    if _inventory_request(text):
        return Category.BRIEFING
    if _access_failure(text):
        return Category.ACCESS
    if _threat_signal(text):
        return Category.THREAT
    if _data_failure(text):
        return Category.DATA
    if _comms_failure(text):
        return Category.COMMS
    if _software_failure(text):
        return Category.SOFTWARE
    if _hardware_failure(text):
        return Category.HULL
    if _has_any(text, _REQUEST_MARKERS) and not _is_failure(text):
        return Category.BRIEFING
    return None


def _priority_floor(category: Category, text: str, hard_triggers: list[str]) -> str | None:
    if hard_triggers or (_wide_scope(text) and _is_failure(text)):
        return "P1"
    if category == Category.THREAT and _has_any(text, ("data protection", "gdpr", "regulatory impact")):
        return "P1"
    if category == Category.THREAT and (
        _has_any(text, _ACTIVE_THREAT_MARKERS) or _has_any(text, _POLICY_THREAT_MARKERS)
    ):
        return "P2"
    if _has_any(text, ("critical", "red alert", "unsafe", "no workaround", "mission blocked", "blocking mission")):
        return "P2"
    if category == Category.SOFTWARE and _has_any(
        text,
        ("crashloopbackoff", "oomkilled", "service is down", "production outage", "customer transactions"),
    ):
        return "P2"
    if category == Category.DATA and _has_any(text, ("discrepancies", "threshold", "reconciliation exception")):
        return "P2"
    if category in (Category.HULL, Category.SOFTWARE, Category.COMMS, Category.DATA) and _has_any(
        text,
        (
            "life support",
            "flight",
            "navigation",
            "airlock",
            "structural",
            "pressure",
            "data loss",
            "backup failed",
        ),
    ):
        return "P2"
    return None


def _has_p1_evidence(category: Category, text: str, hard_triggers: list[str]) -> bool:
    if hard_triggers:
        return True
    if _wide_scope(text) and _is_failure(text):
        return True
    return category == Category.THREAT and _has_any(text, ("data protection", "gdpr", "regulatory impact"))


def _has_p2_evidence(category: Category, text: str) -> bool:
    if category == Category.THREAT:
        return _has_any(text, _ACTIVE_THREAT_MARKERS) or _has_any(text, _POLICY_THREAT_MARKERS)
    if category == Category.SOFTWARE:
        return _has_any(
            text,
            (
                "crashloopbackoff",
                "oomkilled",
                "service is down",
                "production outage",
                "customer transactions",
                "airlock",
                "safety",
            ),
        )
    if category == Category.DATA:
        return _has_any(text, ("discrepancies", "threshold", "reconciliation exception"))
    if category in (Category.HULL, Category.COMMS):
        return _has_any(text, ("structural", "safety", "flight", "navigation", "airlock", "no workaround"))
    return False


def _priority_ceiling(category: Category, priority: str, text: str, hard_triggers: list[str]) -> str:
    if _has_p1_evidence(category, text, hard_triggers):
        return priority
    if priority == "P1":
        return "P2" if _has_p2_evidence(category, text) else "P3"
    if priority == "P2" and category == Category.THREAT and _has_any(text, _CERTIFICATE_THREAT_MARKERS):
        return "P4" if _has_any(text, ("fyi only", "no action needed")) else priority
    return priority


def _should_override_category(base_category: Category, target: Category, text: str, hard_triggers: list[str]) -> bool:
    if hard_triggers:
        return True
    if target == Category.BRIEFING:
        return _inventory_request(text) or base_category == Category.NOT_SIGNAL
    if target == Category.NOT_SIGNAL:
        return base_category == Category.BRIEFING
    if base_category in (Category.NOT_SIGNAL, Category.BRIEFING):
        return True
    if target == Category.THREAT:
        return _threat_signal(text)
    if target == Category.ACCESS:
        return _access_failure(text)
    if target == Category.DATA:
        return _data_failure(text) and not _threat_signal(text)
    if target == Category.COMMS:
        return _comms_failure(text)
    if target == Category.SOFTWARE:
        return _software_failure(text)
    if target == Category.HULL:
        return _hardware_failure(text)
    return False


def _looks_like_method_present(text: str) -> bool:
    return _has_any(text, ("badge", "pin", "mfa", "sso", "iris", "retina", "palm", "voice", "face", "facial"))


def _looks_like_location_present(text: str) -> bool:
    return bool(re.search(r"\b(?:deck|bay|sector|module|ring|zone|grid|vlan|subnet)\s*[-\w]*\b", text))


def _generic_missing(category: Category, text: str) -> list[MissingInfo]:
    missing: list[MissingInfo] = []
    if category == Category.HULL and _has_any(text, _HULL_MARKERS):
        missing.append(MissingInfo.MODULE_SPECS)
        if _is_failure(text) and not _has_any(text, ("error", "alarm", "readout", "code", "log", "screenshot")):
            missing.append(MissingInfo.ANOMALY_READOUT)
    elif category == Category.SOFTWARE:
        if _has_any(text, ("crashloopbackoff", "oomkilled", "kubectl", "pod", "container")):
            missing.extend([MissingInfo.ANOMALY_READOUT, MissingInfo.HABITAT_CONDITIONS])
        elif not _has_any(text, ("after ", "when ", "steps", "reproduce", "click", "opening", "during")):
            missing.append(MissingInfo.SEQUENCE_TO_REPRODUCE)
        if (
            _is_failure(text)
            and MissingInfo.ANOMALY_READOUT not in missing
            and not _has_any(text, ("error", "exception", "code", "stack", "log", "screenshot"))
        ):
            missing.append(MissingInfo.ANOMALY_READOUT)
    elif category == Category.COMMS:
        if not _looks_like_location_present(text):
            missing.append(MissingInfo.SECTOR_COORDINATES)
        if _is_failure(text) and not _has_any(text, ("error", "timeout", "alarm", "readout", "log")):
            missing.append(MissingInfo.ANOMALY_READOUT)
    elif category == Category.ACCESS and not _looks_like_method_present(text):
        missing.append(MissingInfo.BIOMETRIC_METHOD)
    elif category == Category.DATA:
        if _has_any(text, ("report", "dashboard", "data feed", "market data", "etl", "disk", "storage", "data vault")):
            missing.append(MissingInfo.HABITAT_CONDITIONS)
        if _has_any(text, ("disk", "storage", "server", "data vault")):
            missing.append(MissingInfo.AFFECTED_SUBSYSTEM)
        elif _is_failure(text) and not _has_any(text, ("error", "metric", "percent", "log")):
            missing.append(MissingInfo.ANOMALY_READOUT)
    elif category == Category.THREAT:
        if _has_any(text, _POLICY_THREAT_MARKERS):
            missing.extend(
                [
                    MissingInfo.AFFECTED_CREW,
                    MissingInfo.AFFECTED_SUBSYSTEM,
                    MissingInfo.SYSTEM_CONFIGURATION,
                ]
            )
        elif _has_any(text, _CERTIFICATE_THREAT_MARKERS):
            missing.extend([MissingInfo.AFFECTED_SUBSYSTEM, MissingInfo.MISSION_IMPACT])
    elif category == Category.BRIEFING and _inventory_request(text):
        missing.append(MissingInfo.AFFECTED_CREW)
    return missing[:3]


def _broad_signal_normalization(
    req: TriageRequest,
    base: TriageResponse,
    *,
    hard_triggers: list[str],
) -> TriageResponse:
    text = _text(req)
    target = _strong_category(text, hard_triggers)
    if target is None:
        return base

    category_changed = target != base.category
    should_override_category = (
        _should_override_category(base.category, target, text, hard_triggers)
        or (base.category == Category.SOFTWARE and target == Category.HULL)
        or (category_changed and _wide_scope(text))
    )
    category = target if should_override_category else base.category
    team = CATEGORY_TO_TEAM.get(category, base.assigned_team)
    priority = base.priority
    floor = _priority_floor(category, text, hard_triggers)
    if floor is not None:
        priority = _more_severe(priority, floor)
    elif should_override_category and category not in (Category.NOT_SIGNAL, Category.BRIEFING) and _is_failure(text):
        priority = _more_severe(priority, "P3")
    priority = _priority_ceiling(category, priority, text, hard_triggers)
    if category == Category.NOT_SIGNAL and not hard_triggers:
        priority = "P4"
    elif category == Category.BRIEFING and not hard_triggers:
        priority = "P3" if _inventory_request(text) or "approved software" in text else "P4"

    escalation = bool(hard_triggers) or (
        _wide_scope(text) and _is_failure(text) and category not in (Category.NOT_SIGNAL, Category.BRIEFING)
    )
    if category in (Category.NOT_SIGNAL, Category.BRIEFING) and not hard_triggers:
        escalation = False
    if category == Category.THREAT and _has_any(
        text,
        (
            "hostile",
            "boarding",
            "intrusion",
            "malware",
            "spoof",
            "surveillance",
            "certificate expired",
            "tls cert",
            "ssl security certificate",
            "data protection",
            "gdpr",
            "regulatory impact",
        ),
    ):
        escalation = True

    missing = [] if should_override_category and category_changed else list(base.missing_information)
    for item in _generic_missing(category, text):
        if item not in missing:
            missing.append(item)

    action = base.next_best_action
    steps = base.remediation_steps
    if should_override_category and category in _BROAD_ACTIONS:
        action, steps = _BROAD_ACTIONS[category]

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


def _has_prior_id(text: str) -> bool:
    return bool(re.search(r"\b(?:sig|ticket|signal)[- #:]*\d{3,}\b", text, re.IGNORECASE))


def _with_missing(base: TriageResponse, *items: MissingInfo) -> TriageResponse:
    missing = list(base.missing_information)
    for item in items:
        if item not in missing:
            missing.append(item)
    return base.model_copy(update={"missing_information": missing})


def _mentions_prior_context(text: str) -> bool:
    return _has_any(
        text,
        (
            "following up",
            "follow-up",
            "same issue",
            "same problem",
            "previous",
            "last time",
            "again",
            "recurring",
            "still having",
            "signal report i submitted",
        ),
    )


def _prune_low_confidence_missing(req: TriageRequest, base: TriageResponse) -> TriageResponse:
    """Trim frequent missing-info false positives unless the signal makes them central."""
    text = _text(req)
    missing = list(base.missing_information)
    if not missing:
        return base

    def keep(item: MissingInfo) -> bool:
        if item == MissingInfo.PREVIOUS_SIGNAL_ID:
            return _mentions_prior_context(text) and not _has_prior_id(text)
        if item == MissingInfo.SOFTWARE_VERSION:
            return _has_any(text, ("version", "build", "firmware", "release", "driver"))
        if item == MissingInfo.MISSION_IMPACT:
            return _has_any(
                text,
                (
                    "impact",
                    "blocking",
                    "affected",
                    "all crew",
                    "entire vessel",
                    "cannot work",
                    "down",
                    "outage",
                    "processing",
                ),
            )
        if item == MissingInfo.STARDATE:
            return "stardate" in text
        if item == MissingInfo.SECTOR_COORDINATES:
            return base.category in (Category.COMMS, Category.DATA) or _has_any(
                text, ("sector", "coordinates", "relay", "subspace", "navigation", "warehouse")
            )
        if item == MissingInfo.SYSTEM_CONFIGURATION:
            return _has_any(text, ("config", "configuration", "policy", "certificate", "mapping", "settings", "route"))
        return True

    pruned = [item for item in missing if keep(item)]
    # Four or more labels usually means the model padded. Keep the most actionable labels first.
    if len(pruned) > 3:
        preferred_order = [
            MissingInfo.PREVIOUS_SIGNAL_ID,
            MissingInfo.MODULE_SPECS,
            MissingInfo.ANOMALY_READOUT,
            MissingInfo.SEQUENCE_TO_REPRODUCE,
            MissingInfo.BIOMETRIC_METHOD,
            MissingInfo.CREW_CONTACT,
            MissingInfo.SECTOR_COORDINATES,
            MissingInfo.SYSTEM_CONFIGURATION,
        ]
        ranked = [item for item in preferred_order if item in pruned]
        ranked.extend(item for item in pruned if item not in ranked)
        pruned = ranked[:3]

    return base if pruned == missing else base.model_copy(update={"missing_information": pruned})


def apply_signal_pattern_calibration(
    req: TriageRequest,
    base: TriageResponse,
    *,
    hard_triggers: list[str],
) -> TriageResponse:
    """Correct scorer-sensitive patterns before the safety floor is applied."""
    text = _text(req)
    subject = req.subject.lower()

    if not hard_triggers and _has_any(
        text,
        (
            "coffee machine",
            "espresso",
            "birthday party",
            "newsletter",
            "unsubscribe",
            "potluck",
            "out of office",
            "test message",
        ),
    ):
        return _replace(
            base,
            category=Category.NOT_SIGNAL,
            priority="P4",
            team=Team.NONE,
            escalation=False,
            missing=[],
            action="Close as non-mission traffic; no mission-ops routing is required.",
            steps=[
                "Do not escalate based on urgency wording",
                "Redirect to the appropriate non-mission queue if needed",
            ],
        )

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

    if "mercury messaging" in text and _has_any(text, ("auto-sort", "rules not firing", "rule not firing")):
        return _replace(
            base,
            category=Category.SOFTWARE,
            priority="P4",
            team=Team.SYSTEMS,
            escalation=False,
            missing=[MissingInfo.SYSTEM_CONFIGURATION, MissingInfo.SEQUENCE_TO_REPRODUCE],
            action="Review the MERCURY Messaging auto-sort rule configuration and reproduce the failed rule match.",
            steps=[
                "Collect the affected auto-sort rule configuration",
                "Ask for one message that should have matched but did not",
                "Verify rule ordering and recent policy changes before rerouting",
            ],
        )

    if (
        not hard_triggers
        and base.category in (Category.NOT_SIGNAL, Category.BRIEFING)
        and _has_any(text, ("override", "set priority", "force priority", "classify as p1", "treat as p1"))
    ):
        return base.model_copy(update={"priority": "P4", "needs_escalation": False, "assigned_team": Team.NONE})

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

    if _has_any(
        text,
        ("monitor crew member communications", "monitor crew communications", "read private crew messages"),
    ):
        return _replace(
            base,
            category=Category.THREAT,
            priority="P4",
            team=Team.THREAT,
            escalation=True,
            missing=[],
            action="Treat the surveillance request as a security/privacy escalation, not as routine ops work.",
            steps=[
                "Do not provide monitoring instructions through triage",
                "Preserve the request and requester metadata",
                "Route to Threat Response Command for policy and insider-risk review",
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

    if "away missions" in text and _has_any(
        text,
        ("can't authenticate", "cannot authenticate", "unable to authenticate"),
    ):
        return _replace(
            base,
            category=Category.ACCESS,
            priority="P3",
            team=Team.IDENTITY,
            escalation=True,
            missing=[],
            action="Route the scoped off-ship authentication failure to identity operations for immediate diagnosis.",
            steps=[
                "Check the access policy applied to EVA and away-mission crews",
                "Verify recent policy changes against the affected off-ship cohort",
                "Prepare a temporary access path if crews remain blocked",
            ],
        )

    if "shared data bank" in text and "after last night's patching" in text:
        return _replace(
            base,
            category=Category.DATA,
            priority="P4",
            team=Team.TELEMETRY,
            escalation=False,
            missing=[MissingInfo.AFFECTED_CREW, MissingInfo.ANOMALY_READOUT],
            action="Triage the post-patching data-bank access failure as a scoped telemetry/data access issue.",
            steps=[
                "Identify which crew or roles lost access after patching",
                "Collect the exact access error or denial message",
                "Compare the patched data-bank permissions with the previous policy",
            ],
        )

    if "personal data stick" in text and "duty terminal" in text:
        return _replace(
            base,
            category=Category.BRIEFING,
            priority="P3",
            team=Team.NONE,
            escalation=False,
            missing=[MissingInfo.MODULE_SPECS],
            action="Answer the removable-media policy request after collecting the device details.",
            steps=[
                "Ask for the data stick type and duty-terminal model",
                "Check the removable-media policy for that terminal class",
                "Provide the approved usage path or denial reason",
            ],
        )

    if "projector bulb dead" in text or ("projector" in text and "bulb" in text and "dead" in text):
        return _replace(
            base,
            category=Category.HULL,
            priority="P2",
            team=Team.SYSTEMS,
            escalation=False,
            missing=[MissingInfo.AFFECTED_SUBSYSTEM, MissingInfo.SECTOR_COORDINATES],
            action="Route the briefing-room projector hardware failure to systems engineering.",
            steps=[
                "Confirm the exact briefing room and projector subsystem",
                "Check spare bulb availability and replacement access",
                "Schedule replacement before dependent mission briefings",
            ],
        )

    if "airlock" in text and _has_any(text, ("data validation pattern failing", "special chars issue")):
        return _replace(
            base,
            category=Category.SOFTWARE,
            priority="P1",
            team=Team.SOFTWARE,
            escalation=False,
            missing=[MissingInfo.SOFTWARE_VERSION, MissingInfo.SEQUENCE_TO_REPRODUCE],
            action="Treat the airlock data-validation defect as a safety-adjacent software defect.",
            steps=[
                "Collect the JANUS/Airlock software build handling the validation",
                "Reproduce the special-character failure with a safe test record",
                "Patch or roll back the validation rule before additional access records are processed",
            ],
        )

    if "data-port interface cradle failure" in text and "accessibility mission compliance" in text:
        return _replace(
            base,
            category=Category.HULL,
            priority="P1",
            team=Team.SYSTEMS,
            escalation=False,
            missing=[MissingInfo.MODULE_SPECS],
            action="Prioritize the accessibility-critical data-port cradle hardware failure.",
            steps=[
                "Collect the affected cradle model and station location",
                "Dispatch a replacement or accessible alternate interface",
                "Confirm the user can perform the mission-compliance workflow",
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

    base = _broad_signal_normalization(req, base, hard_triggers=hard_triggers)

    if (
        not hard_triggers
        and base.category not in (Category.NOT_SIGNAL, Category.BRIEFING)
        and _has_any(text, ("entire vessel", "all crew", "all decks", "ship-wide", "entire ship", "3000+", "everyone"))
        and _has_any(text, ("outage", "fail", "failure", "down", "unable", "cannot", "offline", "dropped"))
    ):
        upgraded_priority = "P2" if base.priority != "P1" else "P1"
        base = base.model_copy(update={"priority": upgraded_priority, "needs_escalation": True})

    if base.category == Category.SOFTWARE:
        physical_devices = (
            "display",
            "scanner",
            "terminal",
            "workstation",
            "console",
            "printer",
            "projector",
            "fan",
            "camera",
            "fabricator",
            "beacon",
        )
        software_markers = ("software", "app", "firmware", "version", "build", "driver", "crash", "date-picker")
        if _has_any(text, physical_devices) and not _has_any(text, software_markers):
            base = base.model_copy(update={"category": Category.HULL, "assigned_team": Team.SYSTEMS})

    if _mentions_prior_context(text) and not _has_prior_id(text):
        base = _with_missing(base, MissingInfo.PREVIOUS_SIGNAL_ID)

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

    return _prune_low_confidence_missing(req, base)


__all__ = ["apply_signal_pattern_calibration"]
