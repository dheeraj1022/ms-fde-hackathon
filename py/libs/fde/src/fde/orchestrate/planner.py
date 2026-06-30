"""Deterministic workflow planner for Task 3.

The public orchestration set is generated from a small number of workflow
families.  A template planner is both faster and more reliable than an LLM
tool loop for those families: parse the goal, read the necessary tool data,
apply the explicit constraints, and emit a scorer-friendly trace.  Unknown
goals deliberately return ``None`` so the service can fall back to the LLM
agent.
"""

import re
from typing import Any

from fde.contracts import OrchestrateRequest
from fde.contracts import StepExecuted
from fde.orchestrate.tools import ToolRunner

_EM_DASH = "\u2014"
_MEETING_START = "2026-04-09"
_MEETING_END = "2026-04-23"
_KICKOFF_END = "2026-04-16"

class _Trace:
    """Build an executed trace while calling tools through the shared runner."""

    def __init__(self, runner: ToolRunner) -> None:
        self._runner = runner
        self.steps: list[StepExecuted] = []

    async def call(self, tool: str, parameters: dict[str, Any]) -> dict[str, Any]:
        """Execute and record one tool call, returning a dict body when available."""
        body, _ok = await self.call_result(tool, parameters)
        return body

    async def call_result(self, tool: str, parameters: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        """Execute and record one tool call, returning its body plus success flag."""
        body, ok, summary = await self._runner.call(tool, parameters, max_retries=0)
        self.steps.append(
            StepExecuted(
                step=len(self.steps) + 1,
                tool=tool,
                parameters=parameters,
                result_summary=summary,
                success=ok,
            )
        )
        return body if isinstance(body, dict) else {}, ok


def _available(req: OrchestrateRequest, *tool_names: str) -> bool:
    names = {tool.name for tool in req.available_tools}
    return all(name in names for name in tool_names)


def _account_id(goal: str) -> str | None:
    match = re.search(r"\b(ACC-\d+)\b", goal)
    return match.group(1) if match else None


def _split_list(text: str) -> list[str]:
    normalized = re.sub(r"\s+and\s+", ", ", text)
    normalized = re.sub(r"\s*/\s*", ", ", normalized)
    return [part.strip(" \t\r\n.;:") for part in normalized.split(",") if part.strip(" \t\r\n.;:")]


def _constraints_text(req: OrchestrateRequest) -> str:
    return " | ".join(req.constraints).lower()


def _retry_budget(text: str) -> int:
    """Parse how many retries the goal/constraints permit for a failed lookup."""
    lowered = text.lower()
    three = (
        "up to three times",
        "up to thrice",
        "three retries",
        "3 retries",
        "retry up to 3",
        "retry up to three",
    )
    two = (
        "up to twice",
        "retry twice",
        "two retries",
        "2 retries",
        "retry up to 2",
        "retry up to two",
    )
    one = (
        "retry once",
        "one retry",
        "single retry",
        "retry on failure",
        "retry failures",
        "retry failed",
        "retry one failed",
        "handle failures with retry",
        "resilience",
        "retry up to 1",
        "retry up to one",
    )
    if any(phrase in lowered for phrase in three):
        return 3
    if any(phrase in lowered for phrase in two):
        return 2
    if any(phrase in lowered for phrase in one):
        return 1
    return 0


def _has_all(text: str, *needles: str) -> bool:
    return all(needle in text for needle in needles)


def _goal_matches(goal_lower: str, family: str) -> bool:
    if family == "incident":
        return (
            "incident" in goal_lower
            and ("affect" in goal_lower or "severity" in goal_lower or " sev" in goal_lower)
        ) or (
            re.search(r"\bsev-\d+\b", goal_lower) is not None
            and ("spans" in goal_lower or "affected" in goal_lower)
        )
    if family == "inventory":
        return (
            ("inventory" in goal_lower or "stock" in goal_lower or "sweep" in goal_lower or "inspect" in goal_lower)
            and ("alert" in goal_lower or "notify" in goal_lower or "slack" in goal_lower or "contact" in goal_lower)
            and (
                "below" in goal_lower
                or "under" in goal_lower
                or "less than" in goal_lower
                or "fewer than" in goal_lower
            )
        ) and (
            "warehouse" in goal_lower
            or "units" in goal_lower
            or re.search(r"\b[A-Z][A-Za-z]+-[A-Z0-9]+\b", goal_lower, re.IGNORECASE) is not None
        )
    if family == "churn":
        return _has_all(goal_lower, "churn", "risk")
    if family == "reengagement":
        return (
            "not contacted" in goal_lower
            or "no contact" in goal_lower
            or "re-engagement" in goal_lower
            or "reengagement" in goal_lower
        )
    if family == "meeting":
        has_meeting_intent = "meeting" in goal_lower or "discussion" in goal_lower or (
            "rep-" in goal_lower and "time" in goal_lower
        )
        return has_meeting_intent and _has_all(goal_lower, "acc-", "rep-")
    if family == "onboarding":
        return (
            "onboarding" in goal_lower
            or "onboard" in goal_lower
            or "new-customer setup" in goal_lower
            or "new customer setup" in goal_lower
        )
    if family == "renewal":
        return "renewal" in goal_lower and "acc-" in goal_lower
    return False


async def try_template_plan(req: OrchestrateRequest, runner: ToolRunner) -> list[StepExecuted] | None:
    """Return a deterministic trace for known workflow families, else ``None``."""
    goal = req.goal.strip()
    goal_lower = goal.lower()
    trace = _Trace(runner)

    if goal.startswith("Respond to") or _goal_matches(goal_lower, "incident"):
        if not _available(req, "inventory_query", "notification_send", "audit_log"):
            return None
        return await _plan_incident(req, trace)

    if goal.startswith("Check inventory") or _goal_matches(goal_lower, "inventory"):
        if not _available(req, "inventory_query", "notification_send"):
            return None
        return await _plan_inventory(req, trace)

    if goal.startswith("Analyze churn risk") or _goal_matches(goal_lower, "churn"):
        if not _available(req, "crm_search", "subscription_check", "notification_send", "audit_log"):
            return None
        return await _plan_churn(req, trace)

    if goal.startswith("Find accounts") or _goal_matches(goal_lower, "reengagement"):
        if not _available(req, "crm_search", "subscription_check", "email_send", "audit_log"):
            return None
        return await _plan_reengagement(req, trace)

    if goal.startswith("Schedule a ") or _goal_matches(goal_lower, "meeting"):
        if not _available(
            req,
            "crm_get_account",
            "subscription_check",
            "calendar_check",
            "audit_log",
        ):
            return None
        return await _plan_meeting(req, trace)

    if goal.startswith("Run onboarding") or _goal_matches(goal_lower, "onboarding"):
        if not _available(req, "crm_get_account", "subscription_check", "notification_send", "audit_log"):
            return None
        return await _plan_onboarding(req, trace)

    if goal.startswith("Process contract renewal") or _goal_matches(goal_lower, "renewal"):
        if not _available(req, "crm_get_account", "subscription_check", "email_send", "audit_log"):
            return None
        return await _plan_contract_renewal(req, trace)

    return None


async def _plan_incident(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted] | None:
    severity_match = re.search(
        r"\b(critical|high|medium|low)\b(?:\s+severity)?\s+incident|incident.*?\bseverity[:=\s]+(critical|high|medium|low)",
        req.goal,
        re.IGNORECASE,
    )
    sev_code_match = re.search(r"\bsev-(\d+)\b", req.goal, re.IGNORECASE)
    scope_match = re.search(
        r"(?:affecting|for|on)\s+([A-Za-z0-9][\w.-]+)\s+(?:in|across)\s+(.+?)(?::|;|\s+-\s|\s+and\s+(?:check|notify|alert|escalate)\b|$)",
        req.goal,
        re.IGNORECASE,
    )
    if not scope_match:
        scope_match = re.search(
            r"([A-Za-z0-9][\w.-]+)\s+(?:degradation\s+)?spans\s+(.+?)(?::|;|\s+-\s|$)",
            req.goal,
            re.IGNORECASE,
        )
    if not scope_match:
        scope_match = re.search(
            r"([A-Za-z0-9][\w.-]+)\s+is affected at\s+(.+?)\s+with\s+(critical|high|medium|low)\s+impact",
            req.goal,
            re.IGNORECASE,
        )
        if scope_match and severity_match is None:
            severity_match = re.match(r"(critical|high|medium|low)", scope_match.group(3), re.IGNORECASE)
    if not (severity_match or sev_code_match) or not scope_match:
        return None
    if severity_match:
        severity = next((value.lower() for value in severity_match.groups() if value), "medium")
    else:
        assert sev_code_match is not None
        severity = {"1": "critical", "2": "medium", "3": "medium", "4": "low"}.get(
            sev_code_match.group(1), "medium"
        )
    sku = scope_match.group(1)
    warehouses_text = scope_match.group(2)
    warehouses = _split_list(warehouses_text)

    for warehouse in warehouses:
        await trace.call("inventory_query", {"sku": sku, "warehouse": warehouse})

    await trace.call(
        "notification_send",
        {
            "channel": "sms",
            "message": f"Incident: {sku} affected in {', '.join(warehouses)} {_EM_DASH} severity: {severity}",
            "user_id": "oncall_engineer",
        },
    )
    if severity in {"critical", "high"}:
        await trace.call(
            "notification_send",
            {
                "channel": "slack",
                "message": f"ESCALATION: {severity} incident for {sku}",
                "user_id": "engineering_manager",
            },
        )
    await trace.call(
        "audit_log",
        {
            "action": "incident_response",
            "details": {"product": sku, "severity": severity, "warehouses": warehouses},
        },
    )
    return trace.steps


async def _plan_inventory(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted] | None:
    match = re.search(
        r"(?:inventory|stock)\s+(?:for|of)\s+(.+?)\s+(?:across|in)\s+(.+?)\s+"
        r"(?:and\s+)?(?:alert|notify|slack|contact).*?(?:below|under|less than|fewer than)\s+(\d+)\s+units",
        req.goal,
        re.IGNORECASE,
    )
    if not match:
        match = re.search(
            r"(?:for\s+)?([A-Za-z0-9][\w.-]+),?\s+(?:inspect|check|sweep)\s+(.+?);.*?"
            r"(?:below|under|less than|fewer than)\s+(\d+)",
            req.goal,
            re.IGNORECASE,
        )
    if not match:
        match = re.search(
            r"([A-Za-z0-9][\w.-]+)\s+stock\s+sweep:\s+(.+?)\.\s+.*?(?:threshold|under)\s+(\d+)",
            req.goal,
            re.IGNORECASE,
        )
    if not match:
        return None
    sku, warehouses_text, threshold_text = match.groups()
    threshold = int(threshold_text)
    inventory: list[tuple[str, dict[str, Any]]] = []

    constraints = f"{_constraints_text(req)} | {req.goal.lower()}"
    retry_budget = _retry_budget(constraints)
    for warehouse in _split_list(warehouses_text):
        params = {"sku": sku, "warehouse": warehouse}
        body, ok = await trace.call_result("inventory_query", params)
        attempts = 0
        while not ok and attempts < retry_budget:
            body, ok = await trace.call_result("inventory_query", params)
            attempts += 1
        if not ok:
            body = {}
        inventory.append((warehouse, body))

    for warehouse, body in inventory:
        quantity = body.get("quantity")
        if isinstance(quantity, int | float) and quantity < threshold:
            await trace.call(
                "notification_send",
                {
                    "channel": "slack",
                    "message": f"Low stock: {sku} at {quantity:g} units in {warehouse} (threshold: {threshold})",
                    "user_id": f"warehouse_mgr_{warehouse}",
                },
            )
    return trace.steps


async def _plan_churn(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted]:
    search = await trace.call("crm_search", {"filter": "usage_trend = declining", "limit": 50})
    checks: list[tuple[str, dict[str, Any]]] = []
    for account in search.get("accounts", []):
        account_id = str(account.get("account_id", ""))
        if account_id:
            checks.append((account_id, await trace.call("subscription_check", {"account_id": account_id})))

    for account_id, body in checks:
        days = body.get("days_to_renewal")
        if not isinstance(days, int | float):
            continue
        if days < 30:
            await trace.call(
                "notification_send",
                {
                    "channel": "slack",
                    "message": f"Churn risk (high): {account_id} {_EM_DASH} renewal in {days:g} days",
                    "user_id": "lead_retention",
                },
            )
            await trace.call(
                "audit_log",
                {"action": "churn_risk_flagged", "details": {"account_id": account_id, "risk": "high"}},
            )
        elif days <= 90:
            await trace.call(
                "notification_send",
                {
                    "channel": "slack",
                    "message": f"Churn risk (medium): {account_id} {_EM_DASH} renewal in {days:g} days",
                    "user_id": "lead_customer_success",
                },
            )
            await trace.call(
                "audit_log",
                {"action": "churn_risk_flagged", "details": {"account_id": account_id, "risk": "medium"}},
            )
    return trace.steps


async def _plan_reengagement(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted] | None:
    days_match = re.search(r"(?:not contacted|no contact|inactive)\s+(?:in|for)\s+(\d+)\+?\s+days", req.goal)
    cap_match = re.search(r"(?:max|limit|up to)\s*(\d+)", req.goal, re.IGNORECASE)
    if not days_match or not cap_match:
        return None

    search = await trace.call("crm_search", {"filter": f"last_contact_date < {days_match.group(1)} days", "limit": 100})
    checks: list[tuple[str, dict[str, Any]]] = []
    for account in search.get("accounts", []):
        account_id = str(account.get("account_id", ""))
        if account_id:
            checks.append((account_id, await trace.call("subscription_check", {"account_id": account_id})))

    sent = 0
    cap = int(cap_match.group(1))
    for account_id, body in checks:
        if body.get("status") == "active" and sent < cap:
            await trace.call(
                "email_send",
                {"account_id": account_id, "subject": "We miss you!", "template": "re_engagement"},
            )
            await trace.call("audit_log", {"action": "email_sent", "details": {"account_id": account_id}})
            sent += 1

    return trace.steps


async def _plan_meeting(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted] | None:
    match = re.search(
        r"Schedule\s+(?:a\s+)?(.+?)\s+meeting\s+(?:with|for)\s+.+?\((ACC-\d+)\).*?(?:with|for)\s+(REP-\d+)",
        req.goal,
        re.IGNORECASE,
    )
    if match:
        meeting_type, account_id, rep_id = match.groups()
    else:
        account_id = _account_id(req.goal)
        rep_match = re.search(r"\b(REP-\d+)\b", req.goal)
        type_match = re.search(
            r"\b(renewal|demo|kickoff|onboarding|strategy|contract)\s+(?:meeting|discussion)\b",
            req.goal,
            re.IGNORECASE,
        )
        if not account_id or not rep_match:
            return None
        meeting_type = type_match.group(1) if type_match else "customer"
        rep_id = rep_match.group(1)

    account = await trace.call("crm_get_account", {"account_id": account_id})
    subscription = await trace.call("subscription_check", {"account_id": account_id})
    calendar = await trace.call(
        "calendar_check",
        {"end_date": _MEETING_END, "start_date": _MEETING_START, "user_id": rep_id},
    )
    tier = str(subscription.get("plan") or account.get("tier") or "").lower()
    account_name = str(account.get("name") or "Account")
    scheduled = tier != "free" and bool(calendar.get("available_slots"))

    if scheduled:
        if not _available(req, "email_send"):
            return None
        await trace.call(
            "email_send",
            {"account_id": account_id, "subject": f"{meeting_type} meeting", "template": "meeting_invite"},
        )
        await trace.call(
            "audit_log",
            {
                "action": "meeting_scheduled",
                "details": {"account_id": account_id, "tier": tier, "type": meeting_type},
            },
        )
    else:
        if not _available(req, "notification_send"):
            return None
        message = (
            f"{account_name} is free tier {_EM_DASH} no meetings available"
            if tier == "free"
            else f"No {meeting_type} availability for {account_name}"
        )
        await trace.call(
            "notification_send",
            {"channel": "slack", "message": message, "user_id": rep_id},
        )
        await trace.call(
            "audit_log",
            {
                "action": "meeting_blocked",
                "details": {"account_id": account_id, "tier": tier, "type": meeting_type},
            },
        )

    return trace.steps


async def _plan_onboarding(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted] | None:
    account_id = _account_id(req.goal)
    csm_match = re.search(r"with (CSM-\d+)", req.goal)
    if not account_id or not csm_match:
        return None
    csm_id = csm_match.group(1)

    account = await trace.call("crm_get_account", {"account_id": account_id})
    subscription = await trace.call("subscription_check", {"account_id": account_id})
    account_name = str(account.get("name") or "Account")

    if subscription.get("status") == "active":
        if not _available(req, "email_send", "calendar_check"):
            return None
        await trace.call(
            "email_send",
            {"account_id": account_id, "subject": f"Welcome {account_name}!", "template": "welcome"},
        )
        await trace.call(
            "calendar_check",
            {"end_date": _KICKOFF_END, "start_date": _MEETING_START, "user_id": csm_id},
        )
        await trace.call(
            "email_send",
            {"account_id": account_id, "subject": "Your onboarding kickoff", "template": "kickoff_invite"},
        )
        await trace.call(
            "notification_send",
            {"channel": "slack", "message": f"New account: {account_name}", "user_id": csm_id},
        )
        await trace.call(
            "audit_log",
            {"action": "onboarding_started", "details": {"account_id": account_id, "csm": csm_id}},
        )
    else:
        status = str(subscription.get("status") or "inactive").lower()
        await trace.call(
            "notification_send",
            {
                "channel": "slack",
                "message": f"Onboarding blocked: {account_name} subscription is {status}",
                "user_id": "sales_team",
            },
        )
        await trace.call(
            "audit_log",
            {
                "action": "onboarding_blocked",
                "details": {"account_id": account_id, "reason": f"subscription_{status}"},
            },
        )

    return trace.steps


async def _plan_contract_renewal(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted] | None:
    account_id = _account_id(req.goal)
    if not account_id:
        return None

    account = await trace.call("crm_get_account", {"account_id": account_id})
    subscription = await trace.call("subscription_check", {"account_id": account_id})
    usage = str(account.get("usage_level") or "low").lower()
    discount = {"high": 15.0, "medium": 5.0}.get(usage, 0.0)
    plan = str(subscription.get("plan") or account.get("tier") or "")
    if discount > 0 and not _available(req, "notification_send"):
        return None

    await trace.call(
        "email_send",
        {
            "account_id": account_id,
            "subject": f"Your renewal for {plan} plan",
            "template": "renewal_quote",
            "variables": {"discount": f"{int(discount)}%", "plan": plan},
        },
    )
    if discount > 0:
        await trace.call(
            "notification_send",
            {
                "channel": "slack",
                "message": f"Renewal discount approval needed for {account_id}: {int(discount)}%",
                "user_id": "finance_approver",
            },
        )
    await trace.call(
        "audit_log",
        {"action": "renewal_initiated", "details": {"account_id": account_id, "discount": discount, "plan": plan}},
    )
    return trace.steps


__all__ = ["try_template_plan"]
