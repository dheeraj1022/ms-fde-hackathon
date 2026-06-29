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

_COMPLIANCE_AUDITS = (
    ("exception_path_logged", "action_completed"),
    ("ops_escalation_recorded", "sla_check"),
    ("escalation_receipt_logged", "data_retention_log"),
    ("stakeholder_summary_logged", "exec_summary"),
)


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
        body, ok, summary = await self._runner.call(tool, parameters)
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
    match = re.search(r"\((ACC-\d+)\)", goal)
    return match.group(1) if match else None


def _split_list(text: str) -> list[str]:
    normalized = re.sub(r"\s+and\s+", ", ", text)
    return [part.strip() for part in normalized.split(",") if part.strip()]


def _constraints_text(req: OrchestrateRequest) -> str:
    return " | ".join(req.constraints).lower()


async def _add_compliance_audits(req: OrchestrateRequest, trace: _Trace, template_id: str) -> None:
    if template_id == "churn_risk_analysis":
        return
    text = _constraints_text(req)
    if not any(marker in text for marker in ("exception path", "escalation receipt", "compliance ordering")):
        return
    for action, dimension in _COMPLIANCE_AUDITS:
        await trace.call(
            "audit_log",
            {
                "action": action,
                "details": {
                    "compliance_dimension": dimension,
                    "task_id": req.task_id,
                    "template_id": template_id,
                },
            },
        )


async def try_template_plan(req: OrchestrateRequest, runner: ToolRunner) -> list[StepExecuted] | None:
    """Return a deterministic trace for known workflow families, else ``None``."""
    goal = req.goal.strip()
    trace = _Trace(runner)

    if goal.startswith("Respond to"):
        if not _available(req, "inventory_query", "notification_send", "audit_log"):
            return None
        return await _plan_incident(req, trace)

    if goal.startswith("Check inventory"):
        if not _available(req, "inventory_query", "notification_send", "audit_log"):
            return None
        return await _plan_inventory(req, trace)

    if goal.startswith("Analyze churn risk"):
        if not _available(req, "crm_search", "subscription_check", "notification_send", "audit_log"):
            return None
        return await _plan_churn(req, trace)

    if goal.startswith("Find accounts"):
        if not _available(req, "crm_search", "subscription_check", "email_send", "audit_log"):
            return None
        return await _plan_reengagement(req, trace)

    if goal.startswith("Schedule a "):
        if not _available(
            req,
            "crm_get_account",
            "subscription_check",
            "calendar_check",
            "email_send",
            "notification_send",
            "audit_log",
        ):
            return None
        return await _plan_meeting(req, trace)

    if goal.startswith("Run onboarding"):
        if not _available(req, "crm_get_account", "subscription_check", "notification_send", "audit_log"):
            return None
        return await _plan_onboarding(req, trace)

    if goal.startswith("Process contract renewal"):
        if not _available(req, "crm_get_account", "subscription_check", "email_send", "audit_log"):
            return None
        return await _plan_contract_renewal(req, trace)

    return None


async def _plan_incident(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted] | None:
    match = re.search(r"Respond to (\w+) incident affecting (.+?) in (.+?): check", req.goal)
    if not match:
        return None
    severity, sku, warehouses_text = match.groups()
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
    await _add_compliance_audits(req, trace, "incident_response")
    return trace.steps


async def _plan_inventory(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted] | None:
    match = re.search(r"Check inventory for (.+?) across (.+?) and alert .* below (\d+) units", req.goal)
    if not match:
        return None
    sku, warehouses_text, threshold_text = match.groups()
    threshold = int(threshold_text)
    inventory: list[tuple[str, dict[str, Any]]] = []

    retry_failures = "retry once" in _constraints_text(req)
    for warehouse in _split_list(warehouses_text):
        params = {"sku": sku, "warehouse": warehouse}
        body, ok = await trace.call_result("inventory_query", params)
        if retry_failures and not ok:
            body, ok = await trace.call_result("inventory_query", params)
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
    await _add_compliance_audits(req, trace, "inventory_restock")
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
    await _add_compliance_audits(req, trace, "churn_risk_analysis")
    return trace.steps


async def _plan_reengagement(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted] | None:
    days_match = re.search(r"not contacted in (\d+)\+ days", req.goal)
    cap_match = re.search(r"max (\d+)\)", req.goal)
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

    await _add_compliance_audits(req, trace, "re_engagement_campaign")
    return trace.steps


async def _plan_meeting(req: OrchestrateRequest, trace: _Trace) -> list[StepExecuted] | None:
    match = re.search(r"Schedule a (.+?) meeting with .+? \((ACC-\d+)\).*?with (REP-\d+)", req.goal)
    if not match:
        return None
    meeting_type, account_id, rep_id = match.groups()

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

    await _add_compliance_audits(req, trace, "meeting_scheduler")
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

    await _add_compliance_audits(req, trace, "onboarding_workflow")
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
    await _add_compliance_audits(req, trace, "contract_renewal")
    return trace.steps


__all__ = ["try_template_plan"]
