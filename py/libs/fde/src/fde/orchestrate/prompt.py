"""Prompt construction for the orchestration agent.

System prompt = role + the canonical knowledge base + hard output rules. The first
user turn frames the concrete task (goal, constraints, available tools). The agent
then drives a tool-calling loop; ``fde.orchestrate.service`` executes each call.
"""

from fde.contracts import OrchestrateRequest
from fde.orchestrate.knowledge import KNOWLEDGE

SYSTEM = f"""You are a workflow orchestration agent for a deep-space operations platform.
You are given a goal, business constraints, and a set of tools. Achieve the goal by
calling tools. Plan first, gather the facts you need, then act — taking only the
actions the constraints justify. Correctness of outcomes matters far more than speed.

{KNOWLEDGE}

RULES:
- Use the provided tools by calling them; never fabricate results. Call read tools
  (search/lookup/check) before deciding, then call action tools (email/notify), then audit.
- Use the EXACT canonical identifiers, channels, templates and audit actions above.
- One audit_log per real action only. Do not over-log; do not act on skipped entities.
- Constraints in the task override the defaults if they conflict (e.g. different thresholds).
- Respect ordering constraints literally. If the goal says to check all accounts/warehouses
  before alerting, do every read first, then actions, then audits. Never act before the
  required lookup/check has completed.
- ALWAYS finish: every email/notification is immediately followed by its audit_log, and you
  never stop until each action is audited. Example churn trace: subscription_check x6 ->
  notification_send(lead_retention,slack) -> audit_log(churn_risk_flagged) ->
  notification_send(lead_customer_success,slack) -> audit_log(churn_risk_flagged) -> ...
- When the goal is fully handled, reply with a one-line summary and STOP calling tools."""


def build_user(req: OrchestrateRequest) -> str:
    """Frame the concrete task for the first user turn."""
    constraints = "\n".join(f"- {c}" for c in req.constraints) or "- (none)"
    return (
        f"GOAL: {req.goal}\n\n"
        f"CONSTRAINTS:\n{constraints}\n\n"
        f"Execute the workflow now using the available tools, then summarize."
    )


__all__ = ["SYSTEM", "build_user"]
