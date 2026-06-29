"""Unit tests for Task 3 orchestration: the tool-calling loop records an ordered trace,
stops when the model stops, maps tools to function specs, and degrades safely with no
client. Uses FakeLLMClient; tool HTTP calls hit an unreachable endpoint so they fail fast
and exercise the success=False path without a server."""

import asyncio

import httpx
from fde.contracts import OrchestrateRequest
from fde.contracts import ToolDefinition
from fde.contracts import ToolParameter
from fde.llm import AssistantTurn
from fde.llm import FakeLLMClient
from fde.llm import ToolCall
from fde.orchestrate import orchestrate
from fde.orchestrate.planner import try_template_plan
from fde.orchestrate.tools import ToolRunner
from fde.orchestrate.tools import endpoint_map
from fde.orchestrate.tools import to_function_specs

_TOOLS = [
    ToolDefinition(
        name="subscription_check",
        description="Check subscription",
        endpoint="http://127.0.0.1:1/subscription_check",
        parameters=[ToolParameter(name="account_id", type="string", description="acct", required=True)],
    ),
    ToolDefinition(
        name="audit_log",
        description="Log it",
        endpoint="http://127.0.0.1:1/audit_log",
        parameters=[ToolParameter(name="action", type="string", description="a", required=True)],
    ),
]

_ALL_TOOLS = [
    ToolDefinition(
        name=name,
        description=name,
        endpoint=f"http://127.0.0.1:1/{name}",
        parameters=[],
    )
    for name in (
        "crm_get_account",
        "crm_search",
        "subscription_check",
        "calendar_check",
        "inventory_query",
        "email_send",
        "notification_send",
        "audit_log",
    )
]


def _req(**ov: object) -> OrchestrateRequest:
    base: dict[str, object] = {"task_id": "TASK-1", "goal": "do it", "available_tools": _TOOLS, "constraints": ["c1"]}
    base.update(ov)
    return OrchestrateRequest(**base)  # type: ignore[arg-type]


def _two_round_handler():
    calls = {"n": 0}

    def handler(**_kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return AssistantTurn(content="", tool_calls=[
                ToolCall(id="1", name="subscription_check", arguments={"account_id": "ACC-1"}),
                ToolCall(id="2", name="audit_log", arguments={"action": "email_sent"}),
            ])
        return AssistantTurn(content="done", tool_calls=[])

    return handler


def test_records_trace_and_completes() -> None:
    resp = asyncio.run(orchestrate(_req(), FakeLLMClient(chat_handler=_two_round_handler())))
    d = resp.model_dump()
    assert d["task_id"] == "TASK-1"
    assert d["status"] == "completed"
    assert [s["tool"] for s in d["steps_executed"]] == ["subscription_check", "audit_log"]
    assert [s["step"] for s in d["steps_executed"]] == [1, 2]
    assert d["constraints_satisfied"] == ["c1"]


def test_no_client_degrades_to_failed() -> None:
    resp = asyncio.run(orchestrate(_req(), None))
    assert resp.status == "failed"
    assert resp.steps_executed == []


def test_stops_when_model_emits_no_tool_calls() -> None:
    resp = asyncio.run(orchestrate(_req(), FakeLLMClient(chat_handler=lambda **_: AssistantTurn(content="hi"))))
    assert resp.status == "failed"
    assert resp.steps_executed == []


def test_to_function_specs_maps_params_and_required() -> None:
    specs = to_function_specs(_TOOLS)
    sub = next(s for s in specs if s["function"]["name"] == "subscription_check")
    assert sub["function"]["parameters"]["properties"]["account_id"]["type"] == "string"
    assert sub["function"]["parameters"]["required"] == ["account_id"]


def test_endpoint_map_prefers_tool_endpoint() -> None:
    m = endpoint_map(_TOOLS, "http://mock/scenario/TASK-1")
    assert m["audit_log"] == "http://127.0.0.1:1/audit_log"


def test_endpoint_map_uses_rewritten_mock_url_when_tool_endpoint_missing() -> None:
    tools = [
        ToolDefinition(
            name="audit_log",
            description="Log it",
            endpoint="",
            parameters=[ToolParameter(name="action", type="string", description="a", required=True)],
        )
    ]
    m = endpoint_map(tools, "https://platform.example/scenario/TASK-1")
    assert m["audit_log"] == "https://platform.example/scenario/TASK-1/audit_log"


def test_tool_runner_retries_retryable_statuses() -> None:
    calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429, json={"error": "slow down"}, headers={"Retry-After-Ms": "1"})
        return httpx.Response(200, json={"ok": True})

    runner = ToolRunner(
        {"audit_log": "https://platform.example/scenario/TASK-1/audit_log"},
        transport=httpx.MockTransport(handler),
    )
    try:
        body, ok, summary = asyncio.run(runner.call("audit_log", {"action": "x"}))
    finally:
        asyncio.run(runner.aclose())

    assert calls["n"] == 2
    assert ok is True
    assert body == {"ok": True}
    assert summary == '{"ok": true}'


def test_emails_sent_excludes_failed_sends() -> None:
    tools = [
        ToolDefinition(
            name="email_send",
            description="send",
            endpoint="http://127.0.0.1:1/email_send",
            parameters=[ToolParameter(name="account_id", type="string", description="a", required=True)],
        )
    ]

    def handler(**_kw):
        if handler.n == 0:  # type: ignore[attr-defined]
            handler.n = 1  # type: ignore[attr-defined]
            tc = ToolCall(id="1", name="email_send", arguments={"account_id": "A"})
            return AssistantTurn(content="", tool_calls=[tc])
        return AssistantTurn(content="done", tool_calls=[])

    handler.n = 0  # type: ignore[attr-defined]
    resp = asyncio.run(orchestrate(_req(available_tools=tools), FakeLLMClient(chat_handler=handler)))
    # the send hit an unreachable endpoint (success=False) so it must not be counted
    assert resp.emails_sent is None


class _RecordingRunner:
    def __init__(self, responses: dict[str, list[dict[str, object]]]) -> None:
        self.responses = responses
        self.counts = {name: 0 for name in responses}

    async def call(self, name: str, params: dict[str, object]) -> tuple[dict[str, object], bool, str]:
        idx = self.counts.get(name, 0)
        self.counts[name] = idx + 1
        options = self.responses.get(name) or [{}]
        body = options[min(idx, len(options) - 1)]
        return body, True, "ok"


def test_template_planner_inventory_queries_all_before_alerting() -> None:
    req = OrchestrateRequest(
        task_id="TASK-INV",
        goal=(
            "Check inventory for Sensor-B200 across EU-CENTRAL, APAC-SOUTH, US-WEST "
            "and alert warehouse managers if stock is below 25 units"
        ),
        available_tools=_ALL_TOOLS,
        constraints=["Only alert if stock is below 25 units"],
    )
    runner = _RecordingRunner(
        {"inventory_query": [{"quantity": 61}, {"quantity": 9}, {"quantity": 46}], "notification_send": [{}]}
    )

    steps = asyncio.run(try_template_plan(req, runner))  # type: ignore[arg-type]

    assert steps is not None
    assert [step.tool for step in steps] == [
        "inventory_query",
        "inventory_query",
        "inventory_query",
        "notification_send",
    ]
    assert steps[-1].parameters["user_id"] == "warehouse_mgr_APAC-SOUTH"


def test_template_planner_meeting_variant_uses_goal_type() -> None:
    req = OrchestrateRequest(
        task_id="TASK-MTG",
        goal=(
            "Schedule a demo meeting with Blue Yonder Airlines (ACC-0315) - check tier, "
            "find availability with REP-322, and send invite or notify if blocked"
        ),
        available_tools=_ALL_TOOLS,
        constraints=["Free-tier accounts cannot schedule meetings"],
    )
    runner = _RecordingRunner(
        {
            "crm_get_account": [{"name": "Blue Yonder Airlines", "tier": "enterprise"}],
            "subscription_check": [{"plan": "enterprise", "status": "active"}],
            "calendar_check": [{"available_slots": ["2026-04-10T10:00"]}],
            "email_send": [{}],
            "audit_log": [{}],
        }
    )

    steps = asyncio.run(try_template_plan(req, runner))  # type: ignore[arg-type]

    assert steps is not None
    assert [step.tool for step in steps] == [
        "crm_get_account",
        "subscription_check",
        "calendar_check",
        "email_send",
        "audit_log",
    ]
    assert steps[3].parameters["subject"] == "demo meeting"
    assert steps[4].parameters["details"]["type"] == "demo"


def test_template_planner_inactive_onboarding_does_not_require_email_tools() -> None:
    tools = [tool for tool in _ALL_TOOLS if tool.name not in {"email_send", "calendar_check"}]
    req = OrchestrateRequest(
        task_id="TASK-ONBOARD",
        goal=(
            "Run onboarding workflow for new account Tailspin Toys (ACC-0006): verify subscription, "
            "send welcome package, schedule kickoff with CSM-316, and notify CSM"
        ),
        available_tools=tools,
        constraints=["If subscription is NOT active, abort and notify sales instead"],
    )
    runner = _RecordingRunner(
        {
            "crm_get_account": [{"name": "Tailspin Toys"}],
            "subscription_check": [{"status": "inactive", "plan": "none"}],
            "notification_send": [{}],
            "audit_log": [{}],
        }
    )

    steps = asyncio.run(try_template_plan(req, runner))  # type: ignore[arg-type]

    assert steps is not None
    assert [step.tool for step in steps] == [
        "crm_get_account",
        "subscription_check",
        "notification_send",
        "audit_log",
    ]
    assert steps[2].parameters["message"] == "Onboarding blocked: Tailspin Toys subscription is inactive"
    assert steps[3].parameters["details"]["reason"] == "subscription_inactive"


def test_template_planner_low_discount_renewal_does_not_require_notification_tool() -> None:
    tools = [tool for tool in _ALL_TOOLS if tool.name != "notification_send"]
    req = OrchestrateRequest(
        task_id="TASK-RENEW",
        goal=(
            "Process contract renewal for Tailspin Toys (ACC-0456): check usage, generate renewal quote "
            "with appropriate discount, get approval if needed"
        ),
        available_tools=tools,
        constraints=["Low-usage accounts get no discount"],
    )
    runner = _RecordingRunner(
        {
            "crm_get_account": [{"usage_level": "low", "tier": "professional"}],
            "subscription_check": [{"plan": "professional", "status": "active"}],
            "email_send": [{}],
            "audit_log": [{}],
        }
    )

    steps = asyncio.run(try_template_plan(req, runner))  # type: ignore[arg-type]

    assert steps is not None
    assert [step.tool for step in steps] == [
        "crm_get_account",
        "subscription_check",
        "email_send",
        "audit_log",
    ]
    assert steps[2].parameters["variables"]["discount"] == "0%"


def test_template_planner_active_onboarding_requires_active_branch_tools() -> None:
    tools = [tool for tool in _ALL_TOOLS if tool.name not in {"email_send", "calendar_check"}]
    req = OrchestrateRequest(
        task_id="TASK-ONBOARD-ACTIVE",
        goal=(
            "Run onboarding workflow for new account Tailspin Toys (ACC-0260): verify subscription, "
            "send welcome package, schedule kickoff with CSM-844, and notify CSM"
        ),
        available_tools=tools,
        constraints=["Verify subscription is active before sending welcome email"],
    )
    runner = _RecordingRunner(
        {
            "crm_get_account": [{"name": "Tailspin Toys"}],
            "subscription_check": [{"status": "active", "plan": "enterprise"}],
        }
    )

    assert asyncio.run(try_template_plan(req, runner)) is None  # type: ignore[arg-type]


def test_template_planner_approval_renewal_requires_notification_tool() -> None:
    tools = [tool for tool in _ALL_TOOLS if tool.name != "notification_send"]
    req = OrchestrateRequest(
        task_id="TASK-RENEW-HIGH",
        goal=(
            "Process contract renewal for Tailspin Toys (ACC-9999): check usage, generate renewal quote "
            "with appropriate discount, get approval if needed"
        ),
        available_tools=tools,
        constraints=["High-usage accounts get 15% discount"],
    )
    runner = _RecordingRunner(
        {
            "crm_get_account": [{"usage_level": "high", "tier": "enterprise"}],
            "subscription_check": [{"plan": "enterprise", "status": "active"}],
        }
    )

    assert asyncio.run(try_template_plan(req, runner)) is None  # type: ignore[arg-type]
