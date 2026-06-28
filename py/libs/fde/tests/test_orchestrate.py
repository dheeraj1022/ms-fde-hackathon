"""Unit tests for Task 3 orchestration: the tool-calling loop records an ordered trace,
stops when the model stops, maps tools to function specs, and degrades safely with no
client. Uses FakeLLMClient; tool HTTP calls hit an unreachable endpoint so they fail fast
and exercise the success=False path without a server."""

import asyncio

from fde.contracts import OrchestrateRequest
from fde.contracts import ToolDefinition
from fde.contracts import ToolParameter
from fde.llm import AssistantTurn
from fde.llm import FakeLLMClient
from fde.llm import ToolCall
from fde.orchestrate import orchestrate
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

