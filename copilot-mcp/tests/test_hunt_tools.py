"""Integration tests for the Talon threat-hunting tools.

Each test drives a real registered MCP tool through `app.call_tool` against a
mocked HTTP transport — exercising argument validation, the client request it
builds, and the response shaping, with no live CoPilot call.

Tool arguments are nested under an `args` key: upstream declares each tool
with a single Pydantic model parameter named `args`, so FastMCP publishes an
input schema of {"args": {...}}. The hunt tools follow that same shape.
"""

from __future__ import annotations

import json
from typing import Any, Callable, List, Tuple

import httpx
import pytest
from fastmcp.exceptions import ToolError

from copilot_mcp_server import endpoints
from copilot_mcp_server.client import CoPilotClient
from copilot_mcp_server.config import Config, CoPilotConfig, ServerConfig
from copilot_mcp_server.exceptions import CoPilotMCPError
from copilot_mcp_server.hunt import timeframe_params
from copilot_mcp_server.server import CoPilotMCPServer

TOKEN_PATH = "/api/auth/token"


def _build(
    responder: Callable[[httpx.Request], httpx.Response],
) -> Tuple[CoPilotMCPServer, List[httpx.Request]]:
    """Return a server whose client talks to a mock transport, plus a request log."""
    seen: List[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == TOKEN_PATH:
            return httpx.Response(200, json={"access_token": "test-token"})
        return responder(request)

    config = Config(
        copilot=CoPilotConfig(url="https://copilot.test", username="u", password="p"),
        server=ServerConfig(),
    )
    server = CoPilotMCPServer(config)
    client = CoPilotClient(config.copilot)
    client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    server._client = client
    return server, seen


def _unwrap_text_blocks(value: Any) -> Any:
    """Unwrap a `[{"type": "text", "text": "..."}]` block into its parsed body.

    The tools return MCP-content-shaped dicts, which FastMCP then JSON-encodes
    as an ordinary return value — so the real payload sits one layer deeper
    than the transport content. Applied repeatedly so the test is indifferent
    to how many layers of that wrapping are in play.
    """
    while (
        isinstance(value, list)
        and len(value) == 1
        and isinstance(value[0], dict)
        and value[0].get("type") == "text"
    ):
        value = json.loads(value[0]["text"])
    return value


def _json_payload(result: Any) -> Any:
    """Pull the JSON body out of whatever envelope call_tool returned."""
    content = getattr(result, "content", result)
    if isinstance(content, list) and content:
        first = content[0]
        text = first.get("text") if isinstance(first, dict) else getattr(first, "text", None)
        if text is not None:
            return _unwrap_text_blocks(json.loads(text))
    raise AssertionError(f"unexpected tool result shape: {result!r}")


def _api_calls(seen: List[httpx.Request]) -> List[httpx.Request]:
    return [r for r in seen if r.url.path != TOKEN_PATH]


# --------------------------------------------------------------------------- #
# SearchEventsTool
# --------------------------------------------------------------------------- #
EVENT = {
    "timestamp": "2026-09-12T10:00:00Z",
    "agent_name": "WIN-DC01",
    "agent_id": "004",
    "data_win_eventdata_user": "svc_backup",
    "rule_id": "92052",
    "rule_description": "Powershell encoded command executed",
    "data_win_eventdata_commandLine": "powershell -enc SQBFAFgA",
    "index_name": "wazuh-alerts-4.x-2026.09.12",
}


async def test_search_events_tool_shapes_hits_and_sends_relative_timerange():
    def responder(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == endpoints.SEARCH.format(
            customer_code="ACME", source_name="wazuh"
        )
        return httpx.Response(200, json={"success": True, "events": [EVENT], "total": 1})

    server, seen = _build(responder)
    result = await server.app.call_tool(
        "SearchEventsTool",
        {"args": {"customer_code": "ACME", "query": "powershell -enc", "source_name": "wazuh"}},
    )
    payload = _json_payload(result)

    assert payload["hit_count"] == 1
    assert payload["customer_code"] == "ACME"
    assert payload["sources_searched"] == ["wazuh"]

    found = payload["hits"][0]
    assert found["timestamp"] == "2026-09-12T10:00:00Z"
    assert found["host"] == "WIN-DC01"
    assert found["agent_id"] == "004"
    assert found["user"] == "svc_backup"
    assert found["rule_id"] == "92052"
    assert found["index"] == "wazuh-alerts-4.x-2026.09.12"
    assert found["source_name"] == "wazuh"
    assert "data_win_eventdata_commandLine" in found["matched_fields"]
    assert found["raw_fields"]["rule_description"].startswith("Powershell")

    # last_24h must go out as the API's relative timerange, not absolute bounds.
    params = _api_calls(seen)[0].url.params
    assert params["timerange"] == "24h"
    assert params["query"] == "powershell -enc"
    assert params["page_size"] == "100"
    assert "time_from" not in params


async def test_search_events_tool_sends_absolute_range_for_iso_timeframe():
    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"success": True, "events": []})

    server, seen = _build(responder)
    result = await server.app.call_tool(
        "SearchEventsTool",
        {
            "args": {
                "customer_code": "ACME",
                "query": "mimikatz",
                "source_name": "wazuh",
                "timeframe": "2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
                "limit": 25,
            }
        },
    )
    assert _json_payload(result)["hit_count"] == 0

    params = _api_calls(seen)[0].url.params
    assert params["time_from"] == "2026-09-01T00:00:00Z"
    assert params["time_to"] == "2026-09-02T00:00:00Z"
    assert params["page_size"] == "25"
    # The API takes one or the other, never both.
    assert "timerange" not in params


async def test_search_events_tool_fans_out_when_source_omitted():
    """Omitting source_name searches every source the customer has."""

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == endpoints.EVENT_SOURCES.format(customer_code="ACME"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "event_sources": [{"source_name": "wazuh"}, {"source_name": "office365"}],
                },
            )
        return httpx.Response(200, json={"success": True, "events": [EVENT]})

    server, seen = _build(responder)
    result = await server.app.call_tool(
        "SearchEventsTool", {"args": {"customer_code": "ACME", "query": "powershell"}}
    )
    payload = _json_payload(result)

    assert payload["sources_searched"] == ["wazuh", "office365"]
    assert payload["hit_count"] == 2
    assert {h["source_name"] for h in payload["hits"]} == {"wazuh", "office365"}
    # One source lookup plus one search per source.
    assert len(_api_calls(seen)) == 3


async def test_search_events_tool_survives_one_failing_source():
    """A dead source is reported but must not sink the rest of the hunt."""

    def responder(request: httpx.Request) -> httpx.Response:
        if request.url.path == endpoints.EVENT_SOURCES.format(customer_code="ACME"):
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "event_sources": [{"source_name": "wazuh"}, {"source_name": "broken"}],
                },
            )
        if "broken" in str(request.url):
            return httpx.Response(500, json={"detail": "index unavailable"})
        return httpx.Response(200, json={"success": True, "events": [EVENT]})

    server, _ = _build(responder)
    result = await server.app.call_tool(
        "SearchEventsTool", {"args": {"customer_code": "ACME", "query": "powershell"}}
    )
    payload = _json_payload(result)

    assert payload["hit_count"] == 1
    assert "broken" in payload["source_errors"]
    assert "500" in payload["source_errors"]["broken"]


async def test_search_events_tool_rejects_bad_timeframe_without_calling_api():
    def responder(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("API must not be called when the timeframe is invalid")

    server, seen = _build(responder)
    with pytest.raises(ToolError) as excinfo:
        await server.app.call_tool(
            "SearchEventsTool",
            {"args": {"customer_code": "ACME", "query": "x", "timeframe": "yesterday-ish"}},
        )
    assert "yesterday-ish" in str(excinfo.value)
    assert _api_calls(seen) == []


# --------------------------------------------------------------------------- #
# ListEventSourcesTool
# --------------------------------------------------------------------------- #
async def test_list_event_sources_tool_returns_sources():
    sources = {"success": True, "event_sources": [{"source_name": "wazuh"}]}

    def responder(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == endpoints.EVENT_SOURCES.format(customer_code="ACME")
        return httpx.Response(200, json=sources)

    server, seen = _build(responder)
    result = await server.app.call_tool("ListEventSourcesTool", {"args": {"customer_code": "ACME"}})
    assert _json_payload(result) == sources
    assert len(_api_calls(seen)) == 1


# --------------------------------------------------------------------------- #
# GetAlertTool
# --------------------------------------------------------------------------- #
async def test_get_alert_tool_fetches_by_id():
    alert = {"id": 4321, "alert_name": "Suspicious PowerShell", "customer_code": "ACME"}

    def responder(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == endpoints.ALERT_DETAIL.format(alert_id=4321)
        return httpx.Response(200, json=alert)

    server, seen = _build(responder)
    result = await server.app.call_tool("GetAlertTool", {"args": {"alert_id": 4321}})

    assert _json_payload(result) == alert
    assert len(_api_calls(seen)) == 1


async def test_get_alert_tool_surfaces_backend_error_as_tool_error():
    def responder(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "Alert 99 not found"})

    server, _ = _build(responder)
    with pytest.raises(ToolError) as excinfo:
        await server.app.call_tool("GetAlertTool", {"args": {"alert_id": 99}})

    message = str(excinfo.value)
    assert "GetAlertTool failed" in message
    assert "404" in message
    assert "not found" in message


# --------------------------------------------------------------------------- #
# ListIndicesTool
# --------------------------------------------------------------------------- #
async def test_list_indices_tool_returns_index_list():
    indices = [
        {"index": "wazuh-alerts-4.x-2026.09.12", "health": "green", "docs_count": "12043"},
        {"index": "wazuh-alerts-4.x-2026.09.11", "health": "green", "docs_count": "11877"},
    ]

    def responder(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == endpoints.INDICES
        return httpx.Response(200, json=indices)

    server, seen = _build(responder)
    # No-arg tools take `_args`, matching upstream's GetCustomersTool.
    result = await server.app.call_tool("ListIndicesTool", {"_args": {}})

    payload = _json_payload(result)
    assert [row["index"] for row in payload] == [row["index"] for row in indices]
    assert len(_api_calls(seen)) == 1


# --------------------------------------------------------------------------- #
# GetAgentTool
# --------------------------------------------------------------------------- #
async def test_get_agent_tool_returns_last_seen_and_status():
    agent = {
        "agent_id": "004",
        "hostname": "WIN-DC01",
        "agent_last_seen": "2026-09-05T02:11:00Z",
        "wazuh_agent_status": "disconnected",
    }

    def responder(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == endpoints.AGENT_DETAIL.format(agent_id="004")
        return httpx.Response(200, json=agent)

    server, seen = _build(responder)
    result = await server.app.call_tool("GetAgentTool", {"args": {"agent_id": "004"}})

    payload = _json_payload(result)
    assert payload["agent_last_seen"] == "2026-09-05T02:11:00Z"
    assert payload["wazuh_agent_status"] == "disconnected"
    assert len(_api_calls(seen)) == 1


# --------------------------------------------------------------------------- #
# Timeframe parsing
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "timeframe,expected",
    [
        ("last_24h", "24h"),
        ("last_7d", "7d"),
        ("LAST_24H", "24h"),
        ("2w", "2w"),
        ("48h", "48h"),
    ],
)
def test_timeframe_params_relative(timeframe: str, expected: str):
    assert timeframe_params(timeframe) == {"timerange": expected}


def test_timeframe_params_iso_range_normalizes_to_utc():
    params = timeframe_params("2026-09-01T00:00:00Z..2026-09-02T00:00:00Z")
    assert params == {
        "time_from": "2026-09-01T00:00:00Z",
        "time_to": "2026-09-02T00:00:00Z",
    }


def test_timeframe_params_rejects_reversed_range():
    with pytest.raises(CoPilotMCPError, match="is after end"):
        timeframe_params("2026-09-02T00:00:00Z/2026-09-01T00:00:00Z")


def test_timeframe_params_rejects_garbage():
    with pytest.raises(CoPilotMCPError, match="Unrecognized timeframe"):
        timeframe_params("whenever")
