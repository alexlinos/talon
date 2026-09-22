"""Tests for _run_tool error propagation.

A backend failure (e.g. a 422 validation error from the CoPilot API) must reach
the agent as a real MCP tool error (isError=true via ToolError), not as a
success-shaped text block the agent could misread as completion.
"""

import pytest
from fastmcp.exceptions import ToolError

from copilot_mcp_server.config import Config, CoPilotConfig, ServerConfig
from copilot_mcp_server.exceptions import CoPilotAPIError
from copilot_mcp_server.server import CoPilotMCPServer


def _server() -> CoPilotMCPServer:
    cfg = Config(
        copilot=CoPilotConfig(url="http://example.invalid", username="u", password="p"),
        server=ServerConfig(),
    )
    return CoPilotMCPServer(cfg)


async def test_run_tool_success_returns_text_block():
    server = _server()

    async def ok():
        return {"hello": "world"}

    result = await server._run_tool("AnyTool", ok())

    assert result[0]["type"] == "text"
    assert "hello" in result[0]["text"]


async def test_run_tool_raises_tool_error_on_backend_failure():
    server = _server()

    async def boom():
        raise CoPilotAPIError(
            "CoPilot API error (422) on POST /api/ai_analyst/reports: "
            '{"detail": "Report body fields must be non-empty: report_markdown"}'
        )

    with pytest.raises(ToolError) as excinfo:
        await server._run_tool("SubmitAiAnalystReportTool", boom())

    message = str(excinfo.value)
    # Tool name and the backend detail must both survive so the agent can act on it.
    assert "SubmitAiAnalystReportTool failed" in message
    assert "422" in message
    assert "report_markdown" in message
