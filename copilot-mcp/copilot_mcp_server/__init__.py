"""SOCFortress CoPilot MCP Server.

A Model Context Protocol (MCP) server that wraps the SOCFortress CoPilot API,
exposing its endpoints as MCP tools for use by AI agents.

Talon fork of github.com/socfortress/copilot-mcp-server — adds the
threat-hunting tools (SearchEventsTool, GetAlertTool, ListIndicesTool,
GetAgentTool) on top of upstream's AI-analyst write-back surface.
"""

from copilot_mcp_server.client import CoPilotClient
from copilot_mcp_server.config import Config, CoPilotConfig, ServerConfig
from copilot_mcp_server.server import CoPilotMCPServer, create_server

__version__ = "0.1.0+talon.1"

__all__ = [
    "CoPilotClient",
    "CoPilotConfig",
    "CoPilotMCPServer",
    "Config",
    "ServerConfig",
    "create_server",
    "__version__",
]
