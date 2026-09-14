# copilot-mcp-server

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that wraps the
[SOCFortress CoPilot](https://github.com/socfortress/CoPilot) API and exposes its endpoints
as MCP tools for use by SOC AI agents.

## Features

- OAuth2 password-grant authentication against the CoPilot backend with JWT token caching and
  automatic refresh on `401`s.
- Async HTTP client built on `httpx` (HTTP/2 enabled).
- Pluggable tool registration via [`fastmcp`](https://pypi.org/project/fastmcp/).
- **stdio transport** — designed to be launched on demand by an MCP host (Claude Desktop,
  LangChain, custom containers).
- Configuration via environment variables, `.env` file, or CLI flags.

### Available tools

**Customers**

| Tool | Endpoint | Description |
|------|----------|-------------|
| `GetCustomersTool` | `GET /api/customers` | Fetches the list of customers from CoPilot. |

**AI Analyst — Jobs**

| Tool | Endpoint | Description |
|------|----------|-------------|
| `CreateAiAnalystJobTool` | `POST /api/ai_analyst/jobs` | Register a new AI analyst investigation job. |
| `UpdateAiAnalystJobTool` | `PATCH /api/ai_analyst/jobs/{job_id}` | Update a job's status / error message. |
| `GetAiAnalystJobTool` | `GET /api/ai_analyst/jobs/{job_id}` | Get a specific job by ID. |
| `ListAiAnalystJobsByAlertTool` | `GET /api/ai_analyst/jobs/alert/{alert_id}` | List all jobs for an alert. |
| `ListAiAnalystJobsByCustomerTool` | `GET /api/ai_analyst/jobs/customer/{code}` | List all jobs for a customer. |

**AI Analyst — Reports**

| Tool | Endpoint | Description |
|------|----------|-------------|
| `SubmitAiAnalystReportTool` | `POST /api/ai_analyst/reports` | Submit a markdown investigation report with severity and recommended actions. |
| `ListAiAnalystReportsByAlertTool` | `GET /api/ai_analyst/reports/alert/{alert_id}` | List all reports for an alert. |

**AI Analyst — IOCs**

| Tool | Endpoint | Description |
|------|----------|-------------|
| `SubmitAiAnalystIocsTool` | `POST /api/ai_analyst/iocs` | Submit extracted IOCs with VT verdicts for a report. |
| `ListAiAnalystIocsByReportTool` | `GET /api/ai_analyst/iocs/report/{report_id}` | List IOCs for a specific report. |
| `ListAiAnalystIocsByAlertTool` | `GET /api/ai_analyst/iocs/alert/{alert_id}` | List all IOCs for an alert. |
| `ListAiAnalystIocsByCustomerTool` | `GET /api/ai_analyst/iocs/customer/{code}` | List IOCs for a customer (optionally filtered by VT verdict). |

**AI Analyst — Combined**

| Tool | Endpoint | Description |
|------|----------|-------------|
| `GetAlertAiAnalysisTool` | `GET /api/ai_analyst/alert/{alert_id}` | One-shot: job + report + IOCs for an alert. |

**Notifications**

| Tool | Endpoint | Description |
|------|----------|-------------|
| `DispatchNotificationsTool` | `POST /api/notifications/dispatch` | Fan out a completed investigation's report to the customer's configured destinations (SMTP, Shuffle → Slack/Outlook/Teams/etc.). CoPilot owns the routing, formatting, and idempotency — call once after `SubmitAiAnalystReportTool` succeeds. |

More tools (agents, healthcheck, threat intel, incidents, etc.) will be added incrementally.

## Installation

The fastest way to install is straight from GitHub into a fresh virtualenv:

```bash
python -m venv .venv && source .venv/bin/activate
pip install git+https://github.com/socfortress/copilot-mcp-server.git
```

This pulls the latest `main` and exposes the `copilot-mcp-server` command on your `PATH`.

To pin to a specific tag or commit:

```bash
pip install git+https://github.com/socfortress/copilot-mcp-server.git@v0.1.0
```

Or install a pre-built wheel from a [GitHub Release](https://github.com/socfortress/copilot-mcp-server/releases):

```bash
pip install https://github.com/socfortress/copilot-mcp-server/releases/download/latest/copilot_mcp_server-0.1.0-py3-none-any.whl
```

Or from a local checkout (for development):

```bash
git clone https://github.com/socfortress/copilot-mcp-server.git
cd copilot-mcp-server
pip install -e ".[dev]"
```

## Configuration

Copy `.env.example` to `.env` and fill in your CoPilot connection details:

```bash
cp .env.example .env
```

Required environment variables:

| Variable | Description |
|----------|-------------|
| `COPILOT_URL` | Base URL of the CoPilot backend (e.g. `http://127.0.0.1:5000`) |
| `COPILOT_USERNAME` | Service account username |
| `COPILOT_PASSWORD` | Service account password |

Optional:

| Variable | Default | Description |
|----------|---------|-------------|
| `COPILOT_SSL_VERIFY` | `true` | Verify TLS certificates |
| `COPILOT_TIMEOUT` | `30` | Request timeout in seconds |
| `LOG_LEVEL` | `INFO` | Logging level (logs go to stderr; stdout is reserved for MCP JSON-RPC) |
| `COPILOT_DISABLED_TOOLS` | _(empty)_ | Comma-separated list of tool names to disable |

> **2FA is not supported.** If the configured account has 2FA enabled, the server will raise
> a clear error on first authentication. Use a service account without 2FA.

## Running

This server uses **stdio transport** — it does not bind a network port. Instead, an MCP host
(Claude Desktop, LangChain, a container orchestrator, etc.) launches it as a subprocess and
communicates over its stdin/stdout.

You can still run it manually for smoke-testing:

```bash
copilot-mcp-server          # reads JSON-RPC from stdin, writes responses to stdout
python -m copilot_mcp_server
```

Logs are emitted on **stderr** so they don't corrupt the JSON-RPC stream on stdout.

### Example: Claude Desktop config

```json
{
  "mcpServers": {
    "copilot": {
      "command": "copilot-mcp-server",
      "env": {
        "COPILOT_URL": "http://127.0.0.1:5000",
        "COPILOT_USERNAME": "your-username",
        "COPILOT_PASSWORD": "your-password"
      }
    }
  }
}
```

### Example: LangChain integration

See [`copilot_integration.py`](copilot_integration.py) for a working example that uses
`langchain-mcp-adapters` to spawn this server over stdio and wrap its tools in a LangChain
agent.

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

Apache 2.0 — see [LICENSE](LICENSE).
