# CoPilot MCP (Talon fork)

MCP server wrapping the SOCFortress CoPilot API, used by the `copilot` agent
group for alert investigation and threat hunting.

## Fork status

This is a **Talon fork** of
[`socfortress/copilot-mcp-server`](https://github.com/socfortress/copilot-mcp-server),
vendored into the tree rather than pip-installed from GitHub. Upstream's 14
AI-analyst write-back tools are unchanged; the fork adds five read/search tools
for threat hunting.

All changes to upstream files are **additive** — no upstream line was modified
or removed — so rebasing onto a newer upstream stays mechanical. The divergence
is contained in:

| File | Status |
|------|--------|
| `copilot_mcp_server/endpoints.py` | New — REST paths for the hunt tools |
| `copilot_mcp_server/hunt.py` | New — timeframe translation, hit normalization |
| `copilot_mcp_server/client.py` | Five methods appended + one import |
| `copilot_mcp_server/server.py` | Arg models + `_register_hunt_tools` appended |
| `tests/test_hunt_tools.py` | New — 18 tests |
| `scripts/verify_endpoints.py` | New — re-checks the paths against a live instance |
| `README.upstream.md` | Upstream's README, kept verbatim for reference |

## How search actually works

Worth knowing before using these tools, because it constrains the shape of a hunt:

- **Search is scoped per customer and per event source.** There is no global
  free-text endpoint. `GET /api/siem/events/{customer_code}/{source_name}`
  is the only search route, so `customer_code` is required and a broad hunt
  means fanning out over the customer's sources.
- **Two kinds of index list, and they are not interchangeable.**
  `ListEventSourcesTool` returns what search can target; `ListIndicesTool`
  returns the indexer's raw index inventory (health, doc counts). Pass a
  source name to search, not an index name.
- **Timeframes are relative or absolute, never both.** The API takes either
  `timerange` (`24h`, `7d`, `2w`) or the pair `time_from`/`time_to`.

These were confirmed against the live instance — see [Verifying](#verifying-the-endpoints).

## Tools added by this fork

Tool arguments are nested under an `args` key, matching upstream's convention
(each tool takes a single Pydantic model parameter named `args`). No-argument
tools use `_args`, as upstream's `GetCustomersTool` does.

### `SearchEventsTool`

```jsonc
{ "args": {
    "customer_code": "ACME",          // REQUIRED — search is per-customer
    "query":         "powershell -enc",
    "timeframe":     "last_24h",      // last_24h | last_7d | 24h/7d/2w | ISO range
    "source_name":   "wazuh",         // optional; omit to fan out over all sources
    "limit":         100              // optional, 1-1000 per source, default 100
}}
```

`timeframe` accepts `last_24h` / `last_7d`, a bare relative window (`24h`,
`7d`, `2w`), or an ISO-8601 range separated by `/` or `..`, e.g.
`2026-09-01T00:00:00Z/2026-09-02T00:00:00Z`. A naive timestamp is read as UTC.
Relative windows go out as `timerange`; a range goes out as `time_from`/`time_to`.

Omitting `source_name` looks up the customer's sources and issues one request
per source. If some fail, the successful hits are still returned and the
failures appear under `source_errors` — one dead index does not sink the hunt.

```jsonc
{
  "query": "powershell -enc",
  "customer_code": "ACME",
  "timeframe": { "requested": "last_24h", "params": { "timerange": "24h" } },
  "sources_searched": ["wazuh", "office365"],
  "hit_count": 1,
  "hits": [{
    "timestamp": "2026-09-12T10:00:00Z",
    "index": "wazuh-alerts-4.x-2026.09.12",
    "source_name": "wazuh",
    "host": "WIN-DC01",
    "agent_id": "004",
    "user": "svc_backup",
    "rule_id": "92052",
    "rule_description": "Powershell encoded command executed",
    "matched_fields": ["data_win_eventdata_commandLine"],
    "raw_fields": { }
  }],
  "source_errors": { }
}
```

`matched_fields` is computed locally (CoPilot returns no highlight metadata) and
lists the fields whose value contained the query text. `raw_fields` always holds
the untouched document, so nothing is lost when a field name is unexpected.

### `ListEventSourcesTool`

```jsonc
{ "args": { "customer_code": "ACME" } }
```

The event sources searchable for one customer. These supply `source_name` above.

### `GetAlertTool`

```jsonc
{ "args": { "alert_id": 4321 } }
```

Full detail for one alert. For the AI analyst's job, report, and IOCs for that
alert, use upstream's `GetAlertAiAnalysisTool` instead.

### `ListIndicesTool`

```jsonc
{ "_args": {} }
```

The indexer's raw index inventory with health and doc counts — infrastructure
visibility, not a search target list.

### `GetAgentTool`

```jsonc
{ "args": { "agent_id": "004" } }
```

One agent's record including last-seen timestamp and online/offline status —
the basis of the daily agent-gap hunt.

## Environment variables

Credentials follow the same convention as every other MCP wrapper in this tree.
Copy `.env.example` to `.env` and fill it in:

| Variable | Required | Default | Purpose |
|----------|----------|---------|---------|
| `COPILOT_URL` | yes | — | CoPilot base URL, e.g. `https://copilot.example.com` |
| `COPILOT_USERNAME` | yes | — | Service account username |
| `COPILOT_PASSWORD` | yes | — | Service account password |
| `COPILOT_SSL_VERIFY` | no | `true` | Set `false` for self-signed certs |
| `COPILOT_TIMEOUT` | no | `30` | Request timeout, seconds |
| `COPILOT_DISABLED_TOOLS` | no | — | Comma-separated tool names to withhold |
| `LOG_LEVEL` | no | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR`/`CRITICAL` |

Auth is OAuth2 password-grant against `POST /api/auth/token`; the client caches
the JWT and refreshes it on expiry or on a 401. **2FA is not supported** — use a
service account without it.

> The service account's own permissions bound every tool. A hunt can only see
> the customers and sources that account can see.

### How credentials reach the server

Two paths, both handled by `copilot-mcp.sh`:

- **In the agent container** — `/etc/mcp-secrets/copilot.env` is owned by the
  `mcp-copilot` uid and mode 600. The wrapper `sudo`s to that uid and sources it,
  so the agent (running as `node`) can never read the credentials. The
  `COPILOT_*` variables are **not** in the agent's own environment.
- **On the host** — the wrapper falls back to sourcing `copilot-mcp/.env`.

## Setup

```bash
./copilot-mcp/setup.sh
```

Creates `.venv/` (Python 3.10–3.13), installs the vendored source in editable
mode, and seeds `.env` from `.env.example`. Add `--dev` to also install pytest
and the linters.

## Running it standalone

The server speaks JSON-RPC over stdio; it has no HTTP port and prints nothing
useful when run bare. To drive it by hand:

```bash
set -a; source copilot-mcp/.env; set +a
copilot-mcp/.venv/bin/copilot-mcp-server --log-level DEBUG
```

Equivalently, `copilot-mcp/.venv/bin/python -m copilot_mcp_server`. Credentials
can also be passed as flags (`--copilot-url`, `--copilot-username`,
`--copilot-password`), which is handy for testing against a second instance
without editing `.env`.

To list the registered tools without a client:

```bash
copilot-mcp/.venv/bin/python -c "
import asyncio
from copilot_mcp_server.config import Config, CoPilotConfig, ServerConfig
from copilot_mcp_server.server import CoPilotMCPServer
cfg = Config(copilot=CoPilotConfig(url='http://x', username='u', password='p'), server=ServerConfig())
print(sorted(t.name for t in asyncio.run(CoPilotMCPServer(cfg).app.list_tools())))"
```

## Verifying the endpoints

The paths in `endpoints.py` were verified against the live instance. That
instance runs with OpenAPI docs disabled (`/api/openapi.json` 404s), so there is
no spec to diff against — instead the API answers **401** for a route that
exists and **404** for one that does not, which is enough to detect a path that
has moved. To re-check after a CoPilot upgrade:

```bash
set -a; source copilot-mcp/.env; set +a
copilot-mcp/.venv/bin/python copilot-mcp/scripts/verify_endpoints.py
```

```
  OK       SEARCH          GET  /api/siem/events/{customer_code}/{source_name}
  OK       EVENT_SOURCES   GET  /api/siem/event_sources/{customer_code}
  ...
All endpoints confirmed present.
```

It sends no credentials and touches no event data. It first probes a route that
cannot exist and aborts if that does not 404 — otherwise a proxy or SPA
catch-all answering for unknown paths would make every result meaningless.

Existence is all this proves. Query-parameter names and the response envelope
were read from the CoPilot web UI's own JavaScript bundle; if a future upgrade
changes those, this check still passes while calls return unexpected shapes. A
live smoke test is the backstop:

```bash
set -a; source copilot-mcp/.env; set +a
copilot-mcp/.venv/bin/python -c "
import asyncio, json
from copilot_mcp_server.client import CoPilotClient
from copilot_mcp_server.config import CoPilotConfig
async def main():
    c = CoPilotClient(CoPilotConfig.from_env())
    print(json.dumps(await c.list_indices(), indent=2, default=str)[:2000]); await c.close()
asyncio.run(main())"
```

`list_indices` is the cheapest probe — no arguments and a small response. If it
returns data, auth and base URL are good.

## Adding it to an MCP config

For Claude Code (`.mcp.json`) or a scheduled task, on the host:

```json
{
  "mcpServers": {
    "copilot": {
      "command": "/absolute/path/to/talon/copilot-mcp/copilot-mcp.sh"
    }
  }
}
```

Inside the agent container the path is the mount point, which is what
`groups/copilot/.mcp.json` already uses:

```json
{
  "mcpServers": {
    "copilot": {
      "command": "/workspace/extra/copilot-mcp/copilot-mcp.sh"
    }
  }
}
```

The wrapper sources credentials itself, so no `env` block is needed — and adding
one would put secrets in a file the agent can read. To withhold specific tools
from a given group, set `COPILOT_DISABLED_TOOLS` in that group's `.env`:

```bash
COPILOT_DISABLED_TOOLS=SubmitAiAnalystReportTool,DispatchNotificationsTool
```

Tools are namespaced by the server key, so `"copilot"` above makes them
`mcp__copilot__SearchEventsTool` and so on.

## Tests

```bash
copilot-mcp/.venv/bin/python -m pytest copilot-mcp/tests/ -q
```

20 tests, no network: each hunt tool is driven through `app.call_tool` against an
`httpx.MockTransport`, covering argument validation, the request actually built
(including relative vs absolute timeframe parameters), source fan-out, partial
source failure, response shaping, and error propagation.
`tests/test_run_tool_errors.py` is upstream's, unmodified.

## Rebuilding the container

The image installs this package from source staged by `container/build.sh` into
`container/vendor/` (the build context is `container/`, so the repo-root package
is not otherwise reachable by `COPY`). After changing anything here:

```bash
./container/build.sh
```

> Buildkit caches the build context aggressively and `--no-cache` alone does not
> invalidate `COPY`. If a source change doesn't appear in the image, prune the
> builder first — see the root `CLAUDE.md`.
