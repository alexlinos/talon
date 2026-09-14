#!/usr/bin/env python3
"""Re-check the endpoints in `endpoints.py` against a live CoPilot instance.

This instance runs with OpenAPI docs disabled, so there is no spec to diff
against. Instead this probes each route unauthenticated and reads the status
code: CoPilot answers 401 for a route that exists and 404 for one that does
not, which is enough to catch a path that has moved or been removed.

Usage:
    set -a; source copilot-mcp/.env; set +a
    copilot-mcp/.venv/bin/python copilot-mcp/scripts/verify_endpoints.py

Exits 0 if every endpoint still exists, 1 otherwise. Read-only and
unauthenticated: it sends no credentials and never touches event data.
"""

from __future__ import annotations

import asyncio
import sys
from typing import List, Tuple

import httpx

from copilot_mcp_server import endpoints
from copilot_mcp_server.config import CoPilotConfig

# (constant name, method, path with sample values substituted).
# The sample values only need to satisfy the route's type converters — the
# request is rejected at auth long before anything looks them up.
CHECKS: Tuple[Tuple[str, str, str], ...] = (
    (
        "SEARCH",
        "GET",
        endpoints.SEARCH.format(customer_code="PROBE", source_name="probe"),
    ),
    ("EVENT_SOURCES", "GET", endpoints.EVENT_SOURCES.format(customer_code="PROBE")),
    (
        "FIELD_MAPPINGS",
        "GET",
        endpoints.FIELD_MAPPINGS.format(customer_code="PROBE", source_name="probe"),
    ),
    ("ALERT_DETAIL", "GET", endpoints.ALERT_DETAIL.format(alert_id=1)),
    ("INDICES", "GET", endpoints.INDICES),
    ("AGENT_DETAIL", "GET", endpoints.AGENT_DETAIL.format(agent_id="probe")),
)

#: A route that cannot exist, used to confirm the 401/404 split is meaningful
#: before trusting any of the results above.
CONTROL = "/api/this_route_does_not_exist_probe"


async def main() -> int:
    config = CoPilotConfig.from_env()
    if not config.url:
        print("ERROR: COPILOT_URL is not set. Source copilot-mcp/.env first.", file=sys.stderr)
        return 1

    async with httpx.AsyncClient(verify=config.ssl_verify, timeout=config.timeout) as client:
        try:
            control = await client.get(f"{config.url}{CONTROL}")
        except httpx.HTTPError as exc:
            print(f"ERROR: cannot reach {config.url}: {exc}", file=sys.stderr)
            return 1

        if control.status_code != 404:
            print(
                f"ERROR: control probe returned {control.status_code}, expected 404. "
                "Something in front of the API (a proxy or SPA catch-all) is answering "
                "for unknown paths, so existence cannot be inferred from status codes.",
                file=sys.stderr,
            )
            return 1

        print(f"Probing {config.url} (control 404 confirmed)\n")

        failures: List[str] = []
        for name, method, path in CHECKS:
            try:
                response = await client.request(method, f"{config.url}{path}")
            except httpx.HTTPError as exc:
                print(f"  ERROR    {name:<15} {exc}")
                failures.append(name)
                continue

            code = response.status_code
            if code in (401, 403):
                print(f"  OK       {name:<15} {method:<4} {getattr(endpoints, name)}")
            elif code == 405:
                print(f"  METHOD   {name:<15} exists but not as {method} — {path}")
                failures.append(name)
            elif code == 404:
                print(f"  MISSING  {name:<15} {method:<4} {path}")
                failures.append(name)
            else:
                print(f"  ?{code:<7} {name:<15} unexpected status — {path}")
                failures.append(name)

    print()
    if failures:
        print(
            "Needs attention: " + ", ".join(failures) + "\n"
            "Fix in copilot_mcp_server/endpoints.py — the only place these are defined."
        )
        return 1
    print("All endpoints confirmed present.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
