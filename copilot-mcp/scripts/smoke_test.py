#!/usr/bin/env python3
"""Validate the hunt tools against a live CoPilot instance.

The mocked tests prove the tools build the right requests; they cannot prove
that `hunt._FIELD_CANDIDATES` matches the field names real events actually use.
This runs one real search and reports which mapped fields resolved, plus any
observed field that looks like a better candidate.

Values are REDACTED by default — the investigation workflow deliberately keeps
hostnames, usernames, and internal IPs out of cloud context (see the
"Privacy-Aware SIEM Queries" section of groups/copilot/CLAUDE.md), and field
names alone are enough to fix the mapping. Pass --show-values only if you
intend the sample data to be visible.

Usage:
    set -a; source copilot-mcp/.env; set +a
    copilot-mcp/.venv/bin/python copilot-mcp/scripts/smoke_test.py [--query powershell]

Read-only: authenticates, lists customers/sources, runs one search.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import Any, List

from copilot_mcp_server.client import CoPilotClient
from copilot_mcp_server.config import CoPilotConfig
from copilot_mcp_server.hunt import _FIELD_CANDIDATES, extract_hits, normalize_hit, timeframe_params

REDACTED = "<redacted>"


def _preview(value: Any, show: bool) -> str:
    if value is None:
        return "None"
    if show:
        text = str(value)
        return text if len(text) <= 60 else text[:57] + "..."
    return f"{REDACTED} ({type(value).__name__})"


def _names(rows: Any, *keys: str) -> List[str]:
    """Pull a list of names out of a CoPilot list response."""
    if isinstance(rows, dict):
        for key in ("customers", "event_sources", "results", "data"):
            if isinstance(rows.get(key), list):
                rows = rows[key]
                break
    if not isinstance(rows, list):
        return []
    out = []
    for row in rows:
        if isinstance(row, str):
            out.append(row)
        elif isinstance(row, dict):
            for k in keys:
                if row.get(k):
                    out.append(str(row[k]))
                    break
    return out


async def run(args: argparse.Namespace) -> int:
    config = CoPilotConfig.from_env()
    try:
        config.validate()
    except Exception as exc:
        print(f"ERROR: {exc}\nSource copilot-mcp/.env first.", file=sys.stderr)
        return 1

    client = CoPilotClient(config)
    try:
        print(f"1. Authenticating to {config.url} ...")
        await client.authenticate()
        print("   OK — token acquired\n")

        print("2. GetCustomersTool ...")
        customers = _names(await client.get_customers(), "customer_code", "code")
        if not customers:
            print("   No customers returned — the service account may have no scope.")
            return 1
        print(f"   {len(customers)} customer(s); using {customers[0]!r}\n")
        customer = args.customer or customers[0]

        print(f"3. ListEventSourcesTool({customer!r}) ...")
        sources = _names(await client.list_event_sources(customer), "source_name", "name")
        if not sources:
            print("   No event sources — cannot search this customer.")
            return 1
        print(f"   sources: {sources}\n")
        source = args.source or sources[0]

        print("4. ListIndicesTool ...")
        indices = await client.list_indices()
        count = len(indices) if isinstance(indices, list) else len(_names(indices, "index"))
        print(f"   {count} index/indices reported\n")

        print(f"5. SearchEventsTool(query={args.query!r}, source={source!r}, {args.timeframe}) ...")
        payload = await client.search_events(
            customer_code=customer,
            source_name=source,
            query=args.query,
            page_size=args.limit,
            timeframe=timeframe_params(args.timeframe),
        )
        if isinstance(payload, dict):
            print(f"   envelope keys: {sorted(payload)}")
        hits = extract_hits(payload)
        print(f"   {len(hits)} hit(s) extracted\n")

        if not hits:
            print("No hits — try a broader --query or --timeframe to validate the mapping.")
            return 0

        raw = hits[0].get("_source") if isinstance(hits[0].get("_source"), dict) else hits[0]
        shaped = normalize_hit(hits[0], args.query)

        print("6. Field mapping on the first hit:")
        missing = []
        for field in list(_FIELD_CANDIDATES) + ["index", "doc_id"]:
            value = shaped.get(field)
            status = "ok  " if value is not None else "NULL"
            if value is None:
                missing.append(field)
            print(f"   {status} {field:<18} {_preview(value, args.show_values)}")

        print(f"\n7. Observed fields on the raw event ({len(raw)} total):")
        for key in sorted(raw)[: args.max_fields]:
            print(f"   {key}")
        if len(raw) > args.max_fields:
            print(f"   ... {len(raw) - args.max_fields} more (raise --max-fields)")

        if missing:
            print(
                "\nUnmapped: " + ", ".join(missing) + "\n"
                "Add the matching field name(s) from the list above to "
                "_FIELD_CANDIDATES in copilot_mcp_server/hunt.py."
            )
        else:
            print("\nAll mapped fields resolved — _FIELD_CANDIDATES matches this source.")
        return 0
    finally:
        await client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Live smoke test for the CoPilot hunt tools")
    parser.add_argument("--query", default="a", help="Search text (default: 'a', matches broadly)")
    parser.add_argument(
        "--timeframe", default="last_24h", help="last_24h | last_7d | 2w | ISO range"
    )
    parser.add_argument("--customer", default=None, help="Customer code (default: first returned)")
    parser.add_argument("--source", default=None, help="Event source (default: first returned)")
    parser.add_argument("--limit", type=int, default=5, help="Hits to request (default: 5)")
    parser.add_argument("--max-fields", type=int, default=40, help="Field names to print")
    parser.add_argument(
        "--show-values",
        action="store_true",
        help="Print sample values instead of redacting them (may expose PII)",
    )
    return asyncio.run(run(parser.parse_args()))


if __name__ == "__main__":
    sys.exit(main())
