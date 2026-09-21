"""Helpers for the Talon threat-hunting tools: timeframe parsing and hit shaping.

Kept out of `client.py` and `server.py` so the pure logic is unit-testable
without standing up a server or an HTTP transport.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from copilot_mcp_server.exceptions import CoPilotMCPError

#: Shorthand windows, mapped to the `timerange` value the search API accepts.
RELATIVE_WINDOWS = {
    "last_24h": "24h",
    "last_7d": "7d",
}

#: A bare relative timerange the API takes directly, e.g. "24h", "7d", "2w".
_RELATIVE = re.compile(r"^(\d+)([hdw])$", re.IGNORECASE)

#: An ISO range: two ISO-8601 timestamps separated by "/" or "..".
_RANGE_SPLIT = re.compile(r"\s*(?:/|\.\.)\s*")


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 timestamp, tolerating a trailing 'Z'."""
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise CoPilotMCPError(
            f"Invalid ISO-8601 timestamp {value!r}: {exc}. Expected e.g. 2026-09-01T00:00:00Z."
        ) from exc
    # Treat a naive timestamp as UTC rather than silently adopting local time.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def timeframe_params(timeframe: str) -> Dict[str, str]:
    """Translate a timeframe into the search endpoint's query parameters.

    The API takes either a relative `timerange` ("24h", "7d", "2w") or the
    absolute pair `time_from`/`time_to`, never both. Accepts the shorthands in
    :data:`RELATIVE_WINDOWS`, a bare relative window, or an ISO-8601 range such
    as ``2026-09-01T00:00:00Z/2026-09-02T00:00:00Z``.
    """
    key = timeframe.strip()

    window = RELATIVE_WINDOWS.get(key.lower())
    if window is not None:
        return {"timerange": window}

    if _RELATIVE.match(key):
        return {"timerange": key.lower()}

    parts = _RANGE_SPLIT.split(key)
    if len(parts) == 2 and all(parts):
        start, end = _parse_iso(parts[0]), _parse_iso(parts[1])
        if start > end:
            raise CoPilotMCPError(
                f"Invalid timeframe {timeframe!r}: start {start.isoformat()} "
                f"is after end {end.isoformat()}."
            )
        # The UI sends these as full ISO-8601 with a 'Z', so match that.
        return {
            "time_from": start.isoformat().replace("+00:00", "Z"),
            "time_to": end.isoformat().replace("+00:00", "Z"),
        }

    raise CoPilotMCPError(
        f"Unrecognized timeframe {timeframe!r}. Use one of {sorted(RELATIVE_WINDOWS)}, "
        "a relative window like '24h'/'7d'/'2w', or an ISO range like "
        "'2026-09-01T00:00:00Z/2026-09-02T00:00:00Z'."
    )


# --------------------------------------------------------------------------- #
# Hit normalization
# --------------------------------------------------------------------------- #
# Graylog flattens nested fields with underscores in this environment, so the
# raw documents use `agent_name` / `rule_id`, never dot notation. Each tuple is
# tried in order and the first present, non-empty value wins.
_FIELD_CANDIDATES: Dict[str, Tuple[str, ...]] = {
    "timestamp": ("timestamp", "@timestamp", "alert_timestamp", "event_timestamp"),
    "host": ("agent_name", "agent_labels_host", "host_name", "hostname", "manager_name"),
    "agent_id": ("agent_id", "agent_ip"),
    # Order matters: `_first_present` takes the first hit. Frequencies below are
    # from a 700-event sample of this estate's Wazuh source (see scripts/smoke_test.py).
    # Sysmon's `user` wins most often; `targetUserName` is the account that logged
    # on in Windows 4624/4625, `subjectUserName` the account that requested it.
    # Roughly a third of events (syslog, network) carry no user at all — None is
    # the correct answer there, not a mapping gap.
    "user": (
        "data_win_eventdata_user",  # 296
        "data_win_eventdata_targetUserName",  # 143
        "data_win_eventdata_subjectUserName",  # 16
        "data_dstuser",  # 4
        "data_srcuser",  # 2
        "user",  # generic fallback for other estates/sources
    ),
    "rule_id": ("rule_id", "rule_sid", "sid"),
    "rule_description": ("rule_description", "rule_name", "description"),
}

#: Keys that carry transport metadata rather than event content.
_META_KEYS = frozenset({"_index", "_id", "_score", "_type", "_source", "index", "index_name"})


def _first_present(source: Dict[str, Any], keys: Tuple[str, ...]) -> Optional[Any]:
    for key in keys:
        value = source.get(key)
        if value not in (None, "", []):
            return value
    return None


def _matched_fields(source: Dict[str, Any], query: str, limit: int = 12) -> List[str]:
    """Field names whose value contains the query text (case-insensitive).

    Best-effort: CoPilot does not return highlight metadata, so this is
    computed locally to show *why* a document matched.
    """
    needle = query.strip().strip('"').lower()
    if not needle or len(needle) < 2:
        return []
    hits: List[str] = []
    for key, value in source.items():
        if key in _META_KEYS or isinstance(value, (dict, list)):
            continue
        if needle in str(value).lower():
            hits.append(key)
            if len(hits) >= limit:
                break
    return sorted(hits)


def normalize_hit(raw: Dict[str, Any], query: str = "") -> Dict[str, Any]:
    """Flatten one search hit into the fields a hunt actually reads.

    Tolerates both OpenSearch-shaped hits (`{"_source": {...}, "_index": ...}`)
    and already-flattened CoPilot rows. `raw_fields` preserves the untouched
    document so nothing is lost when a field name is unexpected.
    """
    source = raw.get("_source") if isinstance(raw.get("_source"), dict) else raw
    source = source or {}

    shaped: Dict[str, Any] = {
        field: _first_present(source, candidates) for field, candidates in _FIELD_CANDIDATES.items()
    }
    shaped["index"] = raw.get("_index") or source.get("index_name") or raw.get("index")
    shaped["doc_id"] = raw.get("_id") or source.get("id")
    shaped["matched_fields"] = _matched_fields(source, query)
    shaped["raw_fields"] = source
    return shaped


def extract_hits(payload: Any) -> List[Dict[str, Any]]:
    """Pull the hit list out of whichever envelope CoPilot returned.

    Handles the OpenSearch `{"hits": {"hits": [...]}}` envelope, a flat
    `{"hits": [...]}`, common CoPilot wrappers, and a bare list.
    """
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []

    hits = payload.get("hits")
    if isinstance(hits, dict):
        inner = hits.get("hits")
        if isinstance(inner, list):
            return [item for item in inner if isinstance(item, dict)]
    if isinstance(hits, list):
        return [item for item in hits if isinstance(item, dict)]

    for key in ("events", "results", "alerts", "documents", "data"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return []
