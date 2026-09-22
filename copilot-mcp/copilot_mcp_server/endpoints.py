"""CoPilot REST paths used by the Talon threat-hunting tools.

All paths below were verified against a live CoPilot instance on
2026-09-14. The instance runs with OpenAPI docs disabled
(`/api/openapi.json` 404s), so they were confirmed two ways:

1. Probing each route unauthenticated. This backend answers 401
   `{"success": false, "message": "Not authenticated"}` for a route that
   exists and 404 `{"detail": "Not Found"}` for one that does not, so the
   status code alone distinguishes them.
2. Reading the call sites out of the CoPilot web UI's own JavaScript bundle,
   which is what pinned the query-parameter names and the response envelope.

`scripts/verify_endpoints.py` re-runs check (1) on demand.

Note the search API is scoped per (customer, event source) — there is no
global free-text search endpoint. `SEARCH` therefore takes two path
parameters, and a broad hunt means fanning out over sources.
"""

from __future__ import annotations

#: Event search. `GET /api/siem/events/{customer_code}/{source_name}` with
#: query params: `query`, `page_size`, and EITHER `timerange` (e.g. "24h",
#: "7d", "2w") OR the absolute pair `time_from` / `time_to` (ISO-8601).
#: Responds `{"success": bool, "events": [...], "total": int, "scroll_id": str}`.
SEARCH = "/api/siem/events/{customer_code}/{source_name}"

#: Event sources searchable for one customer — these supply `source_name`
#: above. Responds `{"success": bool, "event_sources": [...]}`.
EVENT_SOURCES = "/api/siem/event_sources/{customer_code}"

#: Field mappings for one customer/source, useful for building a query.
FIELD_MAPPINGS = "/api/siem/events/{customer_code}/{source_name}/fields"

#: Single alert detail by the `incident_management_alert` primary key.
#: NOTE: distinct from `/api/ai_analyst/alert/{id}`, which returns the
#: AI-analysis bundle (job + report + IOCs) rather than the raw alert.
ALERT_DETAIL = "/api/incidents/db_operations/alert/{alert_id}"

#: Raw indexer index list. Global, no parameters — this is the Indices page's
#: data, NOT the set of searchable sources (use EVENT_SOURCES for that).
INDICES = "/api/wazuh_indexer/indices"

#: Agent record including last-seen timestamp and online/offline status.
AGENT_DETAIL = "/api/agents/{agent_id}"

#: Relative-timerange unit suffixes the search endpoint accepts.
TIMERANGE_UNITS = ("h", "d", "w")
