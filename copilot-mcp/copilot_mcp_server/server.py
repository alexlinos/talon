"""FastMCP server exposing CoPilot API endpoints as MCP tools."""

from __future__ import annotations

import json
import logging
from typing import Any, Awaitable, Dict, List, Literal, Optional

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import BaseModel, Field

from copilot_mcp_server.client import CoPilotClient
from copilot_mcp_server.config import Config
from copilot_mcp_server.exceptions import CoPilotMCPError
from copilot_mcp_server.hunt import extract_hits, normalize_hit, timeframe_params

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Enum-style literal types (mirrors CoPilot's ai_analyst Pydantic enums)
# --------------------------------------------------------------------------- #
JobStatus = Literal["pending", "running", "completed", "failed"]
TriggeredBy = Literal["scheduled", "manual", "webhook"]
SeverityAssessment = Literal["Critical", "High", "Medium", "Low", "Informational"]
IocType = Literal["ip", "domain", "hash", "process", "url", "user", "command"]
VtVerdict = Literal["malicious", "suspicious", "clean", "unknown"]


# --------------------------------------------------------------------------- #
# Tool argument models — Customers
# --------------------------------------------------------------------------- #
class GetCustomersArgs(BaseModel):
    """No arguments — returns all customers visible to the authenticated user."""


# --------------------------------------------------------------------------- #
# Tool argument models — AI Analyst: Jobs
# --------------------------------------------------------------------------- #
class CreateJobArgs(BaseModel):
    id: str = Field(
        ...,
        max_length=64,
        description="Unique job identifier, e.g. copilot-inv-1234-abc",
    )
    alert_id: int = Field(..., description="The alert ID from incident_management_alert")
    customer_code: str = Field(..., max_length=64, description="Customer code")
    triggered_by: TriggeredBy = Field(..., description="How the investigation was triggered")
    alert_type: Optional[str] = Field(
        None, max_length=64, description="Detected alert type, e.g. sysmon_event_1"
    )
    template_used: Optional[str] = Field(
        None, max_length=128, description="Template file used for investigation"
    )


class UpdateJobArgs(BaseModel):
    job_id: str = Field(..., description="The job ID to update")
    status: JobStatus = Field(..., description="New job status")
    alert_type: Optional[str] = Field(None, max_length=64)
    template_used: Optional[str] = Field(None, max_length=128)
    error_message: Optional[str] = Field(None, description="Error message if status is failed")


class GetJobArgs(BaseModel):
    job_id: str = Field(..., description="The job ID to retrieve")


class ListJobsByAlertArgs(BaseModel):
    alert_id: int = Field(..., description="The alert ID")


class ListJobsByCustomerArgs(BaseModel):
    customer_code: str = Field(..., description="The customer code")


# --------------------------------------------------------------------------- #
# Tool argument models — AI Analyst: Reports
# --------------------------------------------------------------------------- #
class SubmitReportArgs(BaseModel):
    job_id: str = Field(..., max_length=64, description="The job ID this report belongs to")
    alert_id: int = Field(..., description="The alert ID")
    customer_code: str = Field(..., max_length=64, description="Customer code")
    severity_assessment: Optional[SeverityAssessment] = Field(
        None, description="Severity assessment of the alert"
    )
    summary: Optional[str] = Field(None, description="Short summary of findings")
    report_markdown: Optional[str] = Field(
        None, description="Full investigation report in Markdown"
    )
    recommended_actions: Optional[str] = Field(None, description="Recommended response actions")


class ListReportsByAlertArgs(BaseModel):
    alert_id: int = Field(..., description="The alert ID")


# --------------------------------------------------------------------------- #
# Tool argument models — AI Analyst: IOCs
# --------------------------------------------------------------------------- #
class IocItem(BaseModel):
    ioc_value: str = Field(..., max_length=512, description="The IOC value")
    ioc_type: IocType = Field(..., description="Type of IOC")
    vt_verdict: VtVerdict = Field(default="unknown", description="VirusTotal verdict")
    vt_score: Optional[str] = Field(None, max_length=32, description="VirusTotal score, e.g. 5/70")
    details: Optional[str] = Field(None, description="Additional enrichment details")


class SubmitIocsArgs(BaseModel):
    report_id: int = Field(..., description="The report ID these IOCs belong to")
    alert_id: int = Field(..., description="The alert ID")
    customer_code: str = Field(..., max_length=64, description="Customer code")
    iocs: List[IocItem] = Field(..., description="List of IOCs to submit")


class ListIocsByReportArgs(BaseModel):
    report_id: int = Field(..., description="The report ID")


class ListIocsByAlertArgs(BaseModel):
    alert_id: int = Field(..., description="The alert ID")


class ListIocsByCustomerArgs(BaseModel):
    customer_code: str = Field(..., description="The customer code")
    vt_verdict: Optional[VtVerdict] = Field(None, description="Optional VirusTotal verdict filter")


# --------------------------------------------------------------------------- #
# Tool argument models — AI Analyst: Combined
# --------------------------------------------------------------------------- #
class GetAlertAnalysisArgs(BaseModel):
    alert_id: int = Field(..., description="The alert ID")


# --------------------------------------------------------------------------- #
# Tool argument models — Notifications dispatch
# --------------------------------------------------------------------------- #
NotificationTrigger = Literal["investigation_complete", "severity_critical_or_high"]


class DispatchNotificationsArgs(BaseModel):
    """Arguments for `DispatchNotificationsTool` — what Talon sends to
    CoPilot's notification engine after writing back an investigation
    report. Mirrors `app/notifications/schema/notifications.py:DispatchRequest`
    on the CoPilot side."""

    customer_code: str = Field(
        ...,
        max_length=64,
        description="The alert's customer_code — scopes the route lookup.",
    )
    alert_id: int = Field(
        ..., description="The alert this investigation was for. Used as the idempotency key."
    )
    trigger: NotificationTrigger = Field(
        ...,
        description=(
            "Pick exactly one trigger per dispatch. Use "
            "'severity_critical_or_high' when severity_assessment is Critical "
            "or High; otherwise use 'investigation_complete'. Never call this "
            "tool twice for the same alert."
        ),
    )
    severity_assessment: SeverityAssessment = Field(
        ...,
        description="The report's assessed severity — used for route min_severity filtering.",
    )
    summary: str = Field(
        ...,
        description="One-paragraph human-readable summary. Renders into the default message template.",
    )
    report_url: Optional[str] = Field(
        None, description="Optional deep link back to the full report in CoPilot."
    )
    alert_name: Optional[str] = Field(
        None, description="Original alert title for context in the message body."
    )


# --------------------------------------------------------------------------- #
# Tool argument models — Threat hunting (Talon fork)
# --------------------------------------------------------------------------- #
class SearchEventsArgs(BaseModel):
    customer_code: str = Field(
        ...,
        max_length=64,
        description=(
            "Customer whose events to search. Required — CoPilot's search API is "
            "scoped per customer, there is no cross-customer search."
        ),
    )
    query: str = Field(
        ...,
        min_length=1,
        description="Free-text search terms, e.g. 'powershell -enc' or a hostname.",
    )
    timeframe: str = Field(
        default="last_24h",
        description=(
            "'last_24h' or 'last_7d', a bare relative window ('24h', '7d', '2w'), "
            "or an explicit ISO-8601 range such as "
            "'2026-09-01T00:00:00Z/2026-09-02T00:00:00Z'."
        ),
    )
    source_name: Optional[str] = Field(
        None,
        description=(
            "Restrict to one event source. Omit to search every source this "
            "customer has — that fans out to one request per source. Use "
            "ListEventSourcesTool to see them."
        ),
    )
    limit: int = Field(
        default=100,
        ge=1,
        le=1000,
        description="Maximum hits per source (1-1000). Defaults to 100.",
    )


class ListEventSourcesArgs(BaseModel):
    customer_code: str = Field(..., max_length=64, description="The customer code")


class GetAlertArgs(BaseModel):
    alert_id: int = Field(..., description="The alert ID from incident_management_alert")


class ListIndicesArgs(BaseModel):
    """No arguments — returns every index the indexer reports."""


class GetAgentArgs(BaseModel):
    agent_id: str = Field(
        ..., max_length=128, description="The agent ID, e.g. the Wazuh agent identifier"
    )


# --------------------------------------------------------------------------- #
# Server
# --------------------------------------------------------------------------- #
class CoPilotMCPServer:
    """MCP server that exposes the SOCFortress CoPilot API as tools."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self._client: Optional[CoPilotClient] = None
        self.app = FastMCP(name="CoPilot MCP Server", version="0.1.0")
        self._register_tools()

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _get_client(self) -> CoPilotClient:
        if self._client is None:
            self._client = CoPilotClient(self.config.copilot)
        return self._client

    @staticmethod
    def _safe_truncate(text: str, max_length: int = 32000) -> str:
        if len(text) <= max_length:
            return text
        return text[:max_length] + f"\n\n[... truncated {len(text) - max_length} characters ...]"

    def _is_enabled(self, name: str) -> bool:
        return name not in self.config.server.disabled_tools

    async def _run_tool(
        self,
        name: str,
        coro: Awaitable[Any],
    ) -> List[Dict[str, Any]]:
        """Execute an API coroutine and wrap its result as an MCP text response.

        On failure, raise ToolError so FastMCP marks the result isError=true and
        the backend's message (e.g. a 422 validation detail) reaches the agent
        as a real tool failure it can retry on. Returning the error as a normal
        text block instead would look like success and the agent could move on.
        """
        try:
            data = await coro
            return [
                {
                    "type": "text",
                    "text": self._safe_truncate(json.dumps(data, indent=2, default=str)),
                }
            ]
        except Exception as exc:  # noqa: BLE001
            logger.error("%s error: %s", name, exc)
            raise ToolError(f"{name} failed: {exc}") from exc

    # ------------------------------------------------------------------ #
    # Tool registration
    # ------------------------------------------------------------------ #
    def _register_tools(self) -> None:
        self._register_customer_tools()
        self._register_ai_analyst_job_tools()
        self._register_ai_analyst_report_tools()
        self._register_ai_analyst_ioc_tools()
        self._register_ai_analyst_combined_tools()
        self._register_notification_tools()
        self._register_hunt_tools()

    # -- Customers ----------------------------------------------------- #
    def _register_customer_tools(self) -> None:
        if self._is_enabled("GetCustomersTool"):

            @self.app.tool(
                name="GetCustomersTool",
                description=(
                    "Fetch the list of customers from SOCFortress CoPilot. "
                    "Returns customer codes, names, contact details, and provisioning status."
                ),
            )
            async def get_customers_tool(_args: GetCustomersArgs) -> List[Dict[str, Any]]:
                return await self._run_tool("GetCustomersTool", self._get_client().get_customers())

    # -- AI Analyst: Jobs ---------------------------------------------- #
    def _register_ai_analyst_job_tools(self) -> None:
        if self._is_enabled("CreateAiAnalystJobTool"):

            @self.app.tool(
                name="CreateAiAnalystJobTool",
                description=(
                    "Register a new AI analyst investigation job in CoPilot. "
                    "Call this before submitting a report or IOCs for an alert."
                ),
            )
            async def create_ai_analyst_job_tool(args: CreateJobArgs) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "CreateAiAnalystJobTool",
                    self._get_client().create_ai_analyst_job(args.model_dump(exclude_none=True)),
                )

        if self._is_enabled("UpdateAiAnalystJobTool"):

            @self.app.tool(
                name="UpdateAiAnalystJobTool",
                description=(
                    "Update the status of an existing AI analyst job "
                    "(e.g. move from 'running' to 'completed' or 'failed')."
                ),
            )
            async def update_ai_analyst_job_tool(args: UpdateJobArgs) -> List[Dict[str, Any]]:
                body = args.model_dump(exclude_none=True, exclude={"job_id"})
                return await self._run_tool(
                    "UpdateAiAnalystJobTool",
                    self._get_client().update_ai_analyst_job(args.job_id, body),
                )

        if self._is_enabled("GetAiAnalystJobTool"):

            @self.app.tool(
                name="GetAiAnalystJobTool",
                description="Fetch a single AI analyst job by its job ID.",
            )
            async def get_ai_analyst_job_tool(args: GetJobArgs) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "GetAiAnalystJobTool",
                    self._get_client().get_ai_analyst_job(args.job_id),
                )

        if self._is_enabled("ListAiAnalystJobsByAlertTool"):

            @self.app.tool(
                name="ListAiAnalystJobsByAlertTool",
                description="List all AI analyst investigation jobs associated with an alert.",
            )
            async def list_jobs_by_alert_tool(
                args: ListJobsByAlertArgs,
            ) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "ListAiAnalystJobsByAlertTool",
                    self._get_client().list_ai_analyst_jobs_by_alert(args.alert_id),
                )

        if self._is_enabled("ListAiAnalystJobsByCustomerTool"):

            @self.app.tool(
                name="ListAiAnalystJobsByCustomerTool",
                description="List all AI analyst investigation jobs for a customer.",
            )
            async def list_jobs_by_customer_tool(
                args: ListJobsByCustomerArgs,
            ) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "ListAiAnalystJobsByCustomerTool",
                    self._get_client().list_ai_analyst_jobs_by_customer(args.customer_code),
                )

    # -- AI Analyst: Reports ------------------------------------------- #
    def _register_ai_analyst_report_tools(self) -> None:
        if self._is_enabled("SubmitAiAnalystReportTool"):

            @self.app.tool(
                name="SubmitAiAnalystReportTool",
                description=(
                    "Submit the markdown investigation report, severity assessment, and "
                    "recommended actions produced by the AI analyst for a given job/alert."
                ),
            )
            async def submit_report_tool(args: SubmitReportArgs) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "SubmitAiAnalystReportTool",
                    self._get_client().submit_ai_analyst_report(args.model_dump(exclude_none=True)),
                )

        if self._is_enabled("ListAiAnalystReportsByAlertTool"):

            @self.app.tool(
                name="ListAiAnalystReportsByAlertTool",
                description="List all AI analyst reports associated with a given alert.",
            )
            async def list_reports_by_alert_tool(
                args: ListReportsByAlertArgs,
            ) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "ListAiAnalystReportsByAlertTool",
                    self._get_client().list_ai_analyst_reports_by_alert(args.alert_id),
                )

    # -- AI Analyst: IOCs ---------------------------------------------- #
    def _register_ai_analyst_ioc_tools(self) -> None:
        if self._is_enabled("SubmitAiAnalystIocsTool"):

            @self.app.tool(
                name="SubmitAiAnalystIocsTool",
                description=(
                    "Submit extracted IOCs (IPs, domains, hashes, processes, URLs, users, "
                    "commands) for a report, including VirusTotal verdicts and scores."
                ),
            )
            async def submit_iocs_tool(args: SubmitIocsArgs) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "SubmitAiAnalystIocsTool",
                    self._get_client().submit_ai_analyst_iocs(args.model_dump(exclude_none=True)),
                )

        if self._is_enabled("ListAiAnalystIocsByReportTool"):

            @self.app.tool(
                name="ListAiAnalystIocsByReportTool",
                description="List all IOCs recorded for a specific AI analyst report.",
            )
            async def list_iocs_by_report_tool(
                args: ListIocsByReportArgs,
            ) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "ListAiAnalystIocsByReportTool",
                    self._get_client().list_ai_analyst_iocs_by_report(args.report_id),
                )

        if self._is_enabled("ListAiAnalystIocsByAlertTool"):

            @self.app.tool(
                name="ListAiAnalystIocsByAlertTool",
                description="List all IOCs recorded for a given alert across its reports.",
            )
            async def list_iocs_by_alert_tool(
                args: ListIocsByAlertArgs,
            ) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "ListAiAnalystIocsByAlertTool",
                    self._get_client().list_ai_analyst_iocs_by_alert(args.alert_id),
                )

        if self._is_enabled("ListAiAnalystIocsByCustomerTool"):

            @self.app.tool(
                name="ListAiAnalystIocsByCustomerTool",
                description=(
                    "List IOCs for a customer, optionally filtered by VirusTotal verdict "
                    "(malicious, suspicious, clean, unknown)."
                ),
            )
            async def list_iocs_by_customer_tool(
                args: ListIocsByCustomerArgs,
            ) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "ListAiAnalystIocsByCustomerTool",
                    self._get_client().list_ai_analyst_iocs_by_customer(
                        args.customer_code, vt_verdict=args.vt_verdict
                    ),
                )

    # -- AI Analyst: Combined ------------------------------------------ #
    def _register_ai_analyst_combined_tools(self) -> None:
        if self._is_enabled("GetAlertAiAnalysisTool"):

            @self.app.tool(
                name="GetAlertAiAnalysisTool",
                description=(
                    "Fetch the complete AI analysis bundle for an alert: the investigation "
                    "job, the latest report (summary, severity, recommended actions, full "
                    "markdown), and all extracted IOCs. This is the one-shot tool for "
                    "getting everything the AI analyst produced for an alert."
                ),
            )
            async def get_alert_analysis_tool(
                args: GetAlertAnalysisArgs,
            ) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "GetAlertAiAnalysisTool",
                    self._get_client().get_ai_analyst_alert_analysis(args.alert_id),
                )

    # -- Notifications dispatch ---------------------------------------- #
    def _register_notification_tools(self) -> None:
        if self._is_enabled("DispatchNotificationsTool"):

            @self.app.tool(
                name="DispatchNotificationsTool",
                description=(
                    "Fan out a completed investigation's report to the customer's configured "
                    "notification destinations (Slack, Outlook, Teams, email, etc.). CoPilot "
                    "owns the routing — pass the alert + report fields and CoPilot looks up "
                    "matching routes, formats per channel, dispatches via SMTP or Shuffle, "
                    "and writes an idempotent dispatch log entry. "
                    "\n\n"
                    "Call this exactly once per investigation, AFTER `SubmitAiAnalystReportTool` "
                    "has succeeded. Pick the trigger based on severity_assessment: use "
                    "'severity_critical_or_high' for Critical/High, otherwise "
                    "'investigation_complete'. The call is best-effort — a failure response "
                    "must NOT cause you to fail the investigation. "
                    "\n\n"
                    "Returns per-route outcomes including dispatched count, skipped count "
                    "(idempotency hits), failed count, and any Shuffle execution_ids for "
                    "forensic correlation. Wraps `POST /api/notifications/dispatch`."
                ),
            )
            async def dispatch_notifications_tool(
                args: DispatchNotificationsArgs,
            ) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "DispatchNotificationsTool",
                    self._get_client().dispatch_notifications(args.model_dump(exclude_none=True)),
                )

    # -- Threat hunting (Talon fork) ----------------------------------- #
    async def _sources_for(self, args: SearchEventsArgs) -> List[str]:
        """Resolve which event sources to search for this request."""
        if args.source_name:
            return [args.source_name]
        payload = await self._get_client().list_event_sources(args.customer_code)
        sources = payload.get("event_sources", []) if isinstance(payload, dict) else payload
        names = [
            s.get("source_name") or s.get("name") if isinstance(s, dict) else s
            for s in (sources or [])
        ]
        resolved = [n for n in names if n]
        if not resolved:
            raise CoPilotMCPError(
                f"No event sources found for customer {args.customer_code!r}. "
                "Check the customer code with GetCustomersTool."
            )
        return resolved

    async def _search_events(self, args: SearchEventsArgs) -> Dict[str, Any]:
        """Resolve the timeframe and sources, search each, and shape the hits.

        Runs inside the coroutine handed to `_run_tool`, so a bad timeframe or
        an unknown customer surfaces as a ToolError the agent can act on.
        """
        timeframe = timeframe_params(args.timeframe)
        sources = await self._sources_for(args)

        hits: List[Dict[str, Any]] = []
        errors: Dict[str, str] = {}
        for source in sources:
            try:
                payload = await self._get_client().search_events(
                    customer_code=args.customer_code,
                    source_name=source,
                    query=args.query,
                    page_size=args.limit,
                    timeframe=timeframe,
                )
            except Exception as exc:  # noqa: BLE001
                # One dead source must not sink a fan-out hunt across the rest.
                logger.warning("search failed for source %s: %s", source, exc)
                errors[source] = str(exc)
                continue
            for hit in extract_hits(payload):
                shaped = normalize_hit(hit, args.query)
                shaped.setdefault("source_name", source)
                hits.append(shaped)

        result: Dict[str, Any] = {
            "query": args.query,
            "customer_code": args.customer_code,
            "timeframe": {"requested": args.timeframe, "params": timeframe},
            "sources_searched": sources,
            "hit_count": len(hits),
            "hits": hits,
        }
        if errors:
            result["source_errors"] = errors
        return result

    def _register_hunt_tools(self) -> None:
        if self._is_enabled("SearchEventsTool"):

            @self.app.tool(
                name="SearchEventsTool",
                description=(
                    "Free-text search across a customer's indexed SIEM events. Use this to "
                    "hunt for a technique, binary, command line, hostname, or user over a "
                    "time window. Returns hits shaped to timestamp, index, host, agent_id, "
                    "user, rule_id, rule_description, and matched_fields (which fields "
                    "actually contained the query), plus raw_fields with the untouched "
                    "document. "
                    "\n\n"
                    "customer_code is REQUIRED — CoPilot scopes search per customer. "
                    "timeframe accepts 'last_24h', 'last_7d', a bare window like '2w', or "
                    "an ISO-8601 range. Omitting source_name fans out across every source "
                    "the customer has, one request each, so pass it when you know which "
                    "source holds the data (see ListEventSourcesTool). If some sources "
                    "fail, the successful hits are still returned and the failures are "
                    "reported under source_errors."
                ),
            )
            async def search_events_tool(args: SearchEventsArgs) -> List[Dict[str, Any]]:
                return await self._run_tool("SearchEventsTool", self._search_events(args))

        if self._is_enabled("ListEventSourcesTool"):

            @self.app.tool(
                name="ListEventSourcesTool",
                description=(
                    "List the event sources searchable for one customer. These supply the "
                    "source_name argument to SearchEventsTool — call this first when you "
                    "do not already know which source holds the data."
                ),
            )
            async def list_event_sources_tool(
                args: ListEventSourcesArgs,
            ) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "ListEventSourcesTool",
                    self._get_client().list_event_sources(args.customer_code),
                )

        if self._is_enabled("GetAlertTool"):

            @self.app.tool(
                name="GetAlertTool",
                description=(
                    "Fetch the full detail record for a single alert by its ID. "
                    "This returns the alert itself — for the AI analyst's job, report, "
                    "and IOCs for that alert, use GetAlertAiAnalysisTool instead."
                ),
            )
            async def get_alert_tool(args: GetAlertArgs) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "GetAlertTool", self._get_client().get_alert(args.alert_id)
                )

        if self._is_enabled("ListIndicesTool"):

            @self.app.tool(
                name="ListIndicesTool",
                description=(
                    "Enumerate the raw indices the indexer reports, with health and doc "
                    "counts. This is infrastructure inventory — to pick a search target, "
                    "use ListEventSourcesTool instead."
                ),
            )
            async def list_indices_tool(_args: ListIndicesArgs) -> List[Dict[str, Any]]:
                return await self._run_tool("ListIndicesTool", self._get_client().list_indices())

        if self._is_enabled("GetAgentTool"):

            @self.app.tool(
                name="GetAgentTool",
                description=(
                    "Fetch one agent's record, including last-seen timestamp and "
                    "online/offline status. Use this for agent-gap hunts — an agent whose "
                    "last-seen time is well behind now has stopped reporting and its host "
                    "is effectively unmonitored."
                ),
            )
            async def get_agent_tool(args: GetAgentArgs) -> List[Dict[str, Any]]:
                return await self._run_tool(
                    "GetAgentTool", self._get_client().get_agent(args.agent_id)
                )

    # ------------------------------------------------------------------ #
    # Runtime
    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """Start the MCP server using stdio transport.

        The server reads JSON-RPC messages from stdin and writes responses to stdout,
        which is the standard transport for containerized / on-demand MCP servers
        launched by an MCP host (Claude Desktop, LangChain MCP adapters, etc.).
        """
        logger.info("Starting CoPilot MCP Server (stdio transport)")
        self.app.run()


def create_server(config: Optional[Config] = None) -> CoPilotMCPServer:
    """Construct a fully-configured `CoPilotMCPServer`."""
    if config is None:
        config = Config.from_env()
    config.validate()
    config.setup_logging()
    return CoPilotMCPServer(config)
