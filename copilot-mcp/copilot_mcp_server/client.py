"""Async HTTP client for the SOCFortress CoPilot API."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import httpx

from copilot_mcp_server import endpoints
from copilot_mcp_server.config import CoPilotConfig
from copilot_mcp_server.exceptions import (
    CoPilotAPIError,
    CoPilotAuthenticationError,
    CoPilotTwoFactorRequiredError,
)

logger = logging.getLogger(__name__)

# CoPilot tokens default to 1440 minutes (24 hours). Refresh ~5 minutes before expiry.
TOKEN_LIFETIME_MINUTES = 1440
TOKEN_REFRESH_BUFFER_SECONDS = 300


class CoPilotClient:
    """Async client wrapping the CoPilot REST API.

    Handles OAuth2 password-grant authentication and JWT token caching/refresh.
    """

    def __init__(self, config: CoPilotConfig) -> None:
        self.config = config
        self._client: Optional[httpx.AsyncClient] = None
        self._token: Optional[str] = None
        self._token_expiry: Optional[datetime] = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                verify=self.config.ssl_verify,
                timeout=self.config.timeout,
                http2=True,
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "CoPilotClient":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ------------------------------------------------------------------ #
    # Authentication
    # ------------------------------------------------------------------ #
    async def _refresh_token(self, force: bool = False) -> str:
        """Return a valid JWT, fetching a new one if necessary."""
        if (
            not force
            and self._token
            and self._token_expiry
            and datetime.utcnow() + timedelta(seconds=TOKEN_REFRESH_BUFFER_SECONDS)
            < self._token_expiry
        ):
            return self._token

        token_url = f"{self.config.url}/api/auth/token"
        logger.info("Authenticating to CoPilot at %s", token_url)

        client = await self._get_client()
        try:
            response = await client.post(
                token_url,
                data={
                    "username": self.config.username,
                    "password": self.config.password,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise CoPilotAuthenticationError(
                f"Failed to reach CoPilot auth endpoint: {exc}"
            ) from exc

        if response.status_code != 200:
            raise CoPilotAuthenticationError(
                f"CoPilot authentication failed ({response.status_code}): {response.text}"
            )

        payload = response.json()

        if payload.get("requires_2fa"):
            raise CoPilotTwoFactorRequiredError(
                "CoPilot account requires 2FA, which is not supported by this MCP server. "
                "Disable 2FA on the service account or use an account without 2FA."
            )

        token = payload.get("access_token")
        if not token:
            raise CoPilotAuthenticationError(
                f"CoPilot auth response did not include an access_token: {payload}"
            )

        self._token = token
        self._token_expiry = datetime.utcnow() + timedelta(minutes=TOKEN_LIFETIME_MINUTES)
        logger.info("Obtained CoPilot JWT (expires ~%s UTC)", self._token_expiry.isoformat())
        return token

    async def authenticate(self) -> str:
        """Force a token refresh and return the new token."""
        return await self._refresh_token(force=True)

    # ------------------------------------------------------------------ #
    # Generic request helper
    # ------------------------------------------------------------------ #
    async def request(
        self,
        method: str,
        endpoint: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        retry_on_auth: bool = True,
    ) -> Any:
        """Execute an authenticated API request and return the parsed JSON body."""
        token = await self._refresh_token()
        url = f"{self.config.url}{endpoint}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        if json is not None:
            headers["Content-Type"] = "application/json"

        client = await self._get_client()
        try:
            response = await client.request(
                method,
                url,
                params=params,
                json=json,
                headers=headers,
            )
        except httpx.HTTPError as exc:
            raise CoPilotAPIError(f"HTTP error calling {method} {endpoint}: {exc}") from exc

        if response.status_code == 401 and retry_on_auth:
            logger.info("Got 401 from CoPilot — refreshing token and retrying once")
            await self._refresh_token(force=True)
            return await self.request(
                method,
                endpoint,
                params=params,
                json=json,
                retry_on_auth=False,
            )

        if response.status_code >= 400:
            raise CoPilotAPIError(
                f"CoPilot API error ({response.status_code}) on {method} {endpoint}: "
                f"{response.text}"
            )

        if not response.content:
            return None
        try:
            return response.json()
        except ValueError:
            return response.text

    # ------------------------------------------------------------------ #
    # API methods — Customers
    # ------------------------------------------------------------------ #
    async def get_customers(self) -> Any:
        """Fetch all customers from CoPilot (`GET /api/customers`)."""
        return await self.request("GET", "/api/customers")

    # ------------------------------------------------------------------ #
    # API methods — AI Analyst: Jobs
    # ------------------------------------------------------------------ #
    async def create_ai_analyst_job(self, body: Dict[str, Any]) -> Any:
        """Register a new AI analyst investigation job (`POST /api/ai_analyst/jobs`)."""
        return await self.request("POST", "/api/ai_analyst/jobs", json=body)

    async def update_ai_analyst_job(self, job_id: str, body: Dict[str, Any]) -> Any:
        """Update an AI analyst job status (`PATCH /api/ai_analyst/jobs/{job_id}`)."""
        return await self.request("PATCH", f"/api/ai_analyst/jobs/{job_id}", json=body)

    async def get_ai_analyst_job(self, job_id: str) -> Any:
        """Get a specific AI analyst job (`GET /api/ai_analyst/jobs/{job_id}`)."""
        return await self.request("GET", f"/api/ai_analyst/jobs/{job_id}")

    async def list_ai_analyst_jobs_by_alert(self, alert_id: int) -> Any:
        """List all AI analyst jobs for an alert (`GET /api/ai_analyst/jobs/alert/{alert_id}`)."""
        return await self.request("GET", f"/api/ai_analyst/jobs/alert/{alert_id}")

    async def list_ai_analyst_jobs_by_customer(self, customer_code: str) -> Any:
        """List all AI analyst jobs for a customer (`GET /api/ai_analyst/jobs/customer/{code}`)."""
        return await self.request("GET", f"/api/ai_analyst/jobs/customer/{customer_code}")

    # ------------------------------------------------------------------ #
    # API methods — AI Analyst: Reports
    # ------------------------------------------------------------------ #
    async def submit_ai_analyst_report(self, body: Dict[str, Any]) -> Any:
        """Submit an AI analyst investigation report (`POST /api/ai_analyst/reports`)."""
        return await self.request("POST", "/api/ai_analyst/reports", json=body)

    async def list_ai_analyst_reports_by_alert(self, alert_id: int) -> Any:
        """List all AI analyst reports for an alert (`GET /api/ai_analyst/reports/alert/{id}`)."""
        return await self.request("GET", f"/api/ai_analyst/reports/alert/{alert_id}")

    # ------------------------------------------------------------------ #
    # API methods — AI Analyst: IOCs
    # ------------------------------------------------------------------ #
    async def submit_ai_analyst_iocs(self, body: Dict[str, Any]) -> Any:
        """Submit extracted IOCs for a report (`POST /api/ai_analyst/iocs`)."""
        return await self.request("POST", "/api/ai_analyst/iocs", json=body)

    async def list_ai_analyst_iocs_by_report(self, report_id: int) -> Any:
        """List IOCs for a specific report (`GET /api/ai_analyst/iocs/report/{report_id}`)."""
        return await self.request("GET", f"/api/ai_analyst/iocs/report/{report_id}")

    async def list_ai_analyst_iocs_by_alert(self, alert_id: int) -> Any:
        """List all IOCs for an alert (`GET /api/ai_analyst/iocs/alert/{alert_id}`)."""
        return await self.request("GET", f"/api/ai_analyst/iocs/alert/{alert_id}")

    async def list_ai_analyst_iocs_by_customer(
        self,
        customer_code: str,
        vt_verdict: Optional[str] = None,
    ) -> Any:
        """List IOCs for a customer, optionally filtered by VT verdict.

        `GET /api/ai_analyst/iocs/customer/{customer_code}?vt_verdict=...`
        """
        params: Optional[Dict[str, Any]] = {"vt_verdict": vt_verdict} if vt_verdict else None
        return await self.request(
            "GET",
            f"/api/ai_analyst/iocs/customer/{customer_code}",
            params=params,
        )

    # ------------------------------------------------------------------ #
    # API methods — AI Analyst: Combined
    # ------------------------------------------------------------------ #
    async def get_ai_analyst_alert_analysis(self, alert_id: int) -> Any:
        """Get the full AI analysis for an alert (`GET /api/ai_analyst/alert/{alert_id}`)."""
        return await self.request("GET", f"/api/ai_analyst/alert/{alert_id}")

    # ------------------------------------------------------------------ #
    # API methods — Notifications dispatch
    # ------------------------------------------------------------------ #
    async def dispatch_notifications(self, body: Dict[str, Any]) -> Any:
        """Fire post-investigation notifications for an alert.

        Wraps `POST /api/notifications/dispatch` — CoPilot looks up the
        customer's notification routes, filters by trigger and severity,
        dispatches each match (SMTP / Shuffle / etc.), and returns a
        per-route outcome list. Idempotent on (customer_code, alert_id,
        route_id, trigger).
        """
        return await self.request("POST", "/api/notifications/dispatch", json=body)

    # ------------------------------------------------------------------ #
    # API methods — Threat hunting (Talon fork)
    # ------------------------------------------------------------------ #
    # Paths live in `copilot_mcp_server.endpoints`, verified against the live
    # instance. See that module's docstring for how.
    async def search_events(
        self,
        customer_code: str,
        source_name: str,
        query: Optional[str] = None,
        page_size: int = 100,
        timeframe: Optional[Dict[str, str]] = None,
    ) -> Any:
        """Search one customer's event source (`GET endpoints.SEARCH`).

        `timeframe` is the already-resolved parameter dict from
        `hunt.timeframe_params` — either {"timerange": "24h"} or the absolute
        pair {"time_from": ..., "time_to": ...}.
        """
        params: Dict[str, Any] = {"page_size": page_size}
        if query:
            params["query"] = query
        params.update(timeframe or {})
        return await self.request(
            "GET",
            endpoints.SEARCH.format(customer_code=customer_code, source_name=source_name),
            params=params,
        )

    async def list_event_sources(self, customer_code: str) -> Any:
        """List a customer's searchable event sources (`GET endpoints.EVENT_SOURCES`)."""
        return await self.request(
            "GET", endpoints.EVENT_SOURCES.format(customer_code=customer_code)
        )

    async def get_alert(self, alert_id: int) -> Any:
        """Fetch full detail for a single alert (`GET endpoints.ALERT_DETAIL`)."""
        return await self.request("GET", endpoints.ALERT_DETAIL.format(alert_id=alert_id))

    async def list_indices(self) -> Any:
        """Enumerate raw indexer indices (`GET endpoints.INDICES`)."""
        return await self.request("GET", endpoints.INDICES)

    async def get_agent(self, agent_id: str) -> Any:
        """Fetch an agent's last-seen time and status (`GET endpoints.AGENT_DETAIL`)."""
        return await self.request("GET", endpoints.AGENT_DETAIL.format(agent_id=agent_id))
