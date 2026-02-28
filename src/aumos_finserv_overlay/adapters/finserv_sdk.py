"""Python SDK client for aumos-finserv-overlay API.

GAP-296: Client SDK (Python).
"""
from __future__ import annotations

import asyncio
import random
from typing import Any, Generic, TypeVar

import httpx
from pydantic import BaseModel, Field

T = TypeVar("T")


class PagedResponse(BaseModel, Generic[T]):
    """Paginated API response wrapper."""

    items: list[Any]
    total: int
    page: int
    page_size: int


class FinServSDKError(Exception):
    """Base exception for AumOS FinServ SDK errors."""


class FinServNotFoundError(FinServSDKError):
    """Resource not found (HTTP 404)."""


class FinServAuthError(FinServSDKError):
    """Authentication or authorization failure (HTTP 401/403)."""


class FinServValidationError(FinServSDKError):
    """Request validation failure (HTTP 400)."""


class FinServServerError(FinServSDKError):
    """Server-side error (HTTP 5xx)."""


# HTTP status codes that are retryable
_RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}
# HTTP status codes that are never retried
_NON_RETRYABLE_STATUS_CODES = {400, 401, 403, 404}


def _jitter(base_seconds: float) -> float:
    """Add ±25% jitter to a backoff duration."""
    return base_seconds * (0.75 + random.random() * 0.5)


class AumOSFinServClient:
    """Async Python client for aumos-finserv-overlay API.

    Provides typed access to all FinServ overlay endpoints with
    automatic retry (exponential backoff + jitter) for retryable errors.
    Use as an async context manager to ensure connection pool cleanup.

    Example:
        async with AumOSFinServClient(base_url=..., api_key=..., tenant_id=...) as client:
            alerts = await client.list_aml_alerts(severity="high")
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        tenant_id: str,
        timeout_seconds: float = 30.0,
        max_retries: int = 3,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._tenant_id = tenant_id
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._http: httpx.AsyncClient | None = None

    async def __aenter__(self) -> AumOSFinServClient:
        """Open the HTTP connection pool."""
        self._http = httpx.AsyncClient(
            base_url=self._base_url,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "X-Tenant-ID": self._tenant_id,
                "Content-Type": "application/json",
            },
            timeout=self._timeout,
        )
        return self

    async def __aexit__(self, *args: object) -> None:
        """Close the HTTP connection pool."""
        if self._http:
            await self._http.aclose()

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        """Execute an HTTP request with exponential backoff retry.

        Non-retryable errors (400, 401, 403, 404) raise immediately.
        Retryable errors (429, 5xx) are retried up to max_retries times.
        """
        if not self._http:
            raise FinServSDKError("Client not started. Use as async context manager.")

        last_exc: Exception | None = None
        for attempt in range(self._max_retries + 1):
            try:
                response = await self._http.request(method, path, **kwargs)

                if response.status_code in _NON_RETRYABLE_STATUS_CODES:
                    if response.status_code == 404:
                        raise FinServNotFoundError(f"Not found: {path}")
                    if response.status_code in (401, 403):
                        raise FinServAuthError(f"Auth error {response.status_code}: {path}")
                    raise FinServValidationError(f"Validation error: {response.text}")

                if response.status_code in _RETRYABLE_STATUS_CODES:
                    if attempt < self._max_retries:
                        wait = _jitter(2 ** attempt)
                        await asyncio.sleep(wait)
                        continue
                    raise FinServServerError(f"Server error {response.status_code} after {self._max_retries} retries")

                response.raise_for_status()
                return response.json()

            except (FinServNotFoundError, FinServAuthError, FinServValidationError):
                raise
            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                last_exc = exc
                if attempt < self._max_retries:
                    await asyncio.sleep(_jitter(2 ** attempt))
                    continue
                raise FinServSDKError(f"Request failed after {self._max_retries} retries") from last_exc

        raise FinServSDKError("Unexpected retry loop exit")

    async def list_aml_alerts(self, severity: str | None = None, page: int = 1) -> dict:
        """List AML alerts, optionally filtered by severity.

        Args:
            severity: Optional filter: low, medium, high, critical.
            page: Page number (1-based).

        Returns:
            Paginated response with AML alert records.
        """
        params: dict[str, Any] = {"page": page}
        if severity:
            params["severity"] = severity
        return await self._request("GET", "/api/v1/finserv/aml/alerts", params=params)

    async def review_aml_alert(self, alert_id: str, sar_filed: bool = False) -> dict:
        """Mark an AML alert as reviewed, optionally filing a SAR.

        Args:
            alert_id: UUID of the AML alert.
            sar_filed: Whether a Suspicious Activity Report was filed.

        Returns:
            Updated alert record.
        """
        return await self._request(
            "POST",
            f"/api/v1/finserv/aml/alerts/{alert_id}/review",
            json={"sar_filed": sar_filed},
        )

    async def list_regulatory_updates(
        self, regulator: str | None = None, domain: str | None = None, page: int = 1
    ) -> dict:
        """List regulatory updates.

        Args:
            regulator: Filter by regulator (SEC, FINRA, OCC, CFPB, FRB).
            domain: Filter by compliance domain (SOX, SR_11_7, AML, etc.).
            page: Page number (1-based).

        Returns:
            Paginated response with regulatory update records.
        """
        params: dict[str, Any] = {"page": page}
        if regulator:
            params["regulator"] = regulator
        if domain:
            params["domain"] = domain
        return await self._request("GET", "/api/v1/finserv/regulatory/updates", params=params)

    async def poll_regulatory_feeds(self) -> dict:
        """Trigger manual poll of all regulator feeds.

        Requires privilege level >= 4.

        Returns:
            Summary of newly found regulatory updates.
        """
        return await self._request("POST", "/api/v1/finserv/regulatory/poll")

    async def assess_basel_portfolio(self, exposures: list[dict]) -> dict:
        """Compute Basel III/IV RWA for a portfolio of credit exposures.

        Args:
            exposures: List of CreditExposure dicts with asset_class, EAD, PD, LGD.

        Returns:
            BaselAssessment with total RWA and per-exposure results.
        """
        return await self._request("POST", "/api/v1/finserv/basel/assess", json={"exposures": exposures})

    async def generate_iso20022(self, message_type: str, payload: dict) -> dict:
        """Generate ISO 20022 financial messages.

        Args:
            message_type: pacs.008, pacs.009, or camt.053.
            payload: Message-specific payload fields.

        Returns:
            Generated message metadata and download URI.
        """
        return await self._request(
            "POST",
            "/api/v1/finserv/transactions/generate/iso20022",
            json={"message_type": message_type, "payload": payload},
        )
