"""VirusTotal provider adapter implementing the IOCResult protocol."""

from __future__ import annotations

import os
import requests
from typing import Any, Dict

from provider_interface import IOCResult


class VirusTotalProvider:
    """Light-weight VirusTotal v3 API wrapper (read-only)."""

    NAME: str = "VirusTotal"
    TIMEOUT: int = 30  # seconds

    def __init__(self) -> None:
        """Resolve the API key from the environment on first use."""
        self.API_KEY: str | None = (
            os.getenv("VT_API_KEY")
            or os.getenv("VIRUSTOTAL_API_KEY")
            or None
        )

    # ---------------------------------------------------------------------
    # Public helpers
    # ---------------------------------------------------------------------

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:  # noqa: D401
        """Query VirusTotal for an IOC and return a normalized result."""
        if not self.API_KEY:
            return IOCResult(status="missing_api_key", score=None, raw={})

        # Select the correct collection path.
        collection = {
            "ip": "ip_addresses",
            "domain": "domains",
            "url": "urls",
            "hash": "files",
        }.get(ioc_type, "files")

        url = f"https://www.virustotal.com/api/v3/{collection}/{ioc_value}"
        headers: Dict[str, str] = {"x-apikey": self.API_KEY}

        try:
            r = requests.get(url, headers=headers, timeout=self.TIMEOUT)
        except requests.exceptions.RequestException as exc:  # pragma: no cover
            return IOCResult(status="network_error", score=None, raw={"error": str(exc)})

        if r.status_code == 200:
            data: Dict[str, Any] = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            score = float(stats.get("malicious", 0))
            return IOCResult(status="success", score=score, raw=data)

        if r.status_code == 401:
            return IOCResult(status="invalid_api_key", score=None, raw=r.json())

        if r.status_code == 429:
            return IOCResult(status="quota_exceeded", score=None, raw=r.json())

        return IOCResult(status=f"http_{r.status_code}", score=None, raw={"text": r.text})


# -------------------------------------------------------------------------
# Convenience factory used by registry modules
# -------------------------------------------------------------------------


def get_provider() -> VirusTotalProvider:  # noqa: D401
    """Return a fresh provider instance (simple factory)."""
    return VirusTotalProvider()
