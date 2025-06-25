"""AlienVault OTX provider adapter implementing the unified IOCProvider protocol."""

from __future__ import annotations

import os
import requests
from typing import Any, Dict

from cache import session as requests
from provider_interface import IOCResult, IOCProvider

_API_BASE = "https://otx.alienvault.com/api/v1/indicators"
_KEY = os.getenv("ALIENVAULT_OTX_API_KEY", "")
_HEADERS: Dict[str, str] = {"Accept": "application/json"}
if _KEY:
    _HEADERS["X-OTX-API-KEY"] = _KEY

# Mapping IOC kinds used in this project to OTX endpoint segments.
_IOT_TYPE_MAP = {
    "ip": "IPv4",
    "domain": "domain",
    "url": "url",
    "hash": "file",  # md5/sha1/sha256 handled under 'file'
}


class OTXProvider:
    """OTX implementation conforming to IOCProvider."""

    NAME = "OTX"
    TIMEOUT = 30  # seconds

    def __init__(self) -> None:
        self.API_KEY: str | None = os.getenv("OTX_API_KEY")

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:
        if not self.API_KEY:
            return IOCResult(status="missing_api_key", score=None, raw={})

        url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc_value}"
        headers = {"X-OTX-API-KEY": self.API_KEY}

        try:
            r = requests.get(url, headers=headers, timeout=self.TIMEOUT)
        except requests.exceptions.RequestException as exc:
            return IOCResult(status="network_error", score=None, raw={"error": str(exc)})

        if r.status_code == 200:
            data: Dict[str, Any] = r.json()
            score = float(data.get("pulse_info", {}).get("count", 0))
            return IOCResult(status="success", score=score, raw=data)

        if r.status_code == 401:
            return IOCResult(status="invalid_api_key", score=None, raw=r.json())

        if r.status_code == 429:
            return IOCResult(status="quota_exceeded", score=None, raw=r.json())

        return IOCResult(status=f"http_{r.status_code}", score=None, raw={"text": r.text})


def get_provider():
    return OTXProvider()

# Module-level provider instance
provider: IOCProvider = get_provider()


