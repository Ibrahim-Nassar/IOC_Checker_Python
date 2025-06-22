"""AlienVault OTX provider adapter implementing the unified IOCProvider protocol."""

from __future__ import annotations

import os
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

    NAME = "OTX AlienVault"
    TIMEOUT = 6  # seconds

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:  # type: ignore[override]
        """Query AlienVault OTX and translate response into IOCResult."""
        segment = _IOT_TYPE_MAP.get(ioc_type.lower())
        if not segment:
            return IOCResult(status="unsupported", score=None, raw={})

        url = f"{_API_BASE}/{segment}/{ioc_value}"
        try:
            resp = requests.get(url, headers=_HEADERS, timeout=self.TIMEOUT)
            if resp.status_code == 404:
                # indicator unknown
                return IOCResult(status="clean", score=0.0, raw={"status_code": 404})
            if resp.status_code != 200:
                return IOCResult(
                    status=f"error_{resp.status_code}",
                    score=None,
                    raw={"status_code": resp.status_code, "text": resp.text},
                )
            data: Dict[str, Any] = resp.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            malicious = pulses > 0
            status = "malicious" if malicious else "clean"
            score = min(100.0, pulses * 10.0) if malicious else 0.0
            return IOCResult(status=status, score=score, raw=data)
        except Exception as exc:
            return IOCResult(status="error", score=None, raw={"error": str(exc)})


# Module-level provider instance
provider: IOCProvider = OTXProvider()

# --- AUTOGEN START
# (Cursor will fill in)
# --- AUTOGEN END 