"""AbuseIPDB provider adapter implementing the unified IOCProvider protocol."""

from __future__ import annotations

import os
from typing import Any, Dict

from cache import session as requests
from provider_interface import IOCResult, IOCProvider

_API = "https://api.abuseipdb.com/api/v2/check"
_KEY = os.getenv("ABUSEIPDB_API_KEY", "")

_HEADERS: Dict[str, str] = {
    "Accept": "application/json",
    "Key": _KEY or "",
}

_PARAMS_DEFAULT: Dict[str, str] = {"maxAgeInDays": "90"}


class AbuseIPDBProvider:
    """AbuseIPDB implementation conforming to IOCProvider."""

    NAME = "AbuseIPDB"
    TIMEOUT = 8  # seconds

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:  # type: ignore[override]
        """Query AbuseIPDB for the given IP address and return an IOCResult."""
        if ioc_type.lower() != "ip":
            return IOCResult(status="unsupported", score=None, raw={})

        if not _KEY:
            return IOCResult(status="missing_api_key", score=None, raw={})

        params = dict(_PARAMS_DEFAULT, ipAddress=ioc_value)
        try:
            resp = requests.get(_API, headers=_HEADERS, params=params, timeout=self.TIMEOUT)
            
            if resp.status_code == 401:
                return IOCResult(status="invalid_api_key", score=None, raw={"status_code": 401})
            
            if resp.status_code == 429:
                return IOCResult(status="quota_exceeded", score=None, raw={"status_code": 429})
            
            if resp.status_code == 404:
                # Not found in DB implies clean
                return IOCResult(status="success", score=0.0, raw={"status_code": 404})
            
            if resp.status_code != 200:
                return IOCResult(
                    status=f"http_{resp.status_code}",
                    score=None,
                    raw={"status_code": resp.status_code, "text": resp.text},
                )
            
            data: Dict[str, Any] = resp.json().get("data", {})
            confidence = float(data.get("abuseConfidenceScore", 0))
            return IOCResult(status="success", score=confidence, raw=data)
            
        except requests.exceptions.RequestException as exc:
            return IOCResult(status="network_error", score=None, raw={"error": str(exc)})
        except Exception as exc:
            return IOCResult(status="error", score=None, raw={"error": str(exc)})


# Module-level provider instance
provider: IOCProvider = AbuseIPDBProvider()

# --- AUTOGEN START
# (Cursor will fill in)
# --- AUTOGEN END 