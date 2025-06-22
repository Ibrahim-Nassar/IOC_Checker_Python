"""ThreatFox provider adapter implementing the unified IOCProvider protocol."""

from __future__ import annotations

import os
from typing import Any, Dict

from cache import session as requests
from provider_interface import IOCResult, IOCProvider

_API = "https://threatfox-api.abuse.ch/api/v1/"
_KEY = os.getenv("THREATFOX_API_KEY", "")
_HDRS: Dict[str, str] = {"Accept": "application/json"}
if _KEY:
    _HDRS["API-KEY"] = _KEY

_PAYLOAD_BASE = {"query": "search_ioc"}


class ThreatFoxProvider:
    """ThreatFox implementation conforming to IOCProvider."""

    NAME = "ThreatFox"
    TIMEOUT = 5  # seconds

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:  # type: ignore[override]
        """Query ThreatFox for the given IOC value and return an IOCResult."""
        body = dict(_PAYLOAD_BASE, search_term=ioc_value)
        try:
            resp = requests.post(_API, headers=_HDRS, data=body, timeout=self.TIMEOUT)
            if not resp.ok:
                return IOCResult(
                    status=f"error_{resp.status_code}",
                    score=None,
                    raw={"status_code": resp.status_code, "text": resp.text},
                )
            data: Dict[str, Any] = resp.json()
            malicious = bool(data.get("data"))
            status = "malicious" if malicious else "clean"
            score = 100.0 if malicious else 0.0
            return IOCResult(status=status, score=score, raw=data)
        except Exception as exc:  # pragma: no cover – network/parsing errors are non-fatal
            return IOCResult(status="error", score=None, raw={"error": str(exc)})


# Module-level provider instance for easy registration
provider: IOCProvider = ThreatFoxProvider()

# --- AUTOGEN START
# (Cursor will fill in)
# --- AUTOGEN END 