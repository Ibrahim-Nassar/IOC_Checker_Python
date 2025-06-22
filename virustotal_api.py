"""VirusTotal provider adapter implementing the unified IOCProvider protocol."""

from __future__ import annotations

import os
import urllib.parse as _urlparse
from typing import Any, Dict

from cache import session as requests
from provider_interface import IOCResult, IOCProvider

_API_BASE = "https://www.virustotal.com/api/v3/"
_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
if not _KEY:
    # The provider still operates but will always return an error due to missing key.
    pass

_HEADERS: Dict[str, str] = {
    "Accept": "application/json",
    "x-apikey": _KEY or "",
}


class VirusTotalProvider:
    """VirusTotal implementation conforming to IOCProvider."""

    NAME = "VirusTotal"
    TIMEOUT = 30  # seconds (Public API can be slower)

    def _build_url(self, ioc_type: str, ioc_value: str) -> str:  # noqa: D401
        """Map IOC kinds to VirusTotal v3 endpoints. Defaults to a generic search."""
        # VT v3 endpoints expect unique IDs for certain types; we fall back to search.
        # Generic search is slower but universal.
        encoded = _urlparse.quote(ioc_value, safe="")
        return f"{_API_BASE}search?query={encoded}"

    def _parse_stats(self, data: Dict[str, Any]) -> tuple[int, int]:
        """Return (positives,total) from VT API JSON (first result)."""
        try:
            stats = data["data"][0]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            total = sum(int(v) for v in stats.values()) or 1
            return malicious, total
        except Exception:
            return 0, 1

    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:  # type: ignore[override]
        """Query VirusTotal and translate response into IOCResult."""
        if not _KEY:
            return IOCResult(status="missing_api_key", score=None, raw={})

        url = self._build_url(ioc_type, ioc_value)
        try:
            resp = requests.get(url, headers=_HEADERS, timeout=self.TIMEOUT)
            if resp.status_code == 404:
                return IOCResult(status="clean", score=0.0, raw={"status_code": 404})
            if resp.status_code != 200:
                return IOCResult(
                    status=f"error_{resp.status_code}",
                    score=None,
                    raw={"status_code": resp.status_code, "text": resp.text},
                )
            data: Dict[str, Any] = resp.json()
            pos, tot = self._parse_stats(data)
            malicious = pos >= 5 or (pos / tot) >= 0.10
            status = "malicious" if malicious else "clean"
            score = (pos / tot) * 100 if tot else None
            return IOCResult(status=status, score=score, raw=data)
        except Exception as exc:  # pragma: no cover – network/JSON errors non-fatal
            return IOCResult(status="error", score=None, raw={"error": str(exc)})


# Module-level provider instance for registration convenience
provider: IOCProvider = VirusTotalProvider()

# --- AUTOGEN START
# (Cursor will fill in)
# --- AUTOGEN END 