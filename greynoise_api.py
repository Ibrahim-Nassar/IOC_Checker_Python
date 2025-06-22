"""GreyNoise provider adapter implementing the unified IOCProvider protocol."""

from __future__ import annotations

import os
from typing import Any, Dict

from cache import session as requests
from provider_interface import IOCResult, IOCProvider

_API = "https://api.greynoise.io/v3/community/"
_KEY = os.getenv("GREYNOISE_API_KEY", "")
_HDRS: Dict[str, str] = {"Accept": "application/json"}
if _KEY:
    _HDRS["key"] = _KEY


class GreyNoiseProvider:
    """GreyNoise implementation conforming to IOCProvider."""

    NAME = "GreyNoise"
    TIMEOUT = 10  # seconds

    # The runtime_checkable IOCProvider protocol only inspects attribute names,
    # so we need no explicit subclassing – structural typing is sufficient.
    def query_ioc(self, ioc_type: str, ioc_value: str) -> IOCResult:  # type: ignore[override]
        """Query GreyNoise community API and translate response into IOCResult."""
        if ioc_type.lower() != "ip":
            # GreyNoise only supports IP addresses
            return IOCResult(status="unsupported", score=None, raw={})

        headers = dict(_HDRS)  # copy to avoid accidental mutation
        try:
            resp = requests.get(f"{_API}{ioc_value}", headers=headers, timeout=self.TIMEOUT)
            if resp.status_code != 200:
                return IOCResult(
                    status=f"error_{resp.status_code}",
                    score=None,
                    raw={"status_code": resp.status_code, "text": resp.text},
                )
            data: Dict[str, Any] = resp.json()
            classification = str(data.get("classification", "")).lower()
            malicious = classification == "malicious"
            status = "malicious" if malicious else "clean"
            score = 100.0 if malicious else 0.0
            return IOCResult(status=status, score=score, raw=data)
        except Exception as exc:  # pragma: no cover – network/JSON errors are non-fatal
            return IOCResult(status="error", score=None, raw={"error": str(exc)})


# Provide a module-level instance for convenient import elsewhere
provider: IOCProvider = GreyNoiseProvider()

# --- AUTOGEN START
# (Cursor will fill in)
# --- AUTOGEN END