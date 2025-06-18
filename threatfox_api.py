import os
import requests
import asyncio
from async_http import post

_API = "https://threatfox-api.abuse.ch/api/v1/"
_KEY = os.getenv("THREATFOX_API_KEY", "")
_HDRS = {"Accept": "application/json"}
if _KEY:
    _HDRS["API-KEY"] = _KEY

_PAYLOAD_BASE = {"query": "search_ioc"}


async def check_async(ioc: str) -> bool:  # noqa: D401 – simple wrapper
    """Asynchronously query ThreatFox for *ioc* and return *True* if present."""
    body = dict(_PAYLOAD_BASE, search_term=ioc)
    try:
        data = await post(_API, headers=_HDRS, data=body, provider="ThreatFox")
    except Exception:  # pragma: no cover – network / parsing errors are non-fatal
        return False
    return bool(data.get("data"))


def check(ioc: str) -> bool:  # retained for legacy synchronous callers
    """Synchronous implementation kept for backward-compatibility and testing."""
    body = dict(_PAYLOAD_BASE, search_term=ioc)
    try:
        resp = requests.post(_API, headers=_HDRS, data=body, timeout=15)
        if not resp.ok:
            return False
        return bool(resp.json().get("data"))
    except Exception:
        return False 