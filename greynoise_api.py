import os
import requests
import asyncio
from async_http import get

_API = "https://api.greynoise.io/v3/community/"
_KEY = os.getenv("GREYNOISE_API_KEY", "")
_HDRS = {"Accept": "application/json"}
if _KEY:
    _HDRS["key"] = _KEY


async def check_async(ip: str) -> bool:
    """Asynchronously query GreyNoise and return *True* when classified malicious."""
    try:
        data = await get(f"{_API}{ip}", headers=_HDRS, provider="GreyNoise")
    except Exception:  # pragma: no cover
        return False
    return data.get("classification", "") == "malicious"


def check(ip: str) -> bool:
    """Synchronous implementation preserved for existing tests."""
    headers = dict(_HDRS)
    try:
        resp = requests.get(f"{_API}{ip}", headers=headers, timeout=10)
        if resp.status_code != 200:
            return False
        return resp.json().get("classification", "") == "malicious"
    except Exception:
        return False