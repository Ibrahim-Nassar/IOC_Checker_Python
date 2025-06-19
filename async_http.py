from __future__ import annotations
import aiohttp
from typing import Any, Dict, Optional


async def _fetch_json(method: str, url: str, *, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None, data: Any = None, provider: str = "") -> Dict[str, Any]:
    """Internal helper that performs an HTTP request and returns JSON (or empty dict)."""
    timeout = aiohttp.ClientTimeout(total=15)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.request(method, url, headers=headers, params=params, data=data) as resp:
            try:
                return await resp.json()
            except Exception:
                return {}


async def get(url: str, *, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None, provider: str = "") -> Dict[str, Any]:
    """Asynchronous HTTP GET returning parsed JSON (empty dict on any error)."""
    return await _fetch_json("GET", url, headers=headers, params=params, provider=provider)


async def post(url: str, *, headers: Optional[Dict[str, str]] = None, data: Any = None, provider: str = "") -> Dict[str, Any]:
    """Asynchronous HTTP POST returning parsed JSON (empty dict on any error)."""
    return await _fetch_json("POST", url, headers=headers, data=data, provider=provider) 