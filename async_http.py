from __future__ import annotations
import aiohttp  # type: ignore
import asyncio
import atexit
from typing import Any, Dict, Optional, cast

_SESSION: aiohttp.ClientSession | None = None
_TIMEOUT = aiohttp.ClientTimeout(total=15)


async def get_session() -> aiohttp.ClientSession:
    """Return a shared ``aiohttp`` session, creating it on first use."""
    global _SESSION
    if _SESSION is None or _SESSION.closed:
        _SESSION = aiohttp.ClientSession(timeout=_TIMEOUT)
    return _SESSION


async def close_session() -> None:
    """Close the shared session if it exists."""
    global _SESSION
    if _SESSION is not None and not _SESSION.closed:
        await _SESSION.close()
    _SESSION = None


def _atexit_close() -> None:  # pragma: no cover - cleanup helper
    try:
        asyncio.run(close_session())
    except Exception:
        pass


atexit.register(_atexit_close)


async def _fetch_json(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
    data: Any = None,
    provider: str = "",
) -> Dict[str, Any]:
    """Internal helper that performs an HTTP request and returns JSON (or empty dict)."""
    session = await get_session()
    async with session.request(method, url, headers=headers, params=params, data=data) as resp:
        try:
            return cast(Dict[str, Any], await resp.json())
        except Exception:
            return {}


async def get(
    url: str, *, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None, provider: str = ""
) -> Dict[str, Any]:
    """Asynchronous HTTP GET returning parsed JSON (empty dict on any error)."""
    return await _fetch_json("GET", url, headers=headers, params=params, provider=provider)


async def post(
    url: str, *, headers: Optional[Dict[str, str]] = None, data: Any = None, provider: str = ""
) -> Dict[str, Any]:
    """Asynchronous HTTP POST returning parsed JSON (empty dict on any error)."""
    return await _fetch_json("POST", url, headers=headers, data=data, provider=provider)
