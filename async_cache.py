"""Async HTTP helper with caching and rate limiting, mirroring cache.py but using httpx.AsyncClient."""
from __future__ import annotations

import asyncio
import os
if os.name == "nt":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import atexit
import contextvars
import logging
import threading
import weakref
from pathlib import Path

import httpx
from aiolimiter import AsyncLimiter

# Try to import httpx_cache, fallback to plain client if missing
try:
    from httpx_cache import AsyncClient, FileCache
    _HAS_CACHE = True
except ImportError:
    logging.warning("httpx_cache not available - caching disabled. Install with: pip install httpx-cache")
    _HAS_CACHE = False

# Use proper user cache directory
CACHE_DIR = Path(os.getenv("XDG_CACHE_HOME", Path.home() / ".cache")) / "ioc_checker"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Create file cache instance that can be shared (only if httpx_cache is available)
_FILE_CACHE = FileCache(str(CACHE_DIR / "async_cache")) if _HAS_CACHE else None

# Context variable for per-loop client instances
_CLIENT_CVAR: contextvars.ContextVar[httpx.AsyncClient] = contextvars.ContextVar("client")

_LIMITERS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, AsyncLimiter]] = weakref.WeakKeyDictionary()
_LIM_LOCK = threading.Lock()


def _get_client() -> httpx.AsyncClient:
    """Get or create an AsyncClient for the current context/event loop."""
    try:
        return _CLIENT_CVAR.get()
    except LookupError:
        if _HAS_CACHE and _FILE_CACHE is not None:
            c = AsyncClient(cache=_FILE_CACHE, timeout=5.0)
        else:
            c = httpx.AsyncClient(timeout=5.0)
        _CLIENT_CVAR.set(c)
        return c


def _get_limiter(api_key: str | None) -> AsyncLimiter:
    key = api_key or "anonymous"
    loop = asyncio.get_running_loop()
    with _LIM_LOCK:
        per_loop = _LIMITERS.setdefault(loop, {})
        if key not in per_loop:
            per_loop[key] = AsyncLimiter(4, 60)
        return per_loop[key]


async def aget(url: str, *, timeout: float = 5.0, ttl: int = 900, api_key: str | None = None, headers: dict | None = None) -> httpx.Response:
    """Async GET with caching and rate limiting."""
    client = _get_client()
    limiter = _get_limiter(api_key)
    
    # Add cache control headers if caching is available
    if _HAS_CACHE and headers is None:
        headers = {}
    if _HAS_CACHE and headers is not None:
        headers = headers.copy()
        headers["Cache-Control"] = f"max-age={ttl}"
    
    async with limiter:
        return await client.get(url, timeout=timeout, headers=headers)


async def apost(url: str, json: dict, *, timeout: float = 5.0, ttl: int = 900, api_key: str | None = None) -> httpx.Response:
    """Async POST with caching and rate limiting."""
    client = _get_client()
    limiter = _get_limiter(api_key)
    
    # Add cache control headers if caching is available
    headers = {"Cache-Control": f"max-age={ttl}"} if _HAS_CACHE else None
    
    async with limiter:
        return await client.post(url, json=json, timeout=timeout, headers=headers)


@atexit.register
def _close_all_clients() -> None:
    """Best effort cleanup on exit."""
    try:
        client = _CLIENT_CVAR.get()
        asyncio.run(client.aclose())
    except LookupError:
        # No client in this context
        pass
    except Exception:
        # Best effort cleanup - ignore errors
        pass


__all__ = ["aget", "apost"] 