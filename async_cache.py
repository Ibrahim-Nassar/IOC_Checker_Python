"""Async HTTP helper with caching and rate limiting, mirroring cache.py but using httpx.AsyncClient."""
from __future__ import annotations

import asyncio
import os
if os.name == "nt":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import atexit
from collections import defaultdict
from pathlib import Path

import httpx
from aiolimiter import AsyncLimiter
from httpx_cache import AsyncClient, FileCache

# Use proper user cache directory
CACHE_DIR = Path(os.getenv("XDG_CACHE_HOME", Path.home() / ".cache")) / "ioc_checker"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

_CLIENT = AsyncClient(
    cache=FileCache(str(CACHE_DIR / "async_cache")),
    timeout=5.0,
)

_LIMITERS: dict[str, AsyncLimiter] = defaultdict(lambda: AsyncLimiter(4, 60))


def _get_limiter(api_key: str | None) -> AsyncLimiter:
    return _LIMITERS[api_key or "anonymous"]


async def aget(url: str, *, timeout: float = 5.0, ttl: int = 900, api_key: str | None = None, headers: dict | None = None) -> httpx.Response:
    """Async GET with caching and rate limiting. Falls back to sync cache.get if not in async context."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        from cache import get as sync_get
        return sync_get(url, timeout=timeout, ttl=ttl, headers=headers)
    
    limiter = _get_limiter(api_key)
    async with limiter:
        return await _CLIENT.get(url, timeout=timeout, headers=headers)


async def apost(url: str, json: dict, *, timeout: float = 5.0, ttl: int = 900, api_key: str | None = None) -> httpx.Response:
    """Async POST with caching and rate limiting. Falls back to sync cache.post if not in async context."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        from cache import post as sync_post
        return sync_post(url, json=json, timeout=timeout, ttl=ttl)
    
    limiter = _get_limiter(api_key)
    async with limiter:
        return await _CLIENT.post(url, json=json, timeout=timeout)


@atexit.register
def _close_async_resources() -> None:
    try:
        asyncio.run(_CLIENT.aclose())
    except RuntimeError:
        # Loop already closed – ignore
        pass


__all__ = ["aget", "apost", "CLIENT"] 