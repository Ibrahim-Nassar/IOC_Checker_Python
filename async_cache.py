"""Async HTTP helper with caching and rate limiting, mirroring cache.py but using httpx.AsyncClient."""
from __future__ import annotations

import asyncio
import os
# Note: Removed automatic WindowsSelectorEventLoopPolicy override 
# to avoid breaking subprocess support and user's event loop choice

import atexit
import collections
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

# Per-loop client storage to avoid "attached to different loop" errors
_LOOP_CLIENTS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, tuple[httpx.AsyncClient, asyncio.AbstractEventLoop]] = weakref.WeakKeyDictionary()

_LIMITERS: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, collections.OrderedDict[str, AsyncLimiter]] = weakref.WeakKeyDictionary()
_LIM_LOCK = threading.Lock()
_CLIENT_LOCK = threading.Lock()


def _get_client() -> httpx.AsyncClient:
    """Get or create AsyncClient for the current loop only."""
    
    with _CLIENT_LOCK:
        # Must have a running event loop
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            raise RuntimeError("AsyncClient requires a running event loop")
        
        # Check if we have a client for this loop
        if loop in _LOOP_CLIENTS:
            client, orig_loop = _LOOP_CLIENTS[loop]
            if not client.is_closed and orig_loop == loop:
                return client
            else:
                # Client is closed or loop mismatch, remove it from the cache
                del _LOOP_CLIENTS[loop]
        
        # Create a new client for this loop
        if _HAS_CACHE and _FILE_CACHE is not None:
            client = AsyncClient(cache=_FILE_CACHE, timeout=15.0)
        else:
            client = httpx.AsyncClient(timeout=15.0)
        
        # Store client with its originating loop
        _LOOP_CLIENTS[loop] = (client, loop)
        return client


def _get_limiter(api_key: str | None) -> AsyncLimiter:
    key = api_key or "anonymous"
    loop = asyncio.get_running_loop()
    with _LIM_LOCK:
        per_loop = _LIMITERS.setdefault(loop, collections.OrderedDict())
        if key not in per_loop:
            per_loop[key] = AsyncLimiter(4, 60)
            # LRU eviction: keep only 32 most recent limiters
            while len(per_loop) > 32:
                per_loop.popitem(last=False)
        else:
            # Move to end (most recently used)
            per_loop.move_to_end(key)
        return per_loop[key]


async def aget(url: str, *, timeout: float = 15.0, ttl: int = 900, api_key: str | None = None, headers: dict | None = None) -> httpx.Response:
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


async def apost(url: str, json: dict, *, timeout: float = 5.0, ttl: int = 900, api_key: str | None = None, headers: dict | None = None) -> httpx.Response:
    """Async POST with caching and rate limiting."""
    client = _get_client()
    limiter = _get_limiter(api_key)
    
    # Add cache control headers if caching is available
    if _HAS_CACHE and headers is None:
        headers = {}
    if _HAS_CACHE and headers is not None:
        headers = headers.copy()
        headers["Cache-Control"] = f"max-age={ttl}"
    
    async with limiter:
        return await client.post(url, json=json, timeout=timeout, headers=headers)


@atexit.register
def _close_all_clients() -> None:
    """Best effort cleanup on exit."""
    
    # Close all per-loop clients
    for client, orig_loop in list(_LOOP_CLIENTS.values()):
        if client and not client.is_closed:
            try:
                # Try to get current running loop
                current_loop = asyncio.get_running_loop()
                
                # If client's original loop matches current loop and loop is not closed
                if orig_loop == current_loop and not orig_loop.is_closed():
                    # Schedule cleanup in the existing loop
                    current_loop.create_task(client.aclose())
                else:
                    # Different loop or closed loop, use asyncio.run
                    asyncio.run(client.aclose())
            except RuntimeError:
                # No loop running, use asyncio.run for cleanup
                try:
                    asyncio.run(client.aclose())
                except Exception:
                    pass  # Best effort cleanup


__all__ = ["aget", "apost"] 