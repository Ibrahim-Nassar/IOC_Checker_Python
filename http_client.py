"""
Shared asynchronous HTTP client utilities for networked providers.

Features:
- Single shared httpx.AsyncClient with sane timeouts
- Optional global rate limiting via aiolimiter (disabled by default)
- Robust retry with exponential backoff and jitter on transient errors

This module exposes a single high-level helper: async_request().
"""
from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Optional

import httpx

try:
    from aiolimiter import AsyncLimiter  # type: ignore
except Exception:  # pragma: no cover - optional dependency guard
    AsyncLimiter = None  # type: ignore[misc,assignment]

from .settings import settings

log = logging.getLogger("http_client")


# Global async client (lazy)
_client: Optional[httpx.AsyncClient] = None
_client_lock = asyncio.Lock()


def _build_timeout(default_seconds: float) -> httpx.Timeout:
    # Separate connect/read/write with a generous connect window
    connect_timeout = min(10.0, max(1.0, default_seconds))
    read_timeout = default_seconds
    write_timeout = default_seconds
    return httpx.Timeout(connect=connect_timeout, read=read_timeout, write=write_timeout)


async def get_async_client() -> httpx.AsyncClient:
    """Return a shared AsyncClient instance.

    The client is created lazily and reused across requests to leverage
    connection pooling. It should not be closed by callers.
    """
    global _client
    if _client is not None:
        return _client

    async with _client_lock:
        if _client is None:
            timeout = _build_timeout(settings.HTTP_DEFAULT_TIMEOUT)
            _client = httpx.AsyncClient(timeout=timeout, http2=True)
    return _client

async def close_async_client() -> None:
    """Close the shared AsyncClient if it exists."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


# Optional global rate limiter (requests per second). 0 disables limiting.
_limiter: Any
if getattr(settings, "HTTP_RPS_LIMIT", 0.0) and AsyncLimiter is not None:
    # At most N requests per second globally
    _limiter = AsyncLimiter(max_rate=max(0.1, float(settings.HTTP_RPS_LIMIT)), time_period=1.0)
else:
    # No-op async context manager
    class _NoopLimiter:
        async def __aenter__(self) -> None:  # noqa: D401 - trivial
            return None

        async def __aexit__(self, *exc_info: Any) -> None:
            return None

    _limiter = _NoopLimiter()


class TransientHTTPStatus(Exception):
    """Raised internally to signal that a retryable status was encountered."""

    def __init__(self, status_code: int, message: str = "") -> None:
        super().__init__(f"HTTP {status_code}{': ' + message if message else ''}")
        self.status_code = status_code


def _should_retry_status(status_code: int) -> bool:
    # Retry on 429 and 5xx
    return status_code == 429 or 500 <= status_code < 600


def _compute_backoff(attempt: int, base: float, cap: float) -> float:
    # Exponential backoff with jitter
    expo = base * (2 ** attempt)
    delay = min(cap, expo)
    jitter = random.uniform(0.0, base)
    return max(0.0, delay + jitter)


async def async_request(
    method: str,
    url: str,
    *,
    headers: Optional[dict[str, str]] = None,
    json: Optional[dict[str, Any]] = None,
    timeout: Optional[float] = None,
    retries: Optional[int] = None,
) -> httpx.Response:
    """Perform an HTTP request with retries, timeouts, and optional rate limiting.

    Returns the final httpx.Response if successful (status 2xx or 404/403/etc.).
    Retries are applied for transient statuses (429/5xx) and selected exceptions.
    Non-transient non-2xx statuses are returned without retry to let callers
    handle domain-specific semantics.
    """
    client = await get_async_client()

    max_retries = settings.HTTP_MAX_RETRIES if retries is None else retries
    default_timeout = settings.HTTP_DEFAULT_TIMEOUT if timeout is None else timeout
    backoff_base = settings.HTTP_BACKOFF_BASE
    backoff_cap = settings.HTTP_BACKOFF_CAP

    attempt = 0
    last_exc: Optional[BaseException] = None
    while True:
        try:
            async with _limiter:
                resp = await client.request(
                    method=method.upper(),
                    url=url,
                    headers=headers,
                    json=json,
                    timeout=_build_timeout(default_timeout),
                )

            # Retry on explicitly transient statuses
            if _should_retry_status(resp.status_code):
                raise TransientHTTPStatus(resp.status_code)

            return resp

        except (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.RemoteProtocolError, httpx.TransportError, TransientHTTPStatus) as exc:  # noqa: E501
            last_exc = exc
            if attempt >= max_retries:
                break

            delay = _compute_backoff(attempt, backoff_base, backoff_cap)
            log.warning("HTTP retry %s for %s %s in %.2fs (%s)", attempt + 1, method.upper(), url, delay, exc)
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                raise
            attempt += 1

    assert last_exc is not None
    raise last_exc


__all__ = [
    "async_request",
    "get_async_client",
    "close_async_client",
]


