"""
Standalone synchronous HTTP helper with caching and retries.
"""
from __future__ import annotations

import threading
import atexit
from pathlib import Path
import os
import requests
import requests_cache
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

_retry_config = Retry(
    total=3,
    backoff_factor=0.3,
    status_forcelist=[500, 502, 503, 504]
)

# Use proper user cache directory
CACHE_DIR = Path(os.getenv("XDG_CACHE_HOME", Path.home() / ".cache")) / "ioc_checker"
CACHE_DIR.mkdir(parents=True, exist_ok=True)

_SESSION = requests_cache.CachedSession(
    cache_name=str(CACHE_DIR / "sync_cache"),
    backend='sqlite'
)

_SESSION.mount('http://', HTTPAdapter(max_retries=_retry_config))
_SESSION.mount('https://', HTTPAdapter(max_retries=_retry_config))

_SESSION_LOCK = threading.Lock()


@atexit.register
def _close_session():
    with _SESSION_LOCK:
        _SESSION.close()


def get(url: str, *, timeout: float = 5.0, ttl: int = 900) -> requests.Response:
    with _SESSION_LOCK:
        return _SESSION.get(url, timeout=timeout, expire_after=ttl)


def post(url: str, json: dict, *, timeout: float = 5.0, ttl: int = 900) -> requests.Response:
    with _SESSION_LOCK:
        return _SESSION.post(url, json=json, timeout=timeout, expire_after=ttl)


__all__ = ["get", "post"] 