from __future__ import annotations

import json, pathlib, os, contextlib, time
from filelock import FileLock
import datetime as _dt
from typing import Dict

# Hard-coded daily limits – adjust as needed.
DAILY_LIMITS: Dict[str, int] = {
    "VirusTotal": 500,   # public API
    "AbuseIPDB": 1000,
    "GreyNoise": 50,     # community tier
}

_PATH = pathlib.Path.home() / ".ioc_checker_quota.json"
_LOCK = FileLock(str(_PATH) + ".lock")

def _load() -> dict:
    if not _PATH.exists():
        return {}
    with _PATH.open() as fh:
        return json.load(fh)

def _save(data: dict) -> None:
    tmp = _PATH.with_suffix(".tmp")
    with tmp.open("w") as fh:
        json.dump(data, fh)
    tmp.replace(_PATH)

def increment(key: str, amount: int = 1) -> None:
    with _LOCK:
        data = _load()
        data[key] = data.get(key, 0) + amount
        _save(data)

def _today_key() -> str:
    return _dt.date.today().isoformat()

def increment_provider(provider: str, count: int = 1) -> None:
    """Increment the usage counter for *provider* by *count* today."""
    with _LOCK:
        data = _load()
        today = _today_key()
        day_data = data.setdefault(today, {})
        day_data[provider] = day_data.get(provider, 0) + count
        _save(data)

def remaining(provider: str) -> str:
    """Return a human-readable string with remaining calls or "n/a"."""
    limit = DAILY_LIMITS.get(provider)
    if limit is None:
        return "n/a"
    data = _load().get(_today_key(), {})
    used = data.get(provider, 0)
    return str(max(limit - used, 0))

__all__ = ["increment", "increment_provider", "remaining", "DAILY_LIMITS"] 