from __future__ import annotations

import json, pathlib, os, contextlib, time
from filelock import FileLock
import datetime as _dt
from typing import Dict

# Hard-coded daily limits – adjust as needed.
DAILY_LIMITS: Dict[str, int] = {
    "VirusTotal": 500,   # public API
    "AbuseIPDB": 1000,
}

_PATH = pathlib.Path.home() / ".ioc_checker_quota.json"
_LOCK = FileLock(str(_PATH) + ".lock")

def _load() -> dict:
    if not _PATH.exists():
        return {}
    try:
        with _PATH.open() as fh:
            content = fh.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except (json.JSONDecodeError, OSError):
        # Handle corrupt or empty JSON by returning empty dict
        return {}

def _save(data: dict) -> None:
    with _LOCK:
        temp_path = _PATH.with_suffix('.tmp')
        with open(temp_path, "w") as fh:
            json.dump(data, fh)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except (AttributeError, OSError) as e:
                # Cross-platform safety: some systems don't support fsync
                import logging
                logging.debug(f"fsync not supported or failed: {e}")
        temp_path.replace(_PATH)

def increment(key: str, amount: int = 1) -> None:
    """Deprecated: Use increment_provider() instead for consistent date-scoped tracking."""
    import warnings
    warnings.warn("increment() is deprecated, use increment_provider() instead", 
                  DeprecationWarning, stacklevel=2)
    # Convert to date-scoped format to avoid data structure collision
    with _LOCK:
        data = _load()
        today = _today_key()
        day_data = data.setdefault(today, {})
        day_data[key] = day_data.get(key, 0) + amount
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
    
    with _LOCK:
        data = _load()
        today_data = data.get(_today_key(), {})
        used = today_data.get(provider, 0)
        return str(max(limit - used, 0))

__all__ = ["increment", "increment_provider", "remaining", "DAILY_LIMITS"] 