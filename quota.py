from __future__ import annotations

import json
import os
import datetime as _dt
import tempfile
import shutil
from pathlib import Path
from typing import Dict

# Hard-coded daily limits – adjust as needed.
DAILY_LIMITS: Dict[str, int] = {
    "VirusTotal": 500,   # public API
    "AbuseIPDB": 1000,
    "GreyNoise": 50,     # community tier
}

# Storage location in the user's home directory
_QUOTA_FILE = Path(os.path.expanduser("~")) / ".ioc_checker_quota.json"


def _load() -> dict:
    if _QUOTA_FILE.exists():
        try:
            with _QUOTA_FILE.open("r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception:
            pass
    return {}


def _save(data: dict) -> None:
    """Atomically save quota data to prevent corruption during concurrent access."""
    try:
        # Write to temporary file first
        with tempfile.NamedTemporaryFile(
            mode="w", 
            encoding="utf-8", 
            dir=_QUOTA_FILE.parent,
            delete=False,
            suffix=".tmp"
        ) as tmp_file:
            json.dump(data, tmp_file)
            tmp_filename = tmp_file.name
        
        # Atomically replace the original file
        shutil.move(tmp_filename, _QUOTA_FILE)
    except Exception:
        # Clean up temp file if something went wrong
        try:
            if 'tmp_filename' in locals():
                os.unlink(tmp_filename)
        except Exception:
            pass  # best effort cleanup


def _today_key() -> str:
    return _dt.date.today().isoformat()


def increment(provider: str, count: int = 1) -> None:
    """Increment the usage counter for *provider* by *count* today."""
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

__all__ = ["increment", "remaining", "DAILY_LIMITS"] 