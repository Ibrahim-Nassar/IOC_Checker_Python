# api_key_store.py
"""
Utility module to persist API keys for IOC Checker.

Priority order:
1. keyring backend (service name: "ioc_checker").
2. JSON fallback at ~/.config/ioc_checker/keys.json

Public API
----------
save(provider_env_var: str, value: str) -> None
load(provider_env_var: str) -> str | None
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Optional

SERVICE_NAME = "ioc_checker"

# ---------------------------------------------------------------------------
# Optional keyring backend
# ---------------------------------------------------------------------------
try:
    import keyring  # type: ignore
    from keyring.errors import KeyringError  # type: ignore
    _KEYRING_AVAILABLE = True
except Exception:  # pragma: no cover – import failure
    keyring = None  # type: ignore
    KeyringError = Exception  # type: ignore
    _KEYRING_AVAILABLE = False

# ---------------------------------------------------------------------------
# JSON fallback storage (~/.config/ioc_checker/keys.json)
# ---------------------------------------------------------------------------
_FALLBACK_DIR = Path.home() / ".config" / SERVICE_NAME
_FALLBACK_FILE = _FALLBACK_DIR / "keys.json"


def _ensure_fallback_dir() -> None:
    """Ensure the fallback directory exists."""
    _FALLBACK_DIR.mkdir(parents=True, exist_ok=True)


def _load_all_fallback() -> Dict[str, str]:
    """Load all stored keys from the fallback JSON file."""
    _ensure_fallback_dir()
    if not _FALLBACK_FILE.exists():
        return {}

    try:
        with _FALLBACK_FILE.open("r", encoding="utf-8") as fp:
            data = json.load(fp) or {}
            return {str(k): str(v) for k, v in data.items()}
    except (json.JSONDecodeError, OSError):
        # Corrupted file – rename and start fresh.
        try:
            _FALLBACK_FILE.rename(_FALLBACK_FILE.with_suffix(".corrupt"))
        except OSError:
            pass
        return {}


def _save_all_fallback(data: Dict[str, str]) -> None:
    """Persist *data* atomically to the fallback JSON file."""
    _ensure_fallback_dir()
    tmp = _FALLBACK_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2)
        fp.flush()
        os.fsync(fp.fileno())
    tmp.replace(_FALLBACK_FILE)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
__all__ = ["save", "load"]


def save(provider_env_var: str, value: str) -> None:
    """Persist an API *value* for *provider_env_var*."""
    if _KEYRING_AVAILABLE:
        try:
            keyring.set_password(SERVICE_NAME, provider_env_var, value)
            return
        except KeyringError:
            pass  # fall through to JSON fallback

    data = _load_all_fallback()
    if value:
        data[provider_env_var] = value
    else:
        data.pop(provider_env_var, None)
    _save_all_fallback(data)


def load(provider_env_var: str) -> Optional[str]:
    """Retrieve the stored value or ``None`` if not found."""
    if _KEYRING_AVAILABLE:
        try:
            val = keyring.get_password(SERVICE_NAME, provider_env_var)
            if val:
                return val
        except KeyringError:
            pass  # fall back

    return _load_all_fallback().get(provider_env_var) 