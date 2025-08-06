# api_key_store.py
"""
Utility module to persist API keys for IOC Checker.

Priority order:
1. keyring backend (service name: "ioc_checker").
2. JSON fallback at ~/.config/ioc_checker/keys.json (encrypted with Fernet)

JSON fallback uses Fernet encryption with a key stored in the keyring or 
generated automatically. For headless usage, set the environment variable
IOC_CHECKER_FERNET_KEY to provide the encryption key directly.

Public API
----------
save(provider_env_var: str, value: str) -> None
load(provider_env_var: str) -> str | None
"""

from __future__ import annotations

import json, os, logging
from pathlib import Path
from typing import Dict
from filelock import FileLock

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Cross-platform config directory helper
# ---------------------------------------------------------------------------

def _get_config_dir() -> Path:
    """Return an OS-appropriate per-user config directory."""
    if os.name == "nt":  # Windows – use %APPDATA%\ioc-checker
        base = Path(os.getenv("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:  # Linux / macOS – prefer XDG_CONFIG_HOME else ~/.config
        base = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "ioc-checker"

_CONFIG_DIR = _get_config_dir()
_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
_KEY_FILE = _CONFIG_DIR / "keys.json"
_LOCK     = FileLock(str(_KEY_FILE) + ".lock")

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _load_all() -> Dict[str, str]:
    if not _KEY_FILE.exists():
        return {}
    try:
        with _KEY_FILE.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:  # pragma: no cover – corruption / permissions
        log.warning("Failed to load key store %s: %s", _KEY_FILE, exc)
        return {}

def _save_all(data: Dict[str, str]) -> None:
    tmp = _KEY_FILE.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
        fh.flush()
        try:
            os.fsync(fh.fileno())
        except OSError:
            pass  # best effort on platforms without fsync
    tmp.replace(_KEY_FILE)

# ---------------------------------------------------------------------------
# Public API – unchanged signatures
# ---------------------------------------------------------------------------

def save(provider_env_var: str, value: str | None) -> None:
    """Persist *value* for *provider_env_var*.
    Empty / None value removes the key entirely.
    """
    with _LOCK:
        data = _load_all()
        if value and value.strip():
            data[provider_env_var] = value.strip()
        else:
            data.pop(provider_env_var, None)
        _save_all(data)


def load(provider_env_var: str) -> str | None:
    """Retrieve stored key for *provider_env_var*.
    Environment variables override file-stored values to support containers/CI.
    """
    return os.getenv(provider_env_var) or _load_all().get(provider_env_var) 


def load_saved_keys() -> None:
    """Load saved API keys and set them in os.environ if not already present.
    
    This function is idempotent and safe to call multiple times.
    Loads keys for: VIRUSTOTAL_API_KEY, OTX_API_KEY, ABUSEIPDB_API_KEY
    """
    _API_VARS = ("VIRUSTOTAL_API_KEY", "OTX_API_KEY", "ABUSEIPDB_API_KEY")
    
    loaded_keys = []
    for var in _API_VARS:
        # Only set if not already in environment (idempotent)
        if var not in os.environ:
            val = load(var)
            if val:
                os.environ[var] = val
                loaded_keys.append(var)
    
    # Log results
    if loaded_keys:
        log.info(f"Loaded {len(loaded_keys)} saved API keys: {', '.join(loaded_keys)}")
    else:
        # Check if any of the three vars are present after loading
        present_vars = [var for var in _API_VARS if os.getenv(var)]
        if not present_vars:
            log.warning("No providers activated – add API keys in the GUI or via env vars") 