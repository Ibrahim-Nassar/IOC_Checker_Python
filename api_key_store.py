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

import json
import logging
import os
from pathlib import Path
from typing import Dict, Optional

# Encryption support
try:
    from cryptography.fernet import Fernet
    _HAS_FERNET = True
except ImportError:
    logging.warning("cryptography not available - encryption disabled. Install with: pip install cryptography")
    _HAS_FERNET = False
    Fernet = None

SERVICE_NAME = "ioc_checker"
ENCRYPTION_KEY_NAME = "ioc_checker_fernet_key"

# ---------------------------------------------------------------------------
# Optional keyring backend
# ---------------------------------------------------------------------------
try:
    import keyring  # type: ignore
    from keyring.errors import KeyringError  # type: ignore
    _KEYRING_AVAILABLE = True
except Exception as exc:  # pragma: no cover – import failure
    logging.warning("Keyring backend unavailable: %s", exc)
    keyring = None  # type: ignore
    KeyringError = Exception  # type: ignore
    _KEYRING_AVAILABLE = False

# ---------------------------------------------------------------------------
# Encryption key management
# ---------------------------------------------------------------------------
def _get_encryption_key() -> bytes | None:
    """Get or generate encryption key for JSON fallback."""
    if not _HAS_FERNET:
        return None
    
    # Try environment variable first (for headless usage)
    env_key = os.getenv("IOC_CHECKER_FERNET_KEY")
    if env_key:
        try:
            return env_key.encode('utf-8')
        except Exception:
            logging.warning("Invalid IOC_CHECKER_FERNET_KEY environment variable")
    
    # Try keyring first
    if _KEYRING_AVAILABLE:
        try:
            stored_key = keyring.get_password(SERVICE_NAME, ENCRYPTION_KEY_NAME)
            if stored_key:
                return stored_key.encode('utf-8')
        except KeyringError:
            pass
    
    # Check for existing key in a local file 
    key_file = _FALLBACK_DIR / ".encryption_key"
    if key_file.exists():
        try:
            with key_file.open("r", encoding="utf-8") as f:
                existing_key = f.read().strip().encode('utf-8')
                # Validate the key
                Fernet(existing_key)  # This will raise if invalid
                return existing_key
        except Exception:
            logging.warning("Existing encryption key file is invalid, generating new one")
    
    # Generate new key as last resort
    try:
        key = Fernet.generate_key()
        
        # Store in keyring if available
        if _KEYRING_AVAILABLE:
            try:
                keyring.set_password(SERVICE_NAME, ENCRYPTION_KEY_NAME, key.decode('utf-8'))
            except KeyringError:
                logging.warning("Failed to store encryption key in keyring")
        
        # Always store in local file as backup
        try:
            _ensure_fallback_dir()
            with key_file.open("w", encoding="utf-8") as f:
                f.write(key.decode('utf-8'))
            # Set restrictive permissions (Unix only)
            if os.name != "nt":
                try:
                    os.chmod(key_file, 0o600)
                except OSError:
                    pass
        except Exception as e:
            logging.warning(f"Failed to store encryption key to file: {e}")
        
        return key
    except Exception as e:
        logging.warning(f"Failed to generate encryption key: {e}")
        return None

def _encrypt_value(value: str) -> str:
    """Encrypt a value using Fernet."""
    if not _HAS_FERNET:
        return value
    
    key = _get_encryption_key()
    if not key:
        return value
    
    try:
        f = Fernet(key)
        encrypted = f.encrypt(value.encode('utf-8'))
        return encrypted.decode('utf-8')
    except Exception as e:
        logging.warning(f"Failed to encrypt value: {e}")
        return value

def _decrypt_value(encrypted_value: str) -> str | None:
    """Decrypt a value using Fernet."""
    if not _HAS_FERNET:
        return encrypted_value
    
    key = _get_encryption_key()
    if not key:
        return encrypted_value
    
    try:
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_value.encode('utf-8'))
        return decrypted.decode('utf-8')
    except Exception as e:
        logging.warning(f"Failed to decrypt value (key may have changed): {e}")
        return None

# ---------------------------------------------------------------------------
# JSON fallback storage (~/.config/ioc_checker/keys.json)
# ---------------------------------------------------------------------------
_FALLBACK_DIR = Path.home() / ".config" / SERVICE_NAME
_JSON_PATH = _FALLBACK_DIR / "keys.json"


def _ensure_fallback_dir() -> None:
    """Ensure the fallback directory exists."""
    _FALLBACK_DIR.mkdir(parents=True, exist_ok=True)


def _load_all_fallback() -> Dict[str, str]:
    """Load all stored keys from the fallback JSON file."""
    _ensure_fallback_dir()
    if not _JSON_PATH.exists():
        return {}

    try:
        with _JSON_PATH.open("r", encoding="utf-8") as fp:
            data = json.load(fp) or {}
            
            # If encryption is available, try to decrypt values
            if _HAS_FERNET:
                decrypted_data = {}
                for k, v in data.items():
                    decrypted = _decrypt_value(str(v))
                    if decrypted is not None:
                        decrypted_data[str(k)] = decrypted
                    else:
                        # If decryption fails, try treating as plain text (legacy fallback)
                        logging.warning(f"Failed to decrypt key {k}, treating as plain text")
                        decrypted_data[str(k)] = str(v)
                return decrypted_data
            else:
                # No encryption available, treat all as plain text
                return {str(k): str(v) for k, v in data.items()}
                
    except (json.JSONDecodeError, OSError):
        # Corrupted file – rename and start fresh.
        try:
            _JSON_PATH.rename(_JSON_PATH.with_suffix(".corrupt"))
        except OSError:
            pass
        return {}


def _save_all_fallback(data: Dict[str, str]) -> None:
    """Persist *data* atomically to the fallback JSON file."""
    try:
        _ensure_fallback_dir()
        
        # Create the file if it doesn't exist
        if not _JSON_PATH.exists():
            _JSON_PATH.touch(exist_ok=True)
            # Only set permissions on Unix-like systems
            if os.name != "nt":  # Skip chmod on Windows
                try:
                    os.chmod(_JSON_PATH, 0o600)
                except OSError:
                    logging.warning(f"Failed to set permissions on {_JSON_PATH}")
        
        # Encrypt values before saving
        encrypted_data = {}
        for k, v in data.items():
            if _HAS_FERNET:
                encrypted_data[k] = _encrypt_value(v)
            else:
                encrypted_data[k] = v
        
        tmp = _JSON_PATH.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fp:
            json.dump(encrypted_data, fp, indent=2)
            fp.flush()
            os.fsync(fp.fileno())
        
        # Set restrictive permissions on temp file (Unix only)
        if os.name != "nt":  # Skip chmod on Windows
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                logging.warning(f"Failed to set permissions on temp file")
        
        tmp.replace(_JSON_PATH)
        
        # Ensure final file also has correct permissions (Unix only)
        if os.name != "nt":  # Skip chmod on Windows
            try:
                os.chmod(_JSON_PATH, 0o600)
            except OSError:
                logging.warning(f"Failed to set final permissions on {_JSON_PATH}")
    
    except Exception as e:
        # Re-raise with more context for GUI error handling
        raise RuntimeError(f"Failed to save API keys to {_JSON_PATH}: {str(e)}") from e


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
__all__ = ["save", "load"]


def save(provider_env_var: str, value: str) -> None:
    """Persist an API *value* for *provider_env_var*.
    
    - Non-empty values are stored
    - Empty/blank values remove the stored key entirely
    - Atomic writes ensure data integrity
    """
    # Normalize the value (strip whitespace, treat empty as None)
    normalized_value = value.strip() if value else ""
    
    if _KEYRING_AVAILABLE:
        try:
            if normalized_value:
                keyring.set_password(SERVICE_NAME, provider_env_var, normalized_value)  # type: ignore[call-arg]
            else:
                # Remove the key from keyring when value is empty
                keyring.delete_password(SERVICE_NAME, provider_env_var)  # type: ignore[call-arg]
            return
        except KeyringError:
            pass  # fall through to JSON fallback for both set and delete operations

    # JSON fallback
    data = _load_all_fallback()
    if normalized_value:
        data[provider_env_var] = normalized_value
    else:
        # Remove key completely when clearing
        data.pop(provider_env_var, None)
    _save_all_fallback(data)


def load(provider_env_var: str) -> Optional[str]:
    """Retrieve the stored value or ``None`` if not found."""
    if _KEYRING_AVAILABLE:
        try:
            val = keyring.get_password(SERVICE_NAME, provider_env_var)  # type: ignore[call-arg]
            if val:
                return val
        except KeyringError:
            pass  # fall back

    return _load_all_fallback().get(provider_env_var) 