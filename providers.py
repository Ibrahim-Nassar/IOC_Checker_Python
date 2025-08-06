"""
Provider registry for IOC_Checker using the unified provider interface.
"""
from __future__ import annotations

import threading

_prov_classes = []

try:
    from virustotal_api import VirusTotalProvider
    _prov_classes.append(VirusTotalProvider)
except ImportError:
    pass

try:
    from otx_api import OTXProvider
    _prov_classes.append(OTXProvider)
except ImportError:
    pass

try:
    from abuseipdb_api import AbuseIPDBProvider
    _prov_classes.append(AbuseIPDBProvider)
except ImportError:
    pass

# Make PROV_CLASSES an immutable tuple
PROV_CLASSES = tuple(_prov_classes)

# Backward compatibility alias
PROVIDERS = PROV_CLASSES

# Cache for instantiated providers
_instances: list | None = None
_lock = threading.Lock()

def get_providers() -> list:
    """Return instantiated provider objects from available provider classes."""
    global _instances
    if _instances is None:
        with _lock:
            if _instances is None:
                _instances = []
                for cls in PROV_CLASSES:
                    try:
                        _instances.append(cls())
                    except Exception as exc:
                        import logging
                        logging.warning("%s disabled: %s", cls.__name__, exc)
    return _instances

def refresh() -> None:
    """Reset the cached provider instances, forcing re-instantiation on next get_providers() call."""
    global _instances
    with _lock:
        _instances = None

__all__ = ["PROV_CLASSES", "get_providers", "PROVIDERS", "refresh"] 