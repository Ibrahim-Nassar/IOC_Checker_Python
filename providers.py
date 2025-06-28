"""
Provider registry for IOC_Checker using the unified provider interface.
"""
from __future__ import annotations

import threading

PROV_CLASSES = []

try:
    from virustotal_api import VirusTotalProvider
    PROV_CLASSES.append(VirusTotalProvider)
except ImportError:
    pass

try:
    from otx_api import OTXProvider
    PROV_CLASSES.append(OTXProvider)
except ImportError:
    pass

try:
    from abuseipdb_api import AbuseIPDBProvider
    PROV_CLASSES.append(AbuseIPDBProvider)
except ImportError:
    pass

try:
    from threatfox_api import ThreatFoxProvider
    PROV_CLASSES.append(ThreatFoxProvider)
except ImportError:
    pass

try:
    from greynoise_api import GreyNoiseProvider
    PROV_CLASSES.append(GreyNoiseProvider)
except ImportError:
    pass

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


__all__ = ["PROV_CLASSES", "get_providers", "PROVIDERS"] 