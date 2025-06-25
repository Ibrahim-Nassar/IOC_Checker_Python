"""
Provider registry for IOC_Checker using the unified provider interface.
"""
from __future__ import annotations

from typing import Dict

PROVIDERS = []

try:
    from virustotal_api import VirusTotalProvider
    PROVIDERS.append(VirusTotalProvider)
except ImportError:
    pass

try:
    from otx_api import OTXProvider
    PROVIDERS.append(OTXProvider)
except ImportError:
    pass

try:
    from abuseipdb_api import AbuseIPDBProvider
    PROVIDERS.append(AbuseIPDBProvider)
except ImportError:
    pass

try:
    from threatfox_api import ThreatFoxProvider
    PROVIDERS.append(ThreatFoxProvider)
except ImportError:
    pass

try:
    from greynoise_api import GreyNoiseProvider
    PROVIDERS.append(GreyNoiseProvider)
except ImportError:
    pass


def get_provider_map() -> Dict[str, type]:
    """Return a mapping of provider NAME to provider class for quick lookups."""
    provider_map = {}
    for provider_class in PROVIDERS:
        try:
            provider_map[provider_class.NAME] = provider_class
        except AttributeError:
            pass
    return provider_map


def get_providers(selected: list[str] | None = None) -> list:
    """Return provider instances.
    
    If selected is provided, items are matched case-insensitively against
    each provider's NAME attribute. When selected is None the full
    registry is returned.
    """
    available_providers = []
    
    for provider_class in PROVIDERS:
        try:
            provider_instance = provider_class()
            available_providers.append(provider_instance)
        except Exception:
            continue
    
    if selected:
        sel = {s.lower().strip() for s in selected}
        return [p for p in available_providers if hasattr(p, 'NAME') and p.NAME.lower() in sel]
    
    return available_providers


__all__ = ["PROVIDERS", "get_provider_map"] 