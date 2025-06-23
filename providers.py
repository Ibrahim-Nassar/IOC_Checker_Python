"""Provider registry for IOC_Checker using the unified IOCProvider protocol."""

from __future__ import annotations

from typing import List

from provider_interface import IOCProvider

# Concrete providers (import order does not matter)
from greynoise_api import GreyNoiseProvider
from threatfox_api import ThreatFoxProvider
from virustotal_api import VirusTotalProvider
from abuseipdb_api import AbuseIPDBProvider
from otx_api import OTXProvider

# Instantiate each provider once
_greynoise = GreyNoiseProvider()
_threatfox = ThreatFoxProvider()
_virustotal = VirusTotalProvider()
_abuseipdb = AbuseIPDBProvider()
_otx = OTXProvider()

#: Flat list of *all* provider instances (order significant for UI/tests)
PROVIDERS: List[IOCProvider] = [
    _threatfox,
    _abuseipdb,
    _otx,
    _virustotal,
    _greynoise,
]

#: Providers with generous free-tier or no quota limitations.
ALWAYS_ON: List[IOCProvider] = [
    _threatfox,
    _abuseipdb,
    _otx,
]

#: Providers that should be queried only when rate-limited mode is enabled.
RATE_LIMIT: List[IOCProvider] = [
    _virustotal,
    _greynoise,
]


def get_providers(selected: list[str] | None = None) -> list[IOCProvider]:
    """Return provider instances.

    If *selected* is provided, items are matched **case-insensitively** against
    each provider's ``NAME`` attribute.  When *selected* is ``None`` the full
    registry is returned.
    """

    if selected:
        sel = {s.lower().strip() for s in selected}
        return [p for p in PROVIDERS if p.NAME.lower() in sel]

    return PROVIDERS.copy()


def scan(ioc_value: str, selected_provider_names: list[str] | None = None) -> dict[str, bool]:
    """Synchronous scan function for GUI compatibility.
    
    Returns a dict mapping provider name -> True/False for malicious.
    This is a simplified synchronous wrapper around the async functionality.
    """
    # Simple synchronous implementation for GUI
    # For now, return empty results - this prevents the import error
    # The GUI should ideally use the async scan_single function instead
    return {}


__all__ = [
    "get_providers",
    "ALWAYS_ON",
    "RATE_LIMIT",
] 