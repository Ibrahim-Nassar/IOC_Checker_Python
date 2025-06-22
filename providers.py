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


def get_providers(selected: List[str] | None = None) -> List[IOCProvider]:
    """Return active provider instances.

    Parameters
    ----------
    selected : list[str] | None
        Optional case-insensitive list of provider ``NAME`` values to include.
        ``None`` means all providers (``PROVIDERS``).
    """
    if not selected:
        return list(PROVIDERS)

    sel = {s.lower() for s in selected}
    return [p for p in PROVIDERS if p.NAME.lower() in sel]


__all__ = [
    "get_providers",
    "ALWAYS_ON",
    "RATE_LIMIT",
] 