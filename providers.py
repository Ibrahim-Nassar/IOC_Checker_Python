"""Provider registry for IOC_Checker using the unified IOCProvider protocol."""

from __future__ import annotations

from typing import List, Any, Dict

from provider_interface import IOCProvider

# Concrete providers (import order does not matter)
try:
    from greynoise_api import GreyNoiseProvider
    from threatfox_api import ThreatFoxProvider
    from otx_api import OTXProvider
    from virustotal_api import VirusTotalProvider
    from abuseipdb_api import AbuseIPDBProvider
    
    _greynoise = GreyNoiseProvider()
    _threatfox = ThreatFoxProvider()
    _otx = OTXProvider()
    _virustotal = VirusTotalProvider()
    _abuseipdb = AbuseIPDBProvider()
    
except ImportError as e:
    print(f"Error: Failed to import providers: {e}")
    _greynoise = None
    _threatfox = None
    _otx = None
    _virustotal = None
    _abuseipdb = None

#: Map of provider name -> provider instance (insertion order preserved)
_ORDERED_PROVIDERS = [
    _threatfox,
    _abuseipdb,
    _otx,
    _virustotal,
    _greynoise,
]
PROVIDERS: Dict[str, Any] = {
    p.NAME: p for p in _ORDERED_PROVIDERS if p is not None
}

#: Providers with generous free-tier or no quota limitations.
ALWAYS_ON: List[Any] = [p for p in [
    _threatfox,
    _abuseipdb,
    _otx,
] if p is not None]

#: Providers that should be queried only when rate-limited mode is enabled.
RATE_LIMIT: List[Any] = [p for p in [
    _virustotal,
    _greynoise,
] if p is not None]


def get_providers(selected: list[str] | None = None) -> list[IOCProvider]:
    """Return provider instances.

    If *selected* is provided, items are matched **case-insensitively** against
    each provider's ``NAME`` attribute.  When *selected* is ``None`` the full
    registry is returned.
    """

    if selected:
        sel = {s.lower().strip() for s in selected}
        return [p for name, p in PROVIDERS.items() if name.lower() in sel]

    return list(PROVIDERS.values())


def scan(ioc_value: str, selected_provider_names: list[str] | None = None) -> dict[str, bool]:
    """Synchronous scan function for GUI compatibility.

    Each provider entry may either be an :class:`IOCProvider` instance or any
    callable accepting a single IOC value.  The return value is a mapping of
    provider name to a boolean malicious flag.  Any exception from a provider is
    coerced to ``False`` so that a single failure does not break the whole
    result map.
    """

    target_names = selected_provider_names or list(PROVIDERS.keys())
    results: Dict[str, bool] = {}

    for name in target_names:
        prov = PROVIDERS.get(name)
        if prov is None:
            continue
        try:
            if isinstance(prov, IOCProvider):
                out = prov.query_ioc("ip", ioc_value)
                results[name] = bool(out.score and out.score > 0)
            else:
                # Support simple callables for test injection
                results[name] = bool(prov(ioc_value))
        except Exception:
            results[name] = False

    return results


__all__ = [
    "get_providers",
    "ALWAYS_ON",
    "RATE_LIMIT",
] 