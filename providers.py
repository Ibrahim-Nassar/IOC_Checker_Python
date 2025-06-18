from __future__ import annotations
import asyncio
from typing import Callable, List, Dict, Any

# ────────── fallback checkers ──────────
# Each provider checker should return True if the IOC is malicious / flagged,
# otherwise False.  When the real implementation is missing we fall back to a
# stub that always returns False (clean) so the overall application continues
# to work instead of crashing with ImportError.

def _stub_checker(_: str) -> bool:
    """Default checker that always returns *False* (benign)."""
    return False

# Attempt to import real checker functions if they exist locally.  These are
# extremely small wrappers so we keep the try/except minimal and fall back to
# the stub without raising.
try:
    from threatfox_api import check as _threatfox_check
except ImportError:  # pragma: no cover
    _threatfox_check = _stub_checker

try:
    from greynoise_api import check as _greynoise_check
except ImportError:  # pragma: no cover
    _greynoise_check = _stub_checker

try:
    from virustotal_api import check as _virustotal_check
except ImportError:  # pragma: no cover
    _virustotal_check = _stub_checker

try:
    from abuseipdb_api import check as _abuseipdb_check
except ImportError:  # pragma: no cover
    _abuseipdb_check = _stub_checker

try:
    from otx_api import check as _otx_check
except ImportError:  # pragma: no cover
    _otx_check = _stub_checker


# ────────── provider class ──────────
class Provider:
    """Minimal async wrapper around a synchronous provider *check* function.

    The rest of the application expects each provider object to expose:
    • *name* – unique identifier used in GUI and CLI (lower-case)
    • *ioc_kinds* – list of IOC types the provider supports
    • *query()* – *async* method returning a normalised dict with at least
      ``status`` and ``score`` keys.  ``ioc_checker._query`` awaits this
      method for each provider concurrently.
    """

    def __init__(self, name: str, checker: Callable[[str], bool], ioc_kinds: List[str]):
        self.name = name.lower()
        self._checker = checker
        self.ioc_kinds = ioc_kinds

    # The *session* argument is kept for API-compatibility although none of the
    # simple checker functions make use of it.  This allows swapping in more
    # sophisticated async implementations in the future without touching the
    # call-site.
    async def query(self, session, typ: str, val: str) -> Dict[str, Any]:  # noqa: D401, pylint: disable=unused-argument
        """Async wrapper calling the checker inside a thread pool."""
        if typ not in self.ioc_kinds:
            return {"status": "n/a", "score": 0}

        try:
            malicious: bool = await asyncio.to_thread(self._checker, val)
            status = "malicious" if malicious else "clean"
            score = 100 if malicious else 0
            return {"status": status, "score": score}
        except Exception as exc:  # pragma: no cover
            # Never let an exception propagate – convert to an *error* status so
            # the rest of the pipeline can continue gracefully.
            return {"status": "error", "score": 0, "raw": f"error: {exc}"}


# ────────── concrete provider instances ──────────
_VIRUSTOTAL = Provider("virustotal", _virustotal_check, ["ip", "domain", "url", "hash"])
_ABUSEIPDB  = Provider("abuseipdb",  _abuseipdb_check,  ["ip"])
_OTX        = Provider("otx",        _otx_check,        ["ip", "domain", "url", "hash"])
_THREATFOX  = Provider("threatfox",  _threatfox_check,  ["ip", "domain", "url", "hash"])
_GREYNOISE  = Provider("greynoise",  _greynoise_check,  ["ip"])

# Providers that are inexpensive / key-less and can be queried every time
ALWAYS_ON: List[Provider] = [_VIRUSTOTAL, _ABUSEIPDB]

# Providers that might be subject to stricter rate-limits or require optional
# API keys.  They are only queried when the *rate* flag is used.
RATE_LIMIT: List[Provider] = [_THREATFOX, _GREYNOISE, _OTX]

# Convenience mapping by provider name for quick look-ups.
PROVIDERS: Dict[str, Provider] = {p.name: p for p in ALWAYS_ON + RATE_LIMIT}

# ────────── helper(s) used by other modules ──────────
def _extract_ip(v: str) -> str:
    """Return the address portion of *v* without any port information.

    Examples
    --------
    >>> _extract_ip('1.2.3.4:443')
    '1.2.3.4'
    >>> _extract_ip('[2606:4700:4700::1111]:53')
    '2606:4700:4700::1111'
    """
    if v.startswith('[') and ']:' in v:  # IPv6 in brackets "[::1]:443"
        return v.split(']:')[0][1:]
    if ':' in v and v.count(':') == 1 and not v.startswith('http'):
        # Simple IPv4 with port "1.2.3.4:80"
        return v.split(':')[0]
    return v.strip()
