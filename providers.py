from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List
import asyncio
from typing import Awaitable, Dict as _Dict, Callable as _Callable

# Fallback stub returning False when provider module missing

def _safe_import_check(module_name: str, attr: str = "check"):
    try:
        mod = __import__(module_name)
        return getattr(mod, attr)
    except Exception:  # pragma: no cover
        return lambda _: False

# Rebuild PROVIDERS dict using safe imports
PROVIDERS: Dict[str, Callable[[str], bool]] = {
    "VirusTotal":      _safe_import_check("virustotal_api"),
    "AbuseIPDB":       _safe_import_check("abuseipdb_api"),
    "AlienVault OTX":  _safe_import_check("otx_api"),
    "ThreatFox":       _safe_import_check("threatfox_api"),
    "GreyNoise":       _safe_import_check("greynoise_api"),
}

THREADS: int = min(5, len(PROVIDERS))  # cap threads to avoid oversubscription


def scan(ioc: str) -> Dict[str, bool]:
    """Return per-provider verdicts for one IOC."""
    verdicts: Dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        fut_map = {pool.submit(fn, ioc): name for name, fn in PROVIDERS.items()}
        for fut in as_completed(fut_map):
            verdicts[fut_map[fut]] = bool(fut.result())
    return verdicts

# ---------------------------
# Async implementation
# ---------------------------

def _safe_import_check_async(module_name: str, attr: str = "check_async"):
    """Attempt to import *attr* from *module_name* – return stub on failure."""
    try:
        mod = __import__(module_name)
        return getattr(mod, attr)
    except Exception:  # pragma: no cover
        async def _stub(_):
            return False
        return _stub


# Coroutines used by *scan_async*
PROVIDERS_ASYNC: _Dict[str, _Callable[[str], Awaitable[bool]]] = {
    "VirusTotal":      _safe_import_check_async("virustotal_api"),
    "AbuseIPDB":       _safe_import_check_async("abuseipdb_api"),
    "AlienVault OTX":  _safe_import_check_async("otx_api"),
    "ThreatFox":       _safe_import_check_async("threatfox_api"),
    "GreyNoise":       _safe_import_check_async("greynoise_api"),
}


async def scan_async(ioc: str) -> _Dict[str, bool]:
    """Return per-provider verdicts concurrently using *asyncio* coroutines."""
    # Spawn one task per provider while keeping track of the names.
    names: list[str] = []
    coros: list[Awaitable[bool]] = []
    for name, fn in PROVIDERS_ASYNC.items():
        names.append(name)
        coros.append(fn(ioc))

    results = await asyncio.gather(*coros, return_exceptions=False)
    return {name: bool(res) for name, res in zip(names, results)} 