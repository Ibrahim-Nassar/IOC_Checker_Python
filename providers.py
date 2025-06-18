from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Dict, List

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