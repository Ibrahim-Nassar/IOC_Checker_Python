"""
Provider orchestrator with per-source scoring and simple quorum logic.
This version drops all allow-lists and whitelists.
"""
from typing import Dict, Iterable, Optional
try:
    from .quota import increment as _quota_inc  # when imported as package
except ImportError:  # pragma: no cover – fallback for direct script execution
    from IOC_Checker_Python.quota import increment as _quota_inc

# ------------------------------------------------------------------
# Helper: import provider.check or fall back to stub returning defaults
# ------------------------------------------------------------------

def _import_or_stub(module_name: str, default):
    try:
        mod = __import__(module_name)
        return getattr(mod, "check")
    except Exception:   # pragma: no cover – missing provider or attr
        return lambda _ioc: default

# Provider specific check functions (or stubs)
vt     = _import_or_stub("virustotal_api", {"positives": 0, "total": 1})
abuse  = _import_or_stub("abuseipdb_api",  {"confidence": 0, "reports": 0})
otx    = _import_or_stub("otx_api",        False)
tfox   = _import_or_stub("threatfox_api",  False)
gnoise = _import_or_stub("greynoise_api",  "benign")

# ------------------------------------------------------------------
# Per-provider maliciousness thresholds
# ------------------------------------------------------------------
def _gn_thr(val):  # GreyNoise helper – accepts bool or str
    if isinstance(val, bool):
        return val  # True == malicious
    if isinstance(val, str):
        return val.lower() == "malicious"
    return False

_TH = {
    "virustotal": lambda x: x.get("positives", 0) >= 5
                        or x.get("positives", 0) / max(x.get("total", 1), 1) >= 0.10,
    "abuseipdb":  lambda x: x.get("confidence", 0) >= 50 and x.get("reports", 0) >= 10,
    "greynoise":  _gn_thr,
    "threatfox":  bool,   # already boolean
    "alienvault": bool,   # already boolean (OTX)
}

# ------------------------------------------------------------------
# Public provider map – *values must return bool.*
# ------------------------------------------------------------------
PROVIDERS: Dict[str, callable] = {
    "VirusTotal":  lambda i: _TH["virustotal"](vt(i)),
    "AbuseIPDB":   lambda i: _TH["abuseipdb"](abuse(i)),
    "AlienVault":  otx,
    "ThreatFox":   tfox,
    "GreyNoise":   lambda i: _TH["greynoise"](gnoise(i)),
}

# Votes required for a malicious verdict
QUORUM = 2


def scan(ioc: str, selected: Optional[Iterable[str]] = None) -> Dict[str, bool]:
    """Scan *ioc* across the given *selected* providers.

    Parameters
    ----------
    ioc : str
        Indicator of compromise.
    selected : Iterable[str] | None
        Subset of provider display-names to query. ``None`` (default)
        means *all* providers.

    Returns
    -------
    dict
        Per-provider boolean map plus keys ``verdict`` and ``flagged_by``.
    """
    res: Dict[str, bool] = {}
    selected_set = {s for s in selected} if selected is not None else None

    for name, fn in PROVIDERS.items():
        if selected_set is not None and name not in selected_set:
            continue
        try:
            res[name] = bool(fn(ioc))
            _quota_inc(name)
        except Exception:       # pragma: no cover – provider failed
            res[name] = False
            _quota_inc(name)

    malicious = sum(res.values()) >= QUORUM
    res["verdict"] = "malicious" if malicious else "clean"
    res["flagged_by"] = [p for p, bad in res.items() if p in PROVIDERS and bad]
    return res

# ------------------------------------------------------------------
# Misc helpers kept for backward-compatibility
# ------------------------------------------------------------------

def _extract_ip(value: str) -> str:
    """Strip port suffix and brackets from *value* if present."""
    if value.startswith("[") and "]" in value:
        return value.split("]")[0][1:]
    if value.count(":") == 1 and ":" in value:
        return value.split(":")[0]
    return value

# These lists are still imported by *ioc_checker* but are no longer used
ALWAYS_ON: list = []
RATE_LIMIT: list = []

__all__ = [
    "scan",
    "PROVIDERS",
    "QUORUM",
    "_extract_ip",
    "ALWAYS_ON",
    "RATE_LIMIT",
] 