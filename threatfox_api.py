import os, requests

_API   = "https://threatfox-api.abuse.ch/api/v1/"
_API_K = os.getenv("THREATFOX_API_KEY", "")

_HEADERS = {"Accept": "application/json"}
if _API_K:
    _HEADERS["API-KEY"] = _API_K

_PAYLOAD = {"query": "search_ioc"}

def check(ioc: str) -> bool:
    """True if IOC present in ThreatFox data."""
    data = dict(_PAYLOAD, search_term=ioc)
    r = requests.post(_API, headers=_HEADERS, data=data, timeout=15)
    return r.ok and bool(r.json().get("data")) 