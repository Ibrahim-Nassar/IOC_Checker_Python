import os, requests, typing

_API = "https://api.greynoise.io/v3/community/"
_KEY = os.getenv("GREYNOISE_API_KEY", "")

def check(ip: str) -> bool:
    """Return True if GreyNoise classifies the IP as malicious."""
    headers = {"Accept": "application/json"}
    if _KEY:
        headers["key"] = _KEY
    r = requests.get(f"{_API}{ip}", headers=headers, timeout=10)
    if r.status_code != 200:
        return False
    kind = r.json().get("classification", "")
    return kind == "malicious"