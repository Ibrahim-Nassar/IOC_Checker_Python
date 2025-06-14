"""
IOC parsing, validation and normalisation.
Only top-level docstrings are used, no inline comments.
"""
from __future__ import annotations
import re, ipaddress, urllib.parse
from typing import Callable, Dict, Tuple

_RE_DOMAIN  = re.compile(r"^(?=.{4,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                         r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,}$")
_RE_HASH    = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
_RE_EMAIL   = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_FILE    = re.compile(r"[A-Za-z]:\\|/")
_RE_REG     = re.compile(r"^HK[LMCU]")
_RE_WALLET  = re.compile(r"^0x[a-fA-F0-9]{40}$")
_RE_ASN     = re.compile(r"^AS\d+$")
_RE_ATTCK   = re.compile(r"^T\d{4}(?:\.\d{3})?$")

def _strip_port(v:str)->str:
    if v.startswith('[') and ']:' in v: return v.split(']:')[0][1:]
    if v.count(':')==1: return v.split(':')[0]
    return v

def _extract_ip(v: str) -> str:
    """Extract IP from IP:port format. Alias for _strip_port for compatibility."""
    return _strip_port(v)

def _valid_ip(v:str)->bool:
    try: ipaddress.ip_address(_strip_port(v)); return True
    except ValueError: return False
def _valid_domain(v:str)->bool:  return bool(_RE_DOMAIN.fullmatch(v))
def _valid_url(v:str)->bool:
    p=urllib.parse.urlparse(v)
    return p.scheme in ("http","https","ftp","ftps") and bool(p.netloc)
def _valid_hash(v:str)->bool:     return bool(_RE_HASH.fullmatch(v))
def _valid_email(v:str)->bool:    return bool(_RE_EMAIL.fullmatch(v))
def _valid_file(v:str)->bool:     return bool(_RE_FILE.search(v))
def _valid_reg(v:str)->bool:      return bool(_RE_REG.match(v))
def _valid_wallet(v:str)->bool:   return bool(_RE_WALLET.fullmatch(v))
def _valid_asn(v:str)->bool:
    if _RE_ASN.fullmatch(v): return True
    try: ipaddress.ip_network(v, strict=False); return True
    except ValueError: return False
def _valid_attck(v:str)->bool:    return bool(_RE_ATTCK.fullmatch(v))

VALIDATORS:Dict[str,Callable[[str],bool]]={
    "ip":_valid_ip,"domain":_valid_domain,"url":_valid_url,"hash":_valid_hash,
    "email":_valid_email,"filepath":_valid_file,"registry":_valid_reg,
    "wallet":_valid_wallet,"asn":_valid_asn,"attack":_valid_attck,
}

def _normalise(typ:str,v:str)->str:
    if typ=="url":
        p=urllib.parse.urlparse(v)
        return p._replace(query="",fragment="").geturl()
    if typ=="ip":
        return _strip_port(v)
    if typ in ("domain","hash"): return v.lower()
    return v

def detect_ioc_type(value:str)->Tuple[str,str]:
    v=value.strip()
    # Check in priority order: hash, url, ip, domain, then others
    priority_order = ["hash", "url", "ip", "domain", "email", "filepath", "registry", "wallet", "asn", "attack"]
    for t in priority_order:
        f = VALIDATORS[t]
        if f(v): return t,_normalise(t,v)
    return "unknown",v
