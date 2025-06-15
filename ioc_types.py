"""
IOC parsing, validation and normalisation.
Only top-level docstrings are used, no inline comments.
"""
from __future__ import annotations
import re, ipaddress, urllib.parse
from typing import Callable, Dict, Tuple
from .providers import _extract_ip

_RE_DOMAIN  = re.compile(r"^(?=.{4,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                         r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,}$")
_RE_HASH    = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
_RE_EMAIL   = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# More specific file path regex that matches actual file paths
_RE_FILE    = re.compile(r"^(?:[A-Za-z]:\\[^<>:\"|?*\n]+|\.{0,2}/[^<>:\"|?*\n]+|[^/\\:]+\.[a-zA-Z0-9]{1,10})$")
_RE_REG     = re.compile(r"^HK[LMCU]")
_RE_WALLET  = re.compile(r"^0x[a-fA-F0-9]{40}$")
_RE_ASN     = re.compile(r"^AS\d+$")
_RE_ATTCK   = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Pre-compiled date/time regex patterns for faster validation
_DT_REGEXES = [
    re.compile(r'^\d{1,2}/\d{1,2}/\d{2,4}(\s+\d{1,2}:\d{2}(:\d{2})?(\s*[AaPp][Mm])?)?$'),
    re.compile(r'^\d{4}-\d{2}-\d{2}(\s+\d{1,2}:\d{2}(:\d{2})?)?$'),
    re.compile(r'^\d{1,2}:\d{2}(:\d{2})?(\s*[AaPp][Mm])?$')
]

# Common valid TLDs (subset of most common ones)
_VALID_TLDS = {
    'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'io', 'co', 'ch', 'de', 'uk', 'fr', 'it', 'es', 'pl', 'nl', 'be', 'se', 'no', 'dk', 'fi', 'pt', 'gr', 'at', 'cz', 'hu', 'ro', 'bg', 'hr', 'si', 'sk', 'lt', 'lv', 'ee', 'mt', 'lu', 'cy', 'ie', 'is', 'li', 'mc', 'sm', 'va', 'ad', 'ru', 'ua', 'by', 'md', 'ge', 'am', 'az', 'kz', 'kg', 'tj', 'tm', 'uz', 'cn', 'jp', 'kr', 'tw', 'hk', 'mo', 'sg', 'my', 'th', 'vn', 'ph', 'id', 'in', 'pk', 'bd', 'lk', 'np', 'bt', 'mv', 'af', 'ir', 'iq', 'sy', 'lb', 'jo', 'ps', 'il', 'tr', 'cy', 'eg', 'ly', 'tn', 'dz', 'ma', 'sd', 'so', 'et', 'ke', 'tz', 'ug', 'rw', 'bi', 'mw', 'zm', 'zw', 'bw', 'na', 'sz', 'ls', 'mg', 'mu', 'sc', 'km', 'dj', 'er', 'cf', 'td', 'cm', 'gq', 'ga', 'cg', 'cd', 'ao', 'st', 'gh', 'tg', 'bj', 'ne', 'bf', 'ml', 'sn', 'gm', 'gw', 'cv', 'sl', 'lr', 'ci', 'gn', 'mr', 'eh', 'us', 'ca', 'mx', 'gt', 'bz', 'sv', 'hn', 'ni', 'cr', 'pa', 'cu', 'do', 'ht', 'jm', 'tt', 'bb', 'gd', 'vc', 'lc', 'dm', 'ag', 'kn', 'ms', 'ai', 'vg', 'vi', 'pr', 'br', 'ar', 'uy', 'py', 'bo', 'pe', 'ec', 'co', 've', 'gy', 'sr', 'gf', 'fk', 'gs', 'au', 'nz', 'pg', 'sb', 'vu', 'nc', 'pf', 'wf', 'ws', 'to', 'tv', 'nu', 'ck', 'ki', 'pw', 'fm', 'mh', 'nr', 'um', 'mp', 'gu', 'as', 'cc', 'cx', 'nf', 'hm', 'aq', 'tf', 'bv', 'sj', 'gl', 'fo', 'ax', 'info', 'biz', 'name', 'pro', 'museum', 'coop', 'aero', 'jobs', 'mobi', 'travel', 'xxx', 'cat', 'tel', 'asia', 'post', 'arpa', 'local', 'localhost', 'test', 'example', 'invalid', 'onion', 'exit', 'i2p'
}

# Common file extensions that should not be considered domains
_FILE_EXTENSIONS = {
    'exe', 'dll', 'sys', 'bat', 'cmd', 'com', 'scr', 'pif', 'vbs', 'vbe', 'js', 'jar', 'class', 'py', 'pl', 'rb', 'sh', 'ps1',
    'txt', 'doc', 'docx', 'pdf', 'rtf', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp',
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'svg', 'ico', 'webp',
    'mp3', 'wav', 'flac', 'aac', 'ogg', 'wma', 'm4a',
    'mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm', 'm4v',
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'lzma',
    'log', 'cfg', 'ini', 'conf', 'xml', 'json', 'yaml', 'yml', 'csv', 'tsv',
    'iso', 'img', 'vhd', 'vmdk', 'ova', 'ovf',
    'msi', 'cab', 'deb', 'rpm', 'dmg', 'pkg', 'app',
    'tmp', 'temp', 'bak', 'old', 'orig', 'cache'
}

# Known malware family prefixes/patterns that should not be considered domains
_MALWARE_PREFIXES = {
    'win.', 'apk.', 'js.', 'elf.', 'osx.', 'linux.', 'android.', 'ios.',
    'trojan.', 'backdoor.', 'adware.', 'spyware.', 'ransomware.', 'worm.', 'virus.'
}

def _strip_port(v:str)->str:
    if v.startswith('[') and ']:' in v: return v.split(']:')[0][1:]
    if v.count(':')==1: return v.split(':')[0]
    return v

def _valid_ip(v:str)->bool:
    try: ipaddress.ip_address(_extract_ip(v)); return True
    except ValueError: return False
def _valid_domain(v:str)->bool:  
    # First check basic regex pattern
    if not _RE_DOMAIN.fullmatch(v):
        return False
    
    # Extract the TLD (last part after final dot)
    parts = v.lower().split('.')
    if len(parts) < 2:
        return False
    
    tld = parts[-1]
    
    # Check if it's a file extension masquerading as a domain
    if tld in _FILE_EXTENSIONS:
        return False
    
    # Check if it matches malware family patterns
    v_lower = v.lower()
    for prefix in _MALWARE_PREFIXES:
        if v_lower.startswith(prefix):
            return False
    
    # Check if TLD is valid (must be in our known TLD list)
    if tld not in _VALID_TLDS:
        return False
    
    # Additional check: if it's just two parts and both are short, it might be malware family
    if len(parts) == 2 and len(parts[0]) <= 4 and len(parts[1]) <= 8:
        # Common malware family pattern like win.dcrat, apk.hook, etc.
        if parts[0] in ['win', 'apk', 'js', 'elf', 'osx', 'linux', 'android', 'ios'] and parts[1] not in _VALID_TLDS:
            return False
    
    return True
def _valid_url(v:str)->bool:
    p=urllib.parse.urlparse(v)
    return p.scheme in ("http","https","ftp","ftps") and bool(p.netloc)
def _valid_hash(v:str)->bool:     return bool(_RE_HASH.fullmatch(v))
def _valid_email(v:str)->bool:    return bool(_RE_EMAIL.fullmatch(v))
def _valid_file(v:str)->bool:     
    v_stripped = v.strip()
    
    # Exclude common date/time formats that contain slashes
    if any(pat.match(v_stripped) for pat in _DT_REGEXES):
        return False
    
    # Check if it matches file path pattern
    return bool(_RE_FILE.fullmatch(v_stripped))
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
