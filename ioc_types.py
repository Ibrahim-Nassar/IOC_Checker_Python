# pyright: reportMissingImports=false, reportRedeclaration=false
"""IOC types and result objects for the IOC Checker project.

# pyright: reportMissingImports=false, reportRedeclaration=false
"""
from __future__ import annotations

from enum import Enum
from typing import Literal

try:
    from pydantic import BaseModel
    _HAS_PYDANTIC = True
except ImportError:
    from dataclasses import dataclass
    _HAS_PYDANTIC = False

import regex as re
import ipaddress
import urllib.parse
from typing import Callable, Dict, Tuple

__all__ = ["IOCStatus", "IOCResult", "detect_ioc_type", "validate_ioc"]


class IOCStatus(Enum):
    SUCCESS = "success"
    MALICIOUS = "malicious"
    ERROR = "error"
    UNSUPPORTED = "unsupported"


if _HAS_PYDANTIC:
    class IOCResult(BaseModel):
        ioc: str
        ioc_type: Literal["ip", "domain", "url", "hash"]
        status: IOCStatus
        malicious_engines: int = 0
        total_engines: int = 0
        message: str = ""
else:
    @dataclass
    class IOCResult:
        ioc: str
        ioc_type: Literal["ip", "domain", "url", "hash"]
        status: IOCStatus
        malicious_engines: int = 0
        total_engines: int = 0
        message: str = ""


_RE_DOMAIN = re.compile(r"^(?=.{4,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                        r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.[A-Za-z]{2,}$")
_RE_HASH = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})$")
_RE_EMAIL = re.compile(r".+?@.+")
_RE_FILE = re.compile(r".+?\.(exe|dll|zip|rar|7z)")
_RE_REG = re.compile(r"(?:HKLM|HKCU)\\.+")
_RE_WALLET = re.compile(r"\b[a-f0-9]{32,}\b")
_RE_ASN = re.compile(r"AS\d{1,10}")
_RE_ATTCK = re.compile(r"^T\d{4}")

# Common file extensions that should not be considered domains (removed 'com' which is a valid TLD)
_FILE_EXTENSIONS = {
    'exe', 'dll', 'sys', 'bat', 'cmd', 'scr', 'pif', 'vbs', 'vbe', 'js', 'jar', 'class', 'py', 'pl', 'rb', 'sh', 'ps1',
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

def _extract_ip(v: str) -> str:
    """Return the first dotted-quad in the string or the original value."""
    m = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", v)
    return m.group(0) if m else v

def _strip_port(v:str)->str:
    if v.startswith('[') and ']:' in v: return v.split(']:')[0][1:]
    if v.count(':')==1: return v.split(':')[0]
    return v

def _valid_ip(v:str)->bool:
    try: 
        # First check the basic format - should have exactly 3 dots for IPv4
        if v.count('.') == 3:
            ipaddress.ip_address(_extract_ip(v))
            return True
        # IPv6 addresses don't have dots in this context, they use colons
        elif ':' in v and '.' not in v:
            ipaddress.ip_address(v)
            return True
        else:
            return False
    except ValueError: 
        return False

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
    # Only reject if the entire string looks like a filename (not a proper FQDN)
    if tld in _FILE_EXTENSIONS and len(parts) == 2 and len(parts[0]) <= 32:
        # This looks more like a filename than a domain (e.g., "document.pdf")
        return False
    
    # Check if it matches malware family patterns
    v_lower = v.lower()
    for prefix in _MALWARE_PREFIXES:
        if v_lower.startswith(prefix):
            return False
    
    # Use tldextract for TLD validation
    try:
        import tldextract
        extracted = tldextract.extract(v)
        # Domain is valid if it has a valid suffix (TLD)
        return bool(extracted.suffix)
    except ImportError:
        # Fallback if tldextract is not available
        return len(tld) >= 2 and tld.isalpha()
    
    # Additional check: if it's just two parts and both are short, it might be malware family
    if len(parts) == 2 and len(parts[0]) <= 4 and len(parts[1]) <= 8:
        # Common malware family pattern like win.dcrat, apk.hook, etc.
        if parts[0] in ['win', 'apk', 'js', 'elf', 'osx', 'linux', 'android', 'ios']:
            return False
    
    return True

def _valid_url(v:str)->bool:
    try:
        p = urllib.parse.urlparse(v)
        
        # Must have proper scheme
        if p.scheme not in ("http", "https", "ftp", "ftps"):
            return False
        
        # Must have netloc (domain)
        if not p.netloc:
            return False
        
        # Check for common invalid patterns
        if ".." in v:  # consecutive dots
            return False
        if v.endswith("/.") or "/./" in v:  # path ending with /. or containing /./
            return False
        if "/." in p.path and not "/.well-known" in p.path:  # hidden files/dirs (except .well-known)
            return False
        
        # Check for paths ending with a dot (like /news.)
        if p.path and (p.path.endswith(".") or "/." in p.path):
            # Allow .well-known and file extensions
            if not ("/.well-known" in p.path or any(p.path.endswith(f".{ext}") for ext in ['html', 'php', 'aspx', 'jsp', 'css', 'js', 'json', 'xml'])):
                return False
        
        # Validate the domain part of the URL
        domain = p.netloc.split(':')[0]  # Remove port if present
        if not _valid_domain(domain):
            return False
        
        # Check for malformed path components
        if p.path:
            # Path shouldn't have consecutive slashes (except after scheme)
            normalized_path = p.path.replace('//', '/')
            if '//' in normalized_path:
                return False
            
            # Path components shouldn't be empty strings or just dots
            path_parts = [part for part in p.path.split('/') if part]
            for part in path_parts:
                if part == '.' or part == '..' or (part.endswith('.') and '.' not in part[:-1]):
                    # Reject paths ending with dot unless it's a file extension
                    return False
        
        return True
        
    except Exception:
        return False

def _valid_hash(v:str)->bool:     return bool(_RE_HASH.fullmatch(v))
def _valid_email(v:str)->bool:    return bool(_RE_EMAIL.fullmatch(v))
def _valid_file(v:str)->bool:     
    v_stripped = v.strip()
    # Check if it matches file path pattern
    return bool(_RE_FILE.fullmatch(v_stripped))
def _valid_reg(v:str)->bool:      return bool(_RE_REG.match(v))
def _valid_wallet(v:str)->bool:   
    # Wallet addresses should be between 26-64 characters and only hex
    if len(v) < 26 or len(v) > 64:
        return False
    # Common wallet lengths: Bitcoin (26-35), Ethereum (42), etc.
    if len(v) not in [26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 42, 62, 64]:
        return False
    return bool(_RE_WALLET.fullmatch(v))
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

def validate_ioc(value: str, expected_type: str | None = None) -> Tuple[bool, str, str, str]:
    """
    Validate an IOC value and return validation results.
    
    Args:
        value: The IOC value to validate
        expected_type: Expected IOC type (optional). If None, auto-detect.
    
    Returns:
        Tuple of (is_valid, ioc_type, normalized_value, error_message)
    """
    if not value or not value.strip():
        return False, "unknown", "", "IOC value cannot be empty"
    
    v = value.strip()
    
    # If expected type is provided, validate against it
    if expected_type and expected_type != "auto":
        if expected_type not in VALIDATORS:
            return False, expected_type, v, f"Unknown IOC type: {expected_type}"
        
        validator = VALIDATORS[expected_type]
        if validator(v):
            return True, expected_type, _normalise(expected_type, v), ""
        else:
            return False, expected_type, v, _get_validation_error(expected_type, v)
    
    # Auto-detect type
    detected_type, normalized_value = detect_ioc_type(v)
    
    if detected_type == "unknown":
        return False, "unknown", v, _get_generic_validation_error(v)
    
    return True, detected_type, normalized_value, ""

def _get_validation_error(ioc_type: str, value: str) -> str:
    """Get a helpful error message for a specific IOC type validation failure."""
    if ioc_type == "ip":
        return f"Invalid IP address: '{value}'. Expected format: 192.168.1.1 or 2001:db8::1"
    elif ioc_type == "domain":
        if "." not in value:
            return f"Invalid domain: '{value}'. Domains must contain at least one dot (e.g., example.com)"
        elif value.count(".") == 1 and len(value.split(".")[1]) <= 4:
            return f"Invalid domain: '{value}'. This looks like a filename, not a domain"
        elif "//" in value:
            return f"Invalid domain: '{value}'. This looks like a URL, try selecting 'url' type instead"
        else:
            return f"Invalid domain: '{value}'. Expected format: example.com or subdomain.example.com"
    elif ioc_type == "url":
        if not value.startswith(("http://", "https://", "ftp://", "ftps://")):
            return f"Invalid URL: '{value}'. URLs must start with http://, https://, ftp://, or ftps://"
        elif ".." in value or value.endswith("."):
            return f"Invalid URL: '{value}'. URL contains invalid characters or formatting"
        else:
            return f"Invalid URL: '{value}'. Check the format and ensure it's a valid web address"
    elif ioc_type == "hash":
        if len(value) not in [32, 40, 64]:
            return f"Invalid hash: '{value}'. Hashes must be 32 (MD5), 40 (SHA1), or 64 (SHA256) characters long"
        elif not all(c in "0123456789abcdefABCDEF" for c in value):
            return f"Invalid hash: '{value}'. Hashes can only contain hexadecimal characters (0-9, a-f)"
        else:
            return f"Invalid hash: '{value}'. Expected hexadecimal string of length 32, 40, or 64"
    else:
        return f"Invalid {ioc_type}: '{value}'"

def _get_generic_validation_error(value: str) -> str:
    """Get a helpful error message when IOC type cannot be auto-detected."""
    if not value.strip():
        return "IOC value cannot be empty"
    elif len(value) > 2048:
        return "IOC value is too long (maximum 2048 characters)"
    elif "//" in value and not value.startswith(("http://", "https://", "ftp://", "ftps://")):
        return f"'{value}' looks like a malformed URL. Try adding http:// or https:// at the beginning"
    elif "." in value and len(value.split(".")) >= 2:
        if value.endswith("."):
            return f"'{value}' looks like a domain but ends with an extra dot"
        elif ".." in value:
            return f"'{value}' contains consecutive dots which is invalid for domains and URLs"
        else:
            return f"'{value}' doesn't match any known IOC format. Supported types: IP, domain, URL, hash"
    elif re.match(r"^\d+\.\d+\.\d+\.\d+", value):
        return f"'{value}' looks like an IP address but has invalid format. Expected: 192.168.1.1"
    elif len(value) in [30, 31, 33, 34, 38, 39, 41, 42, 62, 63, 65, 66]:
        return f"'{value}' is {len(value)} characters long, close to hash length but contains invalid characters"
    else:
        return f"'{value}' doesn't match any known IOC format (IP, domain, URL, hash, etc.)"

# ──────────────────────────────────────────────────────────────────────────────
# Static-type-checker friendly stub
# ---------------------------------------------------------------------------
from typing import TYPE_CHECKING
if TYPE_CHECKING:  # executed only while running mypy/pyright, ignored at run-time
    from dataclasses import dataclass as _dataclass

    @_dataclass
    class IOCResult:  # type: ignore[dead-code]
        """Dataclass stub so pyright recognises our keyword arguments."""
        ioc: str
        ioc_type: Literal["ip", "domain", "url", "hash"]
        status: IOCStatus
        malicious_engines: int = 0
        total_engines: int = 0
        message: str = ""
