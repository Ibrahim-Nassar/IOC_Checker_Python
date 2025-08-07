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

try:
    import regex as re
except ImportError:
    import re  # TODO: Add regex to [tool.poetry.dependencies] OR leave fallback comment
import ipaddress
import urllib.parse
from typing import Callable, Dict, Tuple

__all__ = ["IOCStatus", "IOCResult", "detect_ioc_type", "validate_ioc"]


class IOCStatus(Enum):
    SUCCESS = "success"
    MALICIOUS = "malicious"
    ERROR = "error"
    UNSUPPORTED = "unsupported"
    NOT_FOUND = "not_found"


if _HAS_PYDANTIC:
    class IOCResult(BaseModel):
        ioc: str
        ioc_type: Literal["ip", "domain", "url", "hash"]
        status: IOCStatus
        malicious_engines: int = 0
        total_engines: int = 0
        message: str = ""
        
        def __init__(self, ioc=None, ioc_type=None, status=None, malicious_engines=None, total_engines=None, message=None, **kwargs):
            # Support positional arguments for backward compatibility
            if ioc is not None:
                kwargs['ioc'] = ioc
            if ioc_type is not None:
                kwargs['ioc_type'] = ioc_type
            if status is not None:
                kwargs['status'] = status
            if malicious_engines is not None:
                kwargs['malicious_engines'] = malicious_engines
            if total_engines is not None:
                kwargs['total_engines'] = total_engines
            if message is not None:
                kwargs['message'] = message
            super().__init__(**kwargs)
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

def _strip_port(v: str) -> str:
    """Strip port from IP address, handling both IPv4 and IPv6."""
    # Handle bracketed IPv6 with port: [2001:db8::1]:80
    if v.startswith('[') and ']:' in v:
        return v.split(']:')[0][1:]
    
    # Handle bracketed IPv6 without port: [2001:db8::1]
    if v.startswith('[') and v.endswith(']') and ']:' not in v:
        return v[1:-1]  # Remove brackets
    
    # For raw format, try smarter port detection
    if ':' in v:
        colon_count = v.count(':')
        
        # IPv4 with port: 192.168.1.1:80
        if colon_count == 1:
            parts = v.split(':')
            # Check if the last part looks like a port (1-65535)
            try:
                port = int(parts[1])
                if 1 <= port <= 65535:
                    # Verify the first part is a valid IPv4
                    ipaddress.ip_address(parts[0])
                    return parts[0]
            except (ValueError, ipaddress.AddressValueError):
                pass
        
        # IPv6 with potential port: try to detect common port patterns
        elif colon_count > 1:
            # Try stripping the last colon segment if it looks like a port
            parts = v.rsplit(':', 1)
            if len(parts) == 2:
                try:
                    port = int(parts[1])
                    # If the last segment is a valid port number and 
                    # the remaining part is a valid IPv6, strip the port
                    if 1 <= port <= 65535:
                        try:
                            ipaddress.ip_address(parts[0])
                            return parts[0]
                        except ValueError:
                            pass
                except ValueError:
                    pass
    
    # If no port pattern detected or stripping failed, return original
    return v

def _valid_url(v:str)->bool:
    try:
        p = urllib.parse.urlparse(v)
        
        # Must have proper scheme
        if p.scheme not in ("http", "https", "ftp", "ftps"):
            return False
        
        # Must have netloc (host)
        if not p.netloc:
            return False
        
        # Validate the host: allow domain names OR IP literals (IPv4/IPv6)
        host = p.hostname  # Already without brackets and port
        if not host:
            return False
        
        if not (_valid_domain(host) or _valid_ip(host)):
            return False
        
        # Check for common invalid patterns in the whole URL
        if ".." in v:  # consecutive dots anywhere in URL
            return False
        if v.endswith("/.") or "/./" in v or v.endswith("./"):  # path ending with /. or ./ or containing /./
            return False
        if v.endswith(".") and not any(v.endswith(f".{ext}") for ext in ['html', 'php', 'aspx', 'jsp', 'css', 'js', 'json', 'xml', 'txt', 'pdf']):
            return False
        
        # Path validation: reject obviously malformed segments
        if p.path:
            if p.path.startswith("//") or "//" in p.path[1:]:  # Multiple consecutive slashes
                return False
            path_parts = [part for part in p.path.split('/') if part]
            for part in path_parts:
                if part in ['.', '..'] or part.endswith('.'):
                    return False
        
        return True
        
    except Exception:
        return False

def _valid_ip(v:str)->bool:
    try: 
        # Handle bracketed IPv6 (extract the IP from brackets first)
        if v.startswith('[') and (']:' in v or v.endswith(']')):
            # Extract IP from [IP]:port or [IP] format
            ip_part = v[1:v.index(']')] if ']' in v else v[1:-1]
            # Strip zone identifier if present (e.g., %eth0)
            ip_no_zone = ip_part.split('%', 1)[0]
            ipaddress.ip_address(ip_no_zone)
            return True
        
        # IPv4 with optional port
        if v.count('.') == 3:
            ip_str = _extract_ip(_strip_port(v))
            ipaddress.ip_address(ip_str)
            return True
        
        # IPv6 (raw) with optional port and/or zone id
        if ':' in v and '.' not in v:
            ip_str = _strip_port(v)
            ip_str = ip_str.split('%', 1)[0]  # remove zone id if present
            ipaddress.ip_address(ip_str)
            return True
        
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
