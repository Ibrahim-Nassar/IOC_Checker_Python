"""
Async provider clients with per-feed rate control and robust error handling.
• Token bucket rate limiting • Environment variable configuration
• Comprehensive logging • UTF-8 safe operations
"""
from __future__ import annotations
import os, asyncio, base64, datetime, logging
from typing import Optional
import aiohttp
from pathlib import Path
from dotenv import load_dotenv

# Load .env that sits next to the project's .py files
load_dotenv(Path(__file__).resolve().parent / ".env")

# Import IP extraction function
def _extract_ip(v: str) -> str:
    """Extract IP from IP:port format."""
    if v.startswith('[') and ']:' in v: return v.split(']:')[0][1:]
    if v.count(':') == 1: return v.split(':')[0]
    return v

log = logging.getLogger("providers")
HEAD = {"User-Agent": "ioc-checker/1.0"}

class TokenBucket:
    """Rate limiting token bucket implementation."""
    def __init__(self, cap: int, interval: int):
        self.cap = cap
        self.tok = cap
        self.int = interval
        self.upd = datetime.datetime.utcnow()
        self.lock = asyncio.Lock()
    
    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary."""
        async with self.lock:
            now = datetime.datetime.utcnow()
            gain = int((now - self.upd).total_seconds() // self.int)
            if gain:
                self.tok = min(self.cap, self.tok + gain)
                self.upd += datetime.timedelta(seconds=gain * self.int)
            while self.tok == 0:
                # Refresh tokens before calculating wait time
                self._refill()
                wait = self.int - (datetime.datetime.utcnow() - self.upd).total_seconds()
                await asyncio.sleep(max(wait, 0.1))
                self.tok = 1
                self.upd = datetime.datetime.utcnow()
            self.tok -= 1

    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = datetime.datetime.utcnow()
        gain = int((now - self.upd).total_seconds() // self.int)
        if gain:
            self.tok = min(self.cap, self.tok + gain)
            self.upd += datetime.timedelta(seconds=gain * self.int)

class Provider:
    """Base provider class."""
    name: str
    ioc_kinds: tuple[str, ...]
    bucket: Optional[TokenBucket] = None
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        """Query the provider for IOC information."""
        ...

def _key(env: str) -> str:
    """Get environment variable safely."""
    return os.getenv(env, "").strip()

class AbuseIPDB(Provider):
    """AbuseIPDB provider for IP reputation checks."""
    name, ioc_kinds = "abuseipdb", ("ip",)
    key = _key("ABUSEIPDB_API_KEY")
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        if not self.key:
            return "nokey"
        # Extract IP from IP:port format
        ip_addr = _extract_ip(v) if t == "ip" else v
        try:
            p = {"ipAddress": ip_addr, "maxAgeInDays": 30}
            h = HEAD | {"Key": self.key, "Accept": "application/json"}
            async with s.get("https://api.abuseipdb.com/api/v2/check", headers=h, params=p) as r:
                return await r.text()
        except Exception as e:
            log.error(f"AbuseIPDB query failed: {e}")
            return f"error: {str(e)}"

class OTX(Provider):
    """AlienVault OTX provider for threat intelligence."""
    name, ioc_kinds = "otx", ("ip", "domain", "url", "hash")
    key = _key("OTX_API_KEY")
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        if not self.key:
            return "nokey"
        # Extract IP from IP:port format for IP queries
        query_val = _extract_ip(v) if t == "ip" else v
        try:
            suf = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}[t]
            h = HEAD | {"X-OTX-API-KEY": self.key}
            async with s.get(f"https://otx.alienvault.com/api/v1/indicators/{suf}/{query_val}/general", headers=h) as r:
                return await r.text()
        except Exception as e:
            log.error(f"OTX query failed: {e}")
            return f"error: {str(e)}"

class ThreatFox(Provider):
    """Abuse.ch ThreatFox IOC database."""
    name, ioc_kinds = "threatfox", ("ip", "domain", "url", "hash")
    key = _key("THREATFOX_API_KEY")
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        try:
            h = {"Content-Type": "application/json"}
            if self.key:
                h["Auth-Key"] = self.key
            payload = {"query": "search_ioc", "search_term": v, "exact_match": True}
            async with s.post("https://threatfox-api.abuse.ch/api/v1/", json=payload, headers=h) as r:
                return await r.text()
        except Exception as e:
            log.error(f"ThreatFox query failed: {e}")
            return f"error: {str(e)}"

class URLHaus(Provider):
    """Abuse.ch URLhaus malicious URL database."""
    name, ioc_kinds = "urlhaus", ("url",)
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        try:
            async with s.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": v}) as r:
                return await r.text()
        except Exception as e:
            log.error(f"URLhaus query failed: {e}")
            return f"error: {str(e)}"

class MalwareBazaar(Provider):
    """Abuse.ch MalwareBazaar malware hash database."""
    name, ioc_kinds = "malwarebazaar", ("hash",)
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        try:
            async with s.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": v}) as r:
                return await r.text()
        except Exception as e:
            log.error(f"MalwareBazaar query failed: {e}")
            return f"error: {str(e)}"

class VirusTotal(Provider):
    """VirusTotal multi-engine antivirus scanner."""
    name, ioc_kinds = "virustotal", ("ip", "domain", "url", "hash")
    key = _key("VIRUSTOTAL_API_KEY")
    bucket = TokenBucket(4, 60)
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        if not self.key:
            return "nokey"
        try:
            await self.bucket.acquire()
            if t == "url":
                encoded_url = base64.urlsafe_b64encode(v.encode()).decode().strip('=')
                path = f"urls/{encoded_url}"
            else:
                path = {"ip": f"ip_addresses/{v}", "domain": f"domains/{v}", "hash": f"files/{v}"}[t]
            h = HEAD | {"x-apikey": self.key}
            async with s.get(f"https://www.virustotal.com/api/v3/{path}", headers=h) as r:
                return await r.text()
        except Exception as e:
            log.error(f"VirusTotal query failed: {e}")
            return f"error: {str(e)}"

class GreyNoise(Provider):
    """GreyNoise internet background noise intelligence."""
    name, ioc_kinds = "greynoise", ("ip",)
    key = _key("GREYNOISE_API_KEY")
    bucket = TokenBucket(50, 604800)  # 50 requests per week
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        if not self.key:
            return "nokey"
        try:
            await self.bucket.acquire()
            h = HEAD | {"key": self.key, "Accept": "application/json"}
            async with s.get(f"https://api.greynoise.io/v3/community/{v}", headers=h) as r:
                return await r.text()
        except Exception as e:
            log.error(f"GreyNoise query failed: {e}")
            return f"error: {str(e)}"

class Pulsedive(Provider):
    """Pulsedive threat intelligence platform."""
    name, ioc_kinds = "pulsedive", ("ip", "domain", "url")
    key = _key("PULSEDIVE_API_KEY")
    bucket = TokenBucket(50, 86400)  # 50 requests per day
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        if not self.key:
            return "nokey"
        try:
            await self.bucket.acquire()
            params = {"indicator": v, "pretty": "1", "key": self.key}
            async with s.get("https://api.pulsedive.com/info.php", params=params, headers=HEAD) as r:
                return await r.text()
        except Exception as e:
            log.error(f"Pulsedive query failed: {e}")
            return f"error: {str(e)}"

class Shodan(Provider):
    """Shodan internet-connected device search engine."""
    name, ioc_kinds = "shodan", ("ip",)
    key = _key("SHODAN_API_KEY")
    bucket = TokenBucket(100, 2592000)  # 100 requests per month
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        if not self.key:
            return "nokey"
        try:
            await self.bucket.acquire()
            async with s.get(f"https://api.shodan.io/shodan/host/{v}", params={"key": self.key}, headers=HEAD) as r:
                return await r.text()
        except Exception as e:
            log.error(f"Shodan query failed: {e}")
            return f"error: {str(e)}"

# Provider instances
ALWAYS_ON = (AbuseIPDB(), OTX(), ThreatFox(), URLHaus(), MalwareBazaar())
RATE_LIMIT = (VirusTotal(), GreyNoise(), Pulsedive(), Shodan())
