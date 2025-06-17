"""
Async provider clients with structured status responses and robust error handling.
• Clean status mapping • Environment variable configuration  
• Comprehensive logging • UTF-8 safe operations
"""
from __future__ import annotations
import os, asyncio, base64, datetime, logging, json
from typing import Optional, Dict, Any
import aiohttp
from pathlib import Path
from dotenv import load_dotenv
from aiolimiter import AsyncLimiter

# Load .env that sits next to the project's .py files
load_dotenv(Path(__file__).resolve().parent / ".env")

def _rpm(name: str, default: int) -> int:
    """Get rate limit from environment variable or return default."""
    return int(os.getenv(f"{name.upper()}_RPM", default))

__all__ = ['_extract_ip']

# Import IP extraction function
def _extract_ip(v: str) -> str:
    """Extract IP from IP:port format."""
    if v.startswith('[') and ']:' in v: return v.split(']:')[0][1:]
    if v.count(':') == 1: return v.split(':')[0]
    return v

log = logging.getLogger("providers")
HEAD = {"User-Agent": "ioc-checker/1.0"}

def _parse_response(raw_response: str, provider_name: str) -> Dict[str, Any]:
    """Parse provider response and return structured status."""
    try:
        if raw_response.startswith("error:") or raw_response == "nokey":
            return {"status": "n/a", "score": 0, "raw": raw_response}
        
        data = json.loads(raw_response)
        
        # VirusTotal parsing
        if provider_name == "virustotal":
            try:
                stats = data["data"]["attributes"]["last_analysis_stats"]
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                if malicious > 0:
                    return {"status": "malicious", "score": 90, "raw": data}
                elif suspicious > 0:
                    return {"status": "suspicious", "score": 60, "raw": data}
                else:
                    return {"status": "clean", "score": 0, "raw": data}
            except (KeyError, TypeError):
                return {"status": "n/a", "score": 0, "raw": data}
        
        # AbuseIPDB parsing
        elif provider_name == "abuseipdb":
            try:
                score = data["data"]["abuseConfidenceScore"]
                whitelisted = data["data"].get("isWhitelisted", False)
                if whitelisted:
                    return {"status": "clean", "score": 0, "raw": data}
                elif score >= 25:
                    return {"status": "malicious", "score": score, "raw": data}
                else:
                    return {"status": "clean", "score": score, "raw": data}
            except (KeyError, TypeError):
                return {"status": "n/a", "score": 0, "raw": data}
        
        # OTX parsing
        elif provider_name == "otx":
            try:
                pulse_count = data["pulse_info"]["count"]
                if pulse_count > 0:
                    return {"status": "malicious", "score": 80, "raw": data}
                else:
                    return {"status": "clean", "score": 0, "raw": data}
            except (KeyError, TypeError):
                return {"status": "n/a", "score": 0, "raw": data}
        
        # ThreatFox parsing
        elif provider_name == "threatfox":
            try:
                if data.get("query_status") == "ok" and data.get("data"):
                    return {"status": "malicious", "score": 85, "raw": data}
                elif data.get("query_status") == "no_result":
                    return {"status": "clean", "score": 0, "raw": data}
                else:
                    return {"status": "n/a", "score": 0, "raw": data}
            except (KeyError, TypeError):
                return {"status": "n/a", "score": 0, "raw": data}
        
        # URLhaus parsing
        elif provider_name == "urlhaus":
            try:
                if data.get("query_status") == "ok":
                    return {"status": "malicious", "score": 85, "raw": data}
                elif data.get("query_status") == "no_result":
                    return {"status": "clean", "score": 0, "raw": data}
                else:
                    return {"status": "n/a", "score": 0, "raw": data}
            except (KeyError, TypeError):
                return {"status": "n/a", "score": 0, "raw": data}
        
        # MalwareBazaar parsing
        elif provider_name == "malwarebazaar":
            try:
                if data.get("query_status") == "ok" and data.get("data"):
                    return {"status": "malicious", "score": 85, "raw": data}
                elif data.get("query_status") == "no_result":
                    return {"status": "clean", "score": 0, "raw": data}
                else:
                    return {"status": "n/a", "score": 0, "raw": data}
            except (KeyError, TypeError):
                return {"status": "n/a", "score": 0, "raw": data}
          # Default fallback
        return {"status": "clean", "score": 0, "raw": data}
        
    except json.JSONDecodeError:
        return {"status": "n/a", "score": 0, "raw": raw_response}


class Provider:
    """Base provider class with structured response handling."""
    name: str
    ioc_kinds: tuple[str, ...]
    limiter: Optional[AsyncLimiter] = None
    
    async def query(self, s: aiohttp.ClientSession, t: str, v: str) -> Dict[str, Any]:
        """Query the provider and return structured status."""
        raw_response = await self._raw_query(s, t, v)
        return _parse_response(raw_response, self.name)
    
    async def _raw_query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        """Raw query implementation - to be overridden by subclasses."""
        raise NotImplementedError("Subclasses must implement _raw_query method")

def _key(env: str) -> str:
    """Get environment variable safely."""
    return os.getenv(env, "").strip()

class AbuseIPDB(Provider):
    """AbuseIPDB provider for IP reputation checks."""
    name, ioc_kinds = "abuseipdb", ("ip",)
    key = _key("ABUSEIPDB_API_KEY")
    
    async def _raw_query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
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
    
    async def _raw_query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
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
    
    async def _raw_query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
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
    
    async def _raw_query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        try:
            async with s.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": v}) as r:
                return await r.text()
        except Exception as e:
            log.error(f"URLhaus query failed: {e}")
            return f"error: {str(e)}"

class MalwareBazaar(Provider):
    """Abuse.ch MalwareBazaar malware hash database."""
    name, ioc_kinds = "malwarebazaar", ("hash",)
    
    async def _raw_query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
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
    limiter = AsyncLimiter(_rpm("virustotal", 4), 60)
    
    async def _raw_query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        if not self.key:
            return "nokey"
        try:
            async with self.limiter:
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
    limiter = AsyncLimiter(_rpm("greynoise", 50), 604800)  # 50 requests per week
    
    async def _raw_query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        if not self.key:
            return "nokey"
        try:
            async with self.limiter:
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
    limiter = AsyncLimiter(_rpm("pulsedive", 50), 86400)  # 50 requests per day
    
    async def _raw_query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        if not self.key:
            return "nokey"
        try:
            async with self.limiter:
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
    limiter = AsyncLimiter(_rpm("shodan", 100), 2592000)  # 100 requests per month
    
    async def _raw_query(self, s: aiohttp.ClientSession, t: str, v: str) -> str:
        if not self.key:
            return "nokey"
        try:
            async with self.limiter:
                async with s.get(f"https://api.shodan.io/shodan/host/{v}", params={"key": self.key}, headers=HEAD) as r:
                    return await r.text()
        except Exception as e:
            log.error(f"Shodan query failed: {e}")
            return f"error: {str(e)}"

# Provider instances
ALWAYS_ON = (AbuseIPDB(), OTX(), ThreatFox(), URLHaus(), MalwareBazaar())
RATE_LIMIT = (VirusTotal(), GreyNoise(), Pulsedive(), Shodan())
