"""
VirusTotal provider adapter for the IOC Checker project.
"""
from __future__ import annotations

import os
import base64
from typing import Literal

from async_cache import aget
from ioc_types import IOCResult, IOCStatus


class VirusTotalProvider:
    
    NAME = "virustotal"
    
    def __init__(self, api_key: str | None = None) -> None:
        if api_key is None:
            api_key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
        
        if not api_key:
            raise RuntimeError("VirusTotal API key not found in environment variables")
        
        self.api_key = api_key
    
    def _encode_url_for_vt(self, url: str) -> str:
        """Encode URL for VirusTotal API: UTF-8, lowercase, strip, base64url without padding."""
        normalized = url.strip().lower()
        encoded_bytes = base64.urlsafe_b64encode(normalized.encode('utf-8'))
        # Remove padding
        return encoded_bytes.decode('ascii').rstrip('=')
    
    async def query_ioc(self, ioc: str, ioc_type: Literal["ip", "domain", "url", "hash"]) -> IOCResult:
        if ioc_type == "url":
            # Use URL endpoint with base64url encoding
            url_id = self._encode_url_for_vt(ioc)
            endpoint = f"/urls/{url_id}"
        else:
            endpoint_map = {
                "ip": f"/ip_addresses/{ioc}",
                "domain": f"/domains/{ioc}",
                "hash": f"/files/{ioc}"
            }
            endpoint = endpoint_map[ioc_type]
        
        url = f"https://www.virustotal.com/api/v3{endpoint}"
        headers = {"x-apikey": self.api_key}
        
        try:
            resp = await aget(url, headers=headers, timeout=5.0, api_key=self.api_key)
            
            if resp.status_code != 200:
                return IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.ERROR,
                    malicious_engines=0,
                    total_engines=0,
                    message=f"HTTP {resp.status_code}"
                )
            
            data = resp.json()
            
            if "data" not in data or "attributes" not in data["data"]:
                return IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.ERROR,
                    malicious_engines=0,
                    total_engines=0,
                    message="Unexpected API response structure"
                )
            
            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            
            if not stats:
                return IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.ERROR,
                    malicious_engines=0,
                    total_engines=0,
                    message="Missing analysis statistics in response"
                )
            
            malicious_engines = stats.get("malicious", 0)
            total_engines = sum(stats.values())
            
            status = IOCStatus.MALICIOUS if malicious_engines > 0 else IOCStatus.SUCCESS
            
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=status,
                malicious_engines=malicious_engines,
                total_engines=total_engines,
                message=""
            )
            
        except Exception as e:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message=str(e)
            )


__all__ = ["VirusTotalProvider"]
