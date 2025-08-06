"""
VirusTotal provider adapter for the IOC Checker project.
"""
from __future__ import annotations

import os
import base64
from typing import Literal

from providers_base import BaseProvider
from ioc_types import IOCResult, IOCStatus


class VirusTotalProvider(BaseProvider):
    
    NAME = "virustotal"
    SUPPORTED_TYPES = {"ip", "domain", "url", "hash"}
    
    def __init__(self, api_key: str | None = None) -> None:
        if api_key is None:
            api_key = os.getenv("VIRUSTOTAL_API_KEY") or os.getenv("VT_API_KEY")
        super().__init__(api_key, timeout=5.0)
    
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
        headers = {"x-apikey": self._key}
        
        try:
            data = await self._safe_request(url, headers=headers)
            
            if "data" not in data or "attributes" not in data["data"]:
                return self._create_error_result(ioc, ioc_type, "Unexpected API response structure")
            
            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            
            if not stats:
                return self._create_error_result(ioc, ioc_type, "Missing analysis statistics in response")
            
            malicious_engines = stats.get("malicious", 0)
            total_engines = sum(stats.values())
            
            return self._create_success_result(ioc, ioc_type, malicious_engines, total_engines)
            
        except Exception as e:
            error_msg = str(e)
            # Provide more user-friendly messages for common cases
            if "Resource not found" in error_msg:
                if ioc_type == "hash":
                    error_msg = "File not found in VirusTotal database"
                elif ioc_type == "url":
                    error_msg = "URL not previously scanned by VirusTotal"
                elif ioc_type == "domain":
                    error_msg = "Domain not found in VirusTotal database"
                elif ioc_type == "ip":
                    error_msg = "IP address not found in VirusTotal database"
                else:
                    error_msg = "Not found in VirusTotal database"
                
                # Return NOT_FOUND status instead of ERROR for resource not found
                return IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.NOT_FOUND,
                    malicious_engines=0,
                    total_engines=0,
                    message=error_msg
                )
            elif "HTTP 400" in error_msg:
                error_msg = f"Invalid {ioc_type} format"
            elif "API key invalid" in error_msg:
                error_msg = "Invalid VirusTotal API key"
            elif "Rate limited" in error_msg:
                error_msg = "VirusTotal rate limit exceeded"
            
            return self._create_error_result(ioc, ioc_type, error_msg)


__all__ = ["VirusTotalProvider"]
