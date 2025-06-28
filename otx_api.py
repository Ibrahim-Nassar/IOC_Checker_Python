"""
AlienVault OTX provider adapter for the IOC Checker project.
"""
from __future__ import annotations

import os
from typing import Literal

from async_cache import aget
from ioc_types import IOCResult, IOCStatus


class OTXProvider:
    
    NAME = "otx"
    
    def __init__(self, api_key: str | None = None) -> None:
        if api_key is None:
            api_key = os.getenv("OTX_API_KEY") or os.getenv("ALIENVAULT_OTX_API_KEY")
        
        if not api_key:
            raise RuntimeError("OTX API key not found in environment variables")
        
        self.api_key = api_key
    
    async def query_ioc(self, ioc: str, ioc_type: Literal["ip", "domain", "url", "hash"]) -> IOCResult:
        if ioc_type == "url":
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.UNSUPPORTED,
                malicious_engines=0,
                total_engines=0,
                message="URL scanning not supported by this provider"
            )
        
        endpoint_map = {
            "ip": f"IPv4/{ioc}/general",
            "domain": f"domain/{ioc}/general",
            "hash": f"file/{ioc}/general"
        }
        
        url = f"https://otx.alienvault.com/api/v1/indicators/{endpoint_map[ioc_type]}"
        headers = {"X-OTX-API-KEY": self.api_key}
        
        try:
            resp = await aget(url, headers=headers, timeout=15.0, api_key=self.api_key)
            
            if resp.status_code != 200:
                error_msg = f"HTTP {resp.status_code}"
                try:
                    error_body = resp.text
                    if error_body:
                        error_msg += f": {error_body[:200]}"
                except Exception:
                    pass
                
                return IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.ERROR,
                    malicious_engines=0,
                    total_engines=0,
                    message=error_msg
                )
            
            data = resp.json()
            
            pulses = data.get("pulse_info", {}).get("pulses", [])
            pulse_count = len(pulses)
            
            status = IOCStatus.MALICIOUS if pulse_count > 0 else IOCStatus.SUCCESS
            
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=status,
                malicious_engines=pulse_count,
                total_engines=pulse_count,
                message=""
            )
            
        except Exception as e:
            import traceback
            error_type = type(e).__name__
            
            # Provide user-friendly error messages
            if "timeout" in error_type.lower() or "ReadTimeout" in str(e):
                error_detail = "Connection timeout - OTX server slow to respond"
            elif "connection" in error_type.lower():
                error_detail = "Network connection error"
            elif "403" in str(e) or "401" in str(e):
                error_detail = "API key authentication failed"
            else:
                error_detail = f"{error_type}: {str(e)}"
            
            # Add full traceback for debugging (can be removed in production)
            traceback.print_exc()
            
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message=error_detail
            )


__all__ = ["OTXProvider"]


