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
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message=str(e)
            )


__all__ = ["OTXProvider"]


