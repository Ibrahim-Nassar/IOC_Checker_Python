"""
AlienVault OTX provider adapter for the IOC Checker project.
"""
from __future__ import annotations

import os
import requests
from typing import Literal

from ioc_types import IOCStatus, IOCResult


class OTXProvider:
    
    NAME = "otx"
    
    def __init__(self, api_key: str | None = None) -> None:
        if api_key is None:
            api_key = os.getenv("OTX_API_KEY") or os.getenv("ALIENVAULT_OTX_API_KEY")
        
        if not api_key:
            raise RuntimeError("OTX API key not found in environment variables")
        
        self.api_key = api_key
    
    def query_ioc(self, ioc: str, ioc_type: Literal["ip", "domain", "url", "hash"]) -> IOCResult:
        if ioc_type == "url":
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.UNSUPPORTED,
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
            response = requests.get(url, headers=headers, timeout=5)
            response.raise_for_status()
            
            data = response.json()
            
            pulses = data.get("pulse_info", {}).get("pulses", [])
            pulse_count = len(pulses)
            
            status = IOCStatus.MALICIOUS if pulse_count > 0 else IOCStatus.SUCCESS
            
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=status,
                malicious_engines=pulse_count,
                total_engines=pulse_count
            )
            
        except requests.exceptions.RequestException as e:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                message=f"Request failed: {str(e)}"
            )
        except (KeyError, ValueError) as e:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                message=f"Failed to parse response: {str(e)}"
            )


__all__ = ["OTXProvider"]


