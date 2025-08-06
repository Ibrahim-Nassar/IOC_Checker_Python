"""AbuseIPDB provider adapter for IOC Checker (async unified IOCResult)."""
from __future__ import annotations

import os

import httpx
from ioc_types import IOCResult, IOCStatus


class AbuseIPDBProvider:
    NAME = "abuseipdb"
    SUPPORTED_TYPES = {"ip"}

    def __init__(self, api_key: str | None = None):
        self._key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        if not self._key:
            raise RuntimeError("ABUSEIPDB_API_KEY missing")

    async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
        if ioc_type.lower() != "ip":
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.UNSUPPORTED,
                malicious_engines=0,
                total_engines=0,
                message="Only IP addresses are supported",
            )

        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ioc}&maxAgeInDays=90"
        headers = {"Key": self._key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(url, headers=headers)

            if resp.status_code != 200:
                # Provide user-friendly error messages
                if resp.status_code == 404:
                    error_msg = "IP address not found in AbuseIPDB database"
                    return IOCResult(
                        ioc=ioc,
                        ioc_type=ioc_type,
                        status=IOCStatus.NOT_FOUND,
                        malicious_engines=0,
                        total_engines=0,
                        message=error_msg,
                    )
                elif resp.status_code == 403:
                    error_msg = "Invalid AbuseIPDB API key or insufficient permissions"
                elif resp.status_code == 429:
                    error_msg = "AbuseIPDB rate limit exceeded"
                elif resp.status_code >= 500:
                    error_msg = "AbuseIPDB server error"
                else:
                    error_msg = f"HTTP {resp.status_code}"
                
                return IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.ERROR,
                    malicious_engines=0,
                    total_engines=0,
                    message=error_msg,
                )

            data = resp.json()
            score = data["data"]["abuseConfidenceScore"]
            status = IOCStatus.MALICIOUS if score > 0 else IOCStatus.SUCCESS

            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=status,
                malicious_engines=score,
                # AbuseIPDB returns a 0-100 confidence score, treat 100 as "all engines"
                total_engines=100,
                message="",
            )
        except Exception as exc:
            # Provide user-friendly error messages
            error_msg = str(exc)
            if "timeout" in error_msg.lower():
                error_msg = "Connection timeout - AbuseIPDB server slow to respond"
            elif "connection" in error_msg.lower():
                error_msg = "Network connection error"
            elif "json" in error_msg.lower() and "decode" in error_msg.lower():
                error_msg = "Invalid response from AbuseIPDB server"
            
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message=error_msg,
            )


__all__ = ["AbuseIPDBProvider"]
