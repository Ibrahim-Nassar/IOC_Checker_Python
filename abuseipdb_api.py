"""AbuseIPDB provider adapter for IOC Checker (async unified IOCResult)."""
from __future__ import annotations

import os

import httpx
from async_cache import aget
from ioc_types import IOCResult, IOCStatus


class AbuseIPDBProvider:
    NAME = "abuseipdb"

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
            resp = await aget(url, headers=headers, timeout=5, api_key=self._key)

            if resp.status_code != 200:
                return IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.ERROR,
                    malicious_engines=0,
                    total_engines=0,
                    message=f"HTTP {resp.status_code}",
                )

            data = resp.json()
            score = data["data"]["abuseConfidenceScore"]
            status = IOCStatus.MALICIOUS if score > 0 else IOCStatus.SUCCESS

            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=status,
                malicious_engines=score,
                total_engines=100,
                message="",
            )
        except Exception as exc:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message=str(exc),
            )


__all__ = ["AbuseIPDBProvider"]
