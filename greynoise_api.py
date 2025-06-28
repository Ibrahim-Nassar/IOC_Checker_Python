"""GreyNoise provider adapter for IOC Checker (async unified IOCResult)."""
from __future__ import annotations

import os

from async_cache import aget
from ioc_types import IOCResult, IOCStatus


class GreyNoiseProvider:
    NAME = "greynoise"

    def __init__(self, api_key: str | None = None, timeout: float = 5.0):
        self._key = api_key or os.getenv("GREYNOISE_API_KEY")
        self._timeout = timeout
        if not self._key:
            raise RuntimeError("GREYNOISE_API_KEY missing")

    async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
        if ioc_type.lower() != "ip":
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.UNSUPPORTED,
                malicious_engines=0,
                total_engines=0,
                message="GreyNoise scans IPs only",
            )

        url = f"https://api.greynoise.io/v3/community/{ioc}"
        headers = {"key": self._key, "Accept": "application/json"}

        try:
            resp = await aget(url, headers=headers, timeout=self._timeout, api_key=self._key)

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
            classification = data.get("classification", "unknown")
            is_malicious = classification == "malicious"
            status = IOCStatus.MALICIOUS if is_malicious else IOCStatus.SUCCESS

            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=status,
                malicious_engines=1 if is_malicious else 0,
                total_engines=1,
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


__all__ = ["GreyNoiseProvider"]
