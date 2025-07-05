"""ThreatFox provider adapter for IOC Checker (async unified IOCResult)."""
from __future__ import annotations

from async_cache import apost
from ioc_types import IOCResult, IOCStatus


class ThreatFoxProvider:
    NAME = "threatfox"
    SUPPORTED_TYPES = {"ip", "domain", "url", "hash"}

    async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
        if ioc_type.lower() not in self.SUPPORTED_TYPES:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.UNSUPPORTED,
                malicious_engines=0,
                total_engines=0,
                message="Type not supported",
            )

        body = {"query": "ioc", "search": ioc}

        try:
            resp = await apost("https://threatfox-api.abuse.ch/api/v1/", json=body, timeout=5)

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
            records = data.get("data", [])
            is_hit = isinstance(records, list) and len(records) > 0
            status = IOCStatus.MALICIOUS if is_hit else IOCStatus.SUCCESS
            malicious_engines = len(records) if is_hit else 0

            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=status,
                malicious_engines=malicious_engines,
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


__all__ = ["ThreatFoxProvider"]
