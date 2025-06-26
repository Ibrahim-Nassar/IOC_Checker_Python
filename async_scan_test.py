"""
Smoke-test: run three async providers in parallel and print their statuses.
Uses dummy API keys, so expected output is three IOCStatus.ERROR values.
"""

import asyncio
import os
import virustotal_api
import abuseipdb_api
import greynoise_api

# Dummy keys so providers initialise without throwing
os.environ.setdefault("VIRUSTOTAL_API_KEY", "dummy")
os.environ.setdefault("ABUSEIPDB_API_KEY", "dummy")
os.environ.setdefault("GREYNOISE_API_KEY", "dummy")

async def main() -> None:
    vt = virustotal_api.VirusTotalProvider("dummy")
    ab = abuseipdb_api.AbuseIPDBProvider("dummy")
    gn = greynoise_api.GreyNoiseProvider("dummy")

    results = await asyncio.gather(
        vt.query_ioc("8.8.8.8", "ip"),
        ab.query_ioc("8.8.8.8", "ip"),
        gn.query_ioc("8.8.8.8", "ip"),
    )
    print([r.status for r in results])

if __name__ == "__main__":
    asyncio.run(main()) 