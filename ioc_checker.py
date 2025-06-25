"""
IOC checker with async providers using the new unified result format.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Literal

from ioc_types import IOCResult, IOCStatus, detect_ioc_type
from providers import get_providers

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except AttributeError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ioc_checker")


def aggregate_verdict(results: list[IOCResult]) -> IOCStatus:
    """
    Aggregate multiple IOC results into a single verdict.
    """
    if any(r.status == IOCStatus.MALICIOUS for r in results):
        return IOCStatus.MALICIOUS
    elif any(r.status == IOCStatus.ERROR for r in results):
        return IOCStatus.ERROR
    elif any(r.status == IOCStatus.UNSUPPORTED for r in results) and not any(r.status == IOCStatus.ERROR for r in results):
        return IOCStatus.UNSUPPORTED
    else:
        return IOCStatus.SUCCESS


async def query_providers(ioc: str, ioc_type: Literal["ip", "domain", "url", "hash"], provider_names: list[str] | None = None) -> list[IOCResult]:
    """
    Query multiple providers for an IOC and return their results.
    """
    providers = get_providers(provider_names)
    
    async def query_single_provider(provider):
        try:
            if hasattr(provider, 'query_ioc'):
                result = await asyncio.to_thread(provider.query_ioc, ioc, ioc_type)
                if isinstance(result, IOCResult):
                    return result
                else:
                    return IOCResult(
                        ioc=ioc,
                        ioc_type=ioc_type,
                        status=IOCStatus.ERROR,
                        message="Provider returned invalid result format"
                    )
            else:
                return IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.ERROR,
                    message="Provider does not support new query interface"
                )
        except Exception as e:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                message=f"Provider {getattr(provider, 'NAME', 'unknown')} failed: {str(e)}"
            )
    
    tasks = [asyncio.create_task(query_single_provider(provider)) for provider in providers]
    results = await asyncio.gather(*tasks)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="IOC checker with unified provider interface")
    parser.add_argument("ioc", nargs="?", help="IOC value to check")
    parser.add_argument("--type", help="IOC type (ip, domain, url, hash) - auto-detected if not provided")
    parser.add_argument("--providers", help="Comma-separated list of provider names to use")
    
    args = parser.parse_args()
    
    if not args.ioc:
        parser.error("IOC value is required")
    
    if args.type:
        ioc_type = args.type.lower()
        if ioc_type not in ["ip", "domain", "url", "hash"]:
            parser.error("Invalid IOC type. Must be one of: ip, domain, url, hash")
        normalized_ioc = args.ioc
    else:
        detected_type, normalized_ioc = detect_ioc_type(args.ioc)
        if detected_type == "unknown":
            parser.error(f"Could not auto-detect IOC type for: {args.ioc}")
        ioc_type = detected_type
    
    provider_names = [p.strip() for p in args.providers.split(",")] if args.providers else None
    
    async def run_check():
        print(f"\nChecking IOC: {normalized_ioc} (type: {ioc_type})")
        print("-" * 60)
        
        results = await query_providers(normalized_ioc, ioc_type, provider_names)
        
        for result in results:
            provider_name = result.message.split()[1] if "Provider" in result.message else "unknown"
            for provider in get_providers(provider_names):
                if hasattr(provider, 'NAME') and provider.NAME.lower() in result.message.lower():
                    provider_name = provider.NAME
                    break
            
            print(f"{provider_name}: {result.status.name} (mal {result.malicious_engines}/{result.total_engines})")
        
        overall_verdict = aggregate_verdict(results)
        print(f"\nOVERALL: {overall_verdict.name}")
    
    asyncio.run(run_check())


__all__ = ["main", "aggregate_verdict"]


if __name__ == "__main__":
    main()
