"""IOC scanner module with async providers using the unified result format."""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Dict, Literal

from ioc_types import IOCResult, IOCStatus, detect_ioc_type
import providers

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except AttributeError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ioc_checker")


def aggregate_verdict(results: list[IOCResult]) -> IOCStatus:
    """Aggregate multiple IOC results into a single verdict."""
    if any(r.status == IOCStatus.MALICIOUS for r in results):
        return IOCStatus.MALICIOUS
    elif any(r.status == IOCStatus.ERROR for r in results):
        return IOCStatus.ERROR
    elif any(r.status == IOCStatus.UNSUPPORTED for r in results) and not any(r.status == IOCStatus.ERROR for r in results):
        return IOCStatus.UNSUPPORTED
    else:
        return IOCStatus.SUCCESS


async def scan_ioc(ioc: str, ioc_type: str, provider_list: list | None = None) -> Dict[str, IOCResult]:
    """Scan IOC across multiple providers concurrently."""
    if provider_list is None:
        provider_list = providers.PROVIDERS

    async def query_single_provider(provider_cls):
        try:
            provider = provider_cls()
            if hasattr(provider, 'query_ioc'):
                result = await provider.query_ioc(ioc, ioc_type)
                if isinstance(result, IOCResult):
                    return provider.NAME, result
                else:
                    return provider.NAME, IOCResult(
                        ioc=ioc,
                        ioc_type=ioc_type,
                        status=IOCStatus.ERROR,
                        malicious_engines=0,
                        total_engines=0,
                        message="Provider returned invalid result format"
                    )
            else:
                return provider.NAME, IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.ERROR,
                    malicious_engines=0,
                    total_engines=0,
                    message="Provider does not support async query interface"
                )
        except Exception as e:
            provider_name = getattr(provider_cls, 'NAME', 'unknown')
            return provider_name, IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message=str(e)
            )

    tasks = [query_single_provider(provider_cls) for provider_cls in provider_list]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    scan_results = {}
    for result in results:
        if isinstance(result, Exception):
            scan_results["unknown"] = IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message=str(result)
            )
        else:
            provider_name, ioc_result = result
            scan_results[provider_name] = ioc_result
    
    return scan_results


def scan_ioc_sync(ioc: str, ioc_type: str) -> Dict[str, IOCResult]:
    """Sync wrapper for GUI/CLI convenience."""
    return asyncio.run(scan_ioc(ioc, ioc_type, providers.PROVIDERS))


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
    
    # Build name→class mapping from available providers
    provider_map = {}
    for provider_cls in providers.PROV_CLASSES:
        try:
            provider_map[provider_cls.NAME.lower()] = provider_cls
        except AttributeError:
            continue
    
    provider_classes = None
    if args.providers:
        provider_names = [p.strip().lower() for p in args.providers.split(",")]
        provider_classes = []
        for name in provider_names:
            if name in provider_map:
                provider_classes.append(provider_map[name])
            else:
                available = ", ".join(provider_map.keys())
                parser.error(f"Unknown provider '{name}'. Available: {available}")
    
    async def run_check():
        print(f"\nChecking IOC: {normalized_ioc} (type: {ioc_type})")
        print("-" * 60)
        
        results = await scan_ioc(normalized_ioc, ioc_type, provider_classes)
        
        for provider_name, result in results.items():
            print(f"{provider_name}: {result.status.name} (mal {result.malicious_engines}/{result.total_engines})")
        
        overall_verdict = aggregate_verdict(list(results.values()))
        print(f"\nOVERALL: {overall_verdict.name}")
    
    asyncio.run(run_check())


__all__ = ["aggregate_verdict", "scan_ioc", "scan_ioc_sync"]


if __name__ == "__main__":
    main()
