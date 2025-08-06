"""IOC scanner module with async providers using the unified result format."""
from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from typing import Dict, Literal, Any, cast
import contextlib

from ioc_types import IOCResult, IOCStatus, detect_ioc_type
import providers
from api_key_store import load_saved_keys

# ── ensure UTF-8 capable streams without upsetting Pyright ───────────────
if hasattr(sys.stdout, "reconfigure"):   # type: ignore[attr-defined]
    cast(Any, sys.stdout).reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):   # type: ignore[attr-defined]
    cast(Any, sys.stderr).reconfigure(encoding="utf-8")
# ─────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ioc_checker")


def aggregate_verdict(results: list[IOCResult]) -> IOCStatus:
    """Aggregate multiple IOC results into a single verdict.
    
    Precedence logic:
    1. ERROR - if any provider errors exist (even with malicious results)
    2. MALICIOUS - if any provider reports malicious (without errors)
    3. UNSUPPORTED - if all providers are unsupported
    4. NOT_FOUND - if all providers report not found (no success/malicious)
    5. SUCCESS - if all providers report success/clean or not found
    """
    if not results:  # Handle empty results
        return IOCStatus.SUCCESS
        
    if any(r.status == IOCStatus.ERROR for r in results):
        return IOCStatus.ERROR
    elif any(r.status == IOCStatus.MALICIOUS for r in results):
        return IOCStatus.MALICIOUS
    elif any(r.status == IOCStatus.UNSUPPORTED for r in results) and not any(r.status in [IOCStatus.SUCCESS, IOCStatus.NOT_FOUND] for r in results):
        return IOCStatus.UNSUPPORTED
    elif all(r.status == IOCStatus.NOT_FOUND for r in results):
        return IOCStatus.NOT_FOUND
    else:
        return IOCStatus.SUCCESS


async def scan_ioc(ioc: str, ioc_type: str, provider_list: list | None = None) -> Dict[str, IOCResult]:
    """Scan IOC across multiple providers concurrently."""
    if provider_list is None:
        from providers import get_providers
        provider_list = get_providers()

    async def query_single_provider(provider):
        provider_name = getattr(provider, "NAME", "unknown")
        
        try:
            async def _run():
                return await provider.query_ioc(ioc, ioc_type)
            
            task = asyncio.create_task(_run())
            result = await asyncio.wait_for(task, timeout=15.0)
            if isinstance(result, IOCResult):
                return provider_name, result
            else:
                return provider_name, IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.ERROR,
                    malicious_engines=0,
                    total_engines=0,
                    message="Provider returned invalid result format"
                )
        except asyncio.TimeoutError:
            # The wait_for timed out
            return provider_name, IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message="Provider timeout (15 seconds exceeded)"
            )
        except asyncio.CancelledError:
            # Handle cancellation
            return provider_name, IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message="Provider operation was cancelled"
            )
        except BaseException:
            # Catch EVERYTHING including system exceptions and cancellations
            return provider_name, IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message="Provider operation failed"
            )

    tasks = [asyncio.create_task(query_single_provider(p)) for p in provider_list]
    
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
    except asyncio.CancelledError:
        # Handle external cancellation - create clean error results
        scan_results = {
            f"cancelled_{i}": IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message="Batch cancelled"
            )
            for i, _ in enumerate(provider_list, 1)
        }
        # Cancel all provider tasks and clean up
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        return scan_results
    
    scan_results: Dict[str, IOCResult] = {}
    exception_counter = 0
    for item in results:
        if isinstance(item, Exception):
            exception_counter += 1
            # Handle CancelledError specifically
            if isinstance(item, asyncio.CancelledError):
                message = "Operation was cancelled"
            else:
                message = str(item)
            scan_results[f"provider_error_{exception_counter}"] = IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message=message
            )
            continue

        # Ensure `item` is the expected tuple format
        try:
            provider_name, ioc_result = item  # type: ignore[misc]
            scan_results[provider_name] = ioc_result
        except (ValueError, TypeError) as e:
            # Handle unexpected item format
            exception_counter += 1
            scan_results[f"provider_error_{exception_counter}"] = IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message=f"Unexpected result format: {type(item).__name__}"
            )
    
    return scan_results


def scan_ioc_sync(ioc: str, ioc_type: str) -> Dict[str, IOCResult]:
    """Sync wrapper for GUI/CLI convenience."""
    from providers import get_providers
    
    try:
        asyncio.get_running_loop()
        # If we get here, there IS a running loop, so raise error
        raise RuntimeError("scan_ioc_sync cannot be called from an async loop")
    except RuntimeError as e:
        # Check if it's our custom error (loop was found)
        if "scan_ioc_sync cannot be called from an async loop" in str(e):
            raise
        # Otherwise, it's the normal "no running event loop" error, which is what we want
        pass
    
    return asyncio.run(scan_ioc(ioc, ioc_type, get_providers()))


def main() -> None:
    # Load saved API keys before any provider discovery
    load_saved_keys()
    
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
    
    # Get cached provider instances and build name→instance mapping
    from providers import get_providers
    all_providers = get_providers()
    provider_map = {}
    for provider in all_providers:
        try:
            provider_map[provider.NAME.lower()] = provider
        except AttributeError:
            continue
    
    provider_instances = None
    if args.providers:
        provider_names = [p.strip().lower() for p in args.providers.split(",")]
        provider_instances = []
        for name in provider_names:
            if name in provider_map:
                provider_instances.append(provider_map[name])
            else:
                available = ", ".join(provider_map.keys())
                parser.error(f"Unknown provider '{name}'. Available: {available}")
    
    async def run_check():
        print(f"\nChecking IOC: {normalized_ioc} (type: {ioc_type})")
        print("-" * 60)
        
        results = await scan_ioc(normalized_ioc, ioc_type, provider_instances)
        
        for provider_name, result in results.items():
            status_txt = (
                result.status.name          # IOCStatus
                if isinstance(result.status, IOCStatus)
                else str(result.status)     # raw string fallback
            )
            print(f"{provider_name}: {status_txt} (mal {result.malicious_engines}/{result.total_engines})")
        
        overall_verdict = aggregate_verdict(list(results.values()))
        print(f"\nOVERALL: {overall_verdict.name}")
    
    asyncio.run(run_check())


__all__ = ["aggregate_verdict", "scan_ioc", "scan_ioc_sync"]


if __name__ == "__main__":
    main()
