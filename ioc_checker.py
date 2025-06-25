"""
Async IOC checker leveraging the unified provider interface.
• Single-IOC look-ups  • Batch CSV/TXT scans
• Clean console summaries  • Robust CSV parsing
• Cross-platform UTF-8 output
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import pathlib
import sys
from typing import Any, Dict, List

from api_key_store import load as _load_key
from loader import load_iocs
from provider_interface import IOCResult, IOCProvider
from providers import ALWAYS_ON, get_providers
from reports import write_csv
from ioc_types import detect_ioc_type as _detect_ioc_type

# Load API keys from fallback secret store
for _env in (
    "VT_API_KEY",
    "OTX_API_KEY",
    "ABUSEIPDB_API_KEY",
    "THREATFOX_API_KEY",
    "GREYNOISE_API_KEY",
):
    if _env not in os.environ:
        _val = _load_key(_env)
        if _val:
            os.environ[_env] = _val


def detect_ioc_type(value: str) -> tuple[str, str]:
    """Delegate to :func:`ioc_types.detect_ioc_type`."""
    return _detect_ioc_type(value)


# Ensure UTF-8 output on all platforms
try:
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    sys.stderr.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
except AttributeError:
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ioc_checker")

###############################################################################
# Provider querying                                                           #
###############################################################################


async def _query(
    ioc_type: str,
    ioc_value: str,
    providers: List[IOCProvider],
) -> Dict[str, Dict[str, Any]]:
    async def _invoke(prov):
        try:
            result: IOCResult = await asyncio.wait_for(
                asyncio.to_thread(prov.query_ioc, ioc_type, ioc_value),
                timeout=prov.TIMEOUT + 2,
            )
            return prov.NAME, {
                "status": result.status,
                "score": result.score or 0,
                "raw": result.raw,
            }
        except asyncio.TimeoutError:
            return prov.NAME, {"status": "timeout", "score": 0, "raw": {}}
        except Exception as exc:
            log.warning("Provider %s failed: %s", prov.NAME, exc)
            return prov.NAME, {"status": "error", "score": 0, "raw": {"error": str(exc)}}

    tasks = [asyncio.create_task(_invoke(p)) for p in providers]
    pairs = await asyncio.gather(*tasks)
    return {name: data for name, data in pairs}


###############################################################################
# High-level scanning                                                         #
###############################################################################


async def scan_single(ioc_value: str, selected_names: list[str] | None = None):
    ioc_type, normalized = detect_ioc_type(ioc_value)
    if ioc_type == "unknown":
        return {"value": ioc_value, "type": "unknown", "results": {}}

    active = get_providers(selected_names) if selected_names else list(ALWAYS_ON)
    results = await _query(ioc_type, normalized, active)
    return {"value": normalized, "type": ioc_type, "results": results}


async def batch_check_indicators(
    ioc_values: list[str], selected_providers: list[str] | None = None
):
    results = []
    for ioc_value in ioc_values:
        try:
            res = await scan_single(ioc_value, selected_providers)
            results.append(res)
        except Exception as exc:
            log.warning("Failed processing %s: %s", ioc_value, exc)

    flat_rows = [
        {"ioc": r["value"], "verdict": _aggregate_verdict(r["results"]), "flagged_by": _flagged_by(r["results"])}
        for r in results
    ]
    write_csv(pathlib.Path("results.csv"), flat_rows)
    return results


###############################################################################
# Verdict helpers                                                             #
###############################################################################


def _aggregate_verdict(provider_results: Dict[str, Dict[str, Any]]) -> str:
    flagged = sum(1 for r in provider_results.values() if r["status"] == "malicious")
    return "malicious" if flagged >= 2 else "clean"


def _flagged_by(provider_results: Dict[str, Dict[str, Any]]) -> str:
    names = [name for name, r in provider_results.items() if r["status"] == "malicious"]
    return ",".join(names)


###############################################################################
# Console output                                                              #
###############################################################################


def _print_result(provider_name: str, res: "IOCResult") -> None:
    status = res.status
    if status in ("success", "clean"):
        verdict = "malicious" if (res.score or 0) >= 50 else "benign" if (res.score or 0) < 5 else "unknown"
        print(f"{provider_name:<15}: {verdict:<8} score={res.score}", flush=True)
    else:
        print(f"{provider_name:<15}: ERROR – {res.status}", flush=True)


###############################################################################
# File batch mode                                                             #
###############################################################################


async def process_file(path: str, out: str, selected: list[str] | None):
    inpath, outpath = pathlib.Path(path), pathlib.Path(out)
    try:
        iocs = load_iocs(inpath)
    except Exception as exc:
        log.error("Failed to load IOCs: %s", exc)
        return

    results = []
    total = len(iocs)
    for idx, row in enumerate(iocs, 1):
        try:
            res = await scan_single(row["value"], selected)
            results.append(res)
            if idx % 25 == 0:
                log.info("Processed %d/%d", idx, total)
        except KeyboardInterrupt:
            break
        except Exception as exc:
            log.warning("Failed processing %s: %s", row["value"], exc)

    flat_rows = [
        {"ioc": r["value"], "verdict": _aggregate_verdict(r["results"]), "flagged_by": _flagged_by(r["results"])}
        for r in results
    ]
    write_csv(outpath, flat_rows)
    print(f"Report written to {outpath}")


###############################################################################
# CLI Entrypoint                                                              #
###############################################################################


def main() -> None:
    ap = argparse.ArgumentParser(description="IOC checker with async providers")
    ap.add_argument("ioc_type", nargs="?", help="IOC type for single lookup (auto-detect if omitted)")
    ap.add_argument("value", nargs="?", help="IOC value for single lookup")
    ap.add_argument("--file", help="Input file path (CSV, TSV, XLSX, TXT)")
    ap.add_argument("-o", "--out", default="results.csv", help="Output filename")
    ap.add_argument("--providers", help="Comma-separated list of providers to use (by NAME)")
    args = ap.parse_args()

    selected = [p.strip() for p in args.providers.split(",")] if args.providers else None

    if args.value:
        async def _run():
            _sel_objs = get_providers(selected)
            res = await scan_single(args.value, selected)

            print(f"\nIOC  : {res['value']}  ({res['type']})")
            print("-" * 60)
            for prov_obj in _sel_objs:
                pdata = res["results"].get(prov_obj.NAME, {"status": "error", "score": None, "raw": {}})
                _print_result(prov_obj.NAME, IOCResult(**pdata))
            print()

        asyncio.run(_run())
        return

    if args.file:
        asyncio.run(process_file(args.file, args.out, selected))
        return

    ap.error("Provide either (value) or --file")


if __name__ == "__main__":
    main()
