# ioc_checker.py
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
import pathlib
import sys
import aiohttp
from typing import Dict, Any, List
from aiohttp_client_cache import CachedSession, SQLiteBackend
# --- auto-load API keys -------------------------
import os
from api_key_store import load as _load_key

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
# ------------------------------------------------
from provider_interface import IOCResult
from providers import get_providers, ALWAYS_ON, RATE_LIMIT
from reports   import WRITERS, write_csv
from loader import load_iocs

# Ensure UTF-8 output on all platforms
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except AttributeError:
    # Python < 3.7 fallback
    pass

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ioc_checker")

###############################################################################
# Helper formatting functions                                                 #
###############################################################################

def _fmt_raw(data: Dict[str, Any] | None) -> str:
    """Format raw provider JSON for concise console display."""
    if not data:
        return "unparseable"

    # AbuseIPDB
    if "abuseConfidenceScore" in str(data):
        try:
            s = data["data"]["abuseConfidenceScore"]
            wl = data["data"]["isWhitelisted"]
            return "Clean (whitelisted)" if wl else ("Clean" if s == 0 else f"Malicious – score {s}")
        except Exception:
            return "Parse error"

    # VirusTotal
    if "last_analysis_stats" in str(data):
        try:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            if malicious or suspicious:
                return f"Malicious – {malicious} malicious, {suspicious} suspicious"
            if harmless or undetected:
                return "Clean"
        except Exception:
            return "Parse error"

    # OTX
    if "pulse_info" in str(data):
        try:
            count = data["pulse_info"].get("count", 0)
            return "Clean" if count == 0 else f"Malicious – {count} OTX pulse{'s' if count!=1 else ''}"
        except Exception:
            return "Parse error"

    # ThreatFox
    if data.get("query_status") == "no_result":
        return "Clean"
    if data.get("query_status") == "ok" and data.get("data"):
        return f"Malicious – {len(data['data'])} threats"

    return "Unknown"

###############################################################################
# Provider orchestration                                                      #
###############################################################################

async def _query(
    ioc_type: str,
    ioc_value: str,
    providers: List[IOCProvider],
) -> Dict[str, Dict[str, Any]]:
    """Run provider queries concurrently returning uniform dict structure."""

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
# High-level scanning helpers                                                 #
###############################################################################

async def scan_single(ioc_value: str, rate: bool, selected_names: list[str] | None = None):
    ioc_type, normalized = detect_ioc_type(ioc_value)
    if ioc_type == "unknown":
        return {"value": ioc_value, "type": "unknown", "results": {}}

    active = list(ALWAYS_ON) + (list(RATE_LIMIT) if rate else [])
    if selected_names:
        active = [p for p in active if p.NAME.lower() in {s.lower() for s in selected_names}]

    results = await _query(ioc_type, normalized, active)
    return {"value": normalized, "type": ioc_type, "results": results}

###############################################################################
# CLI entry-point                                                           #
###############################################################################

def main() -> None:
    ap = argparse.ArgumentParser(description="IOC checker with async providers")
    ap.add_argument("ioc_type", nargs="?", help="IOC type for single lookup (auto-detect if omitted)")
    ap.add_argument("value", nargs="?", help="IOC value for single lookup")
    ap.add_argument("--file", help="Input file path (CSV, TSV, XLSX, TXT)")
    ap.add_argument("-o", "--out", default="results.csv", help="Output filename")
    ap.add_argument("--rate", action="store_true", help="Include rate-limited providers")
    ap.add_argument("--providers", help="Comma-separated list of providers to use (by NAME)")

    args = ap.parse_args()

    selected = [p.strip() for p in args.providers.split(",")] if args.providers else None

    if args.value:
        # Single lookup mode
        async def _run():
            res = await scan_single(args.value, args.rate, selected)
            print(f"\nIOC  : {res['value']}  ({res['type']})")
            print("-" * 48)
            for prov, pdata in res["results"].items():
                raw_fmt = _fmt_raw(pdata["raw"])
                print(f"{prov:<12}: {pdata['status']:<10} | {raw_fmt}")
            print()
        asyncio.run(_run())
        return

    if args.file:
        asyncio.run(process_file(args.file, args.out, args.rate, selected))
        return

    ap.error("Provide either (value) or --file")

###############################################################################
# Batch-file processing (simplified, retains CSV export)                      #
###############################################################################

async def process_file(path: str, out: str, rate: bool, selected: list[str] | None):
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
            res = await scan_single(row["value"], rate, selected)
            results.append(res)
            if idx % 25 == 0:
                log.info("Processed %d/%d", idx, total)
        except KeyboardInterrupt:
            break
        except Exception as exc:
            log.warning("Failed processing %s: %s", row["value"], exc)

    # Minimal CSV export
    flat_rows = [
        {"ioc": r["value"], "verdict": _aggregate_verdict(r["results"]), "flagged_by": _flagged_by(r["results"]) }
        for r in results
    ]
    write_csv(outpath, flat_rows)
    print(f"Report written to {outpath}")

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
# Script entry-point                                                          #
###############################################################################

if __name__ == "__main__":
    main()
