# ioc_checker.py
"""
Async IOC checker with robust UTF-8 handling and comprehensive error management.
• Single-IOC look-ups  • Batch CSV/TXT scans
• Clean console summaries  • Robust CSV parsing
• Cross-platform UTF-8 output
"""
from __future__ import annotations
import argparse, asyncio, json, logging, pathlib, sys, aiohttp
from typing import Dict, Any
from aiohttp_client_cache import CachedSession, SQLiteBackend
from ioc_types import detect_ioc_type
from providers import ALWAYS_ON, RATE_LIMIT
from reports   import WRITERS
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

# ────────── concise console formatter ──────────
def _fmt(data: Dict[str, Any]) -> str:
    """Format provider response for console display."""
    # Handle None input gracefully
    if data is None:
        return "unparseable"

    # AbuseIPDB format
    if "abuseConfidenceScore" in data:
        try:
            s = data["data"]["abuseConfidenceScore"]
            wl = data["data"]["isWhitelisted"]
            return "Clean (whitelisted)" if wl else ("Clean" if s == 0 else f"Malicious – score {s}")
        except (KeyError, TypeError) as e:
            log.debug(f"AbuseIPDB parsing error: {e}")
            return "Parse error"
    
    # VirusTotal format
    if "last_analysis_stats" in data:
        try:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            
            if malicious > 0 or suspicious > 0:
                return f"Malicious – {malicious} malicious, {suspicious} suspicious"
            elif harmless > 0 or undetected > 0:
                return "Clean"
            else:
                return "Unknown"
        except (KeyError, TypeError) as e:
            log.debug(f"VirusTotal parsing error: {e}")
            return "Parse error"    # OTX format
    if "pulse_info" in data:
        try:
            c = data["pulse_info"]["count"]
            return "Clean" if c == 0 else f"Malicious – {c} OTX pulse{'s' if c!=1 else ''}"
        except (KeyError, TypeError) as e:
            log.debug(f"OTX parsing error: {e}")
            return "Parse error"

    # ThreatFox format
    if "query_status" in data:
        if data.get("query_status") == "no_result":
            return "Clean"
        elif data.get("query_status") == "ok" and data.get("data"):
            threat_count = len(data.get("data", []))
            return f"Malicious – {threat_count} threat{'s' if threat_count != 1 else ''}"
        
    # URLhaus format
    if data.get("query_status") == "ok" and "url" in str(data).lower():
        return "Malicious – URLhaus hit"
    elif data.get("query_status") == "no_result" and "url" in str(data).lower():
        return "Clean"

    # Generic fallback for unknown providers
    return "Unknown"

# ────────── provider orchestration ──────────
async def _query(session: aiohttp.ClientSession, typ: str, val: str, rate: bool, selected_providers: list = None) -> Dict[str, str]:
    """Query available providers for an IOC."""
    if selected_providers:
        # Use only the specifically selected providers
        all_providers = list(ALWAYS_ON) + list(RATE_LIMIT)
        provs = [p for p in all_providers if p.name in selected_providers]
    else:
        # Default behavior: always-on + rate-limited if enabled
        provs = list(ALWAYS_ON) + (list(RATE_LIMIT) if rate else [])
    
    tasks = [p.query(session, typ, val) for p in provs if typ in p.ioc_kinds]
    try:
        outs = await asyncio.gather(*tasks, return_exceptions=True)
        results = {}
        for p, o in zip([q for q in provs if typ in q.ioc_kinds], outs):
            if isinstance(o, Exception):
                error_msg = str(o)
                if "timeout" in error_msg.lower():
                    error_msg = "timeout"
                elif "connection" in error_msg.lower():
                    error_msg = "connection failed"
                elif "ssl" in error_msg.lower():
                    error_msg = "ssl error"
                log.warning(f"Provider {p.name} failed: {o}")
                results[p.name] = {"status": "error", "score": 0, "raw": f"error: {error_msg}"}
            else:
                results[p.name] = o
        return results
    except Exception as e:
        log.error(f"Query orchestration failed: {e}")
        return {"error": str(e)}

async def scan_single(session: aiohttp.ClientSession, val: str, rate: bool, selected_providers: list = None) -> Dict[str, Any]:
    """Scan a single IOC value."""
    typ, norm = detect_ioc_type(val)
    if typ == "unknown":
        log.debug(f"Unknown IOC type for value: {val}")
        return {"value": val, "type": "unknown", "results": {}}
    return {"value": norm, "type": typ,
            "results": await _query(session, typ, norm, rate, selected_providers)}

# ────────── format-agnostic file processing ──────────
async def process_file(file_path: str, out: str, rate: bool, selected_providers: list = None, limit: int = None) -> None:
    """Process any supported file format with format-agnostic IOC discovery."""
    inpath, outpath = pathlib.Path(file_path), pathlib.Path(out)
    
    try:
        # Load IOCs using format-agnostic loader
        print(f"Loading IOCs from {file_path}...")
        iocs = load_iocs(inpath)
        
        # Apply limit if specified
        total_iocs = len(iocs)
        if limit and limit < total_iocs:
            iocs = iocs[:limit]
            print(f"Limited to processing {limit} of {total_iocs} IOCs")
        
        print(f"Processing {len(iocs)} IOCs:")
        type_counts = {}
        for ioc in iocs:
            ioc_type = ioc['type']
            type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
        
        for ioc_type, count in type_counts.items():
            print(f"  {ioc_type}: {count}")
        
    except (FileNotFoundError, ValueError) as e:
        log.error(f"Failed to load IOCs: {e}")
        print(f"Error: {e}")
        return
    
    # Process IOCs
    results = []
    try:
        conn = aiohttp.TCPConnector(limit_per_host=10, ssl=False, force_close=True)
        # Set reasonable timeouts for all requests
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
    except Exception as e:
        log.error(f"Failed to create connector: {e}")
        return
    
    try:
        async with CachedSession(cache=SQLiteBackend(cache_name=".cache/ioc_cache.sqlite", expire_after=86400), connector=conn, timeout=timeout) as sess:
            for idx, ioc_data in enumerate(iocs, 1):
                try:
                    # Add progress output for GUI
                    print(f"Processing IOC: {ioc_data['value']}")
                    result = await scan_single(sess, ioc_data['value'], rate, selected_providers)
                    results.append(result)
                    
                    # Add debug logging and console output for each result
                    log.debug(f"Result row added: {ioc_data['value']}")
                    
                    # Format result for display with clean status
                    print(f"Result: {result['value']} ({result['type']})")
                    for provider, provider_data in result['results'].items():
                        if isinstance(provider_data, dict) and "status" in provider_data:
                            status = provider_data["status"]
                            print(f"  {provider}: {status}")
                        else:
                            # Handle legacy string responses during transition
                            print(f"  {provider}: {provider_data}")
                    print()  # Empty line for readability
                    
                    # Add small delay to avoid overwhelming providers
                    rate_limited = {"virustotal", "greynoise", "pulsedive", "shodan"}
                    if rate or (selected_providers and any(p in rate_limited for p in selected_providers)):
                        await asyncio.sleep(0.1)
                    
                except Exception as e:
                    log.error(f"Failed to scan IOC '{ioc_data['value']}': {e}")
                    print(f"Error processing {ioc_data['value']}: {e}")
                    results.append({
                        "value": ioc_data['value'],
                        "type": "error",
                        "results": {"error": str(e)}
                    })
                if idx % 50 == 0:
                    log.info(f"Processed {idx}/{len(iocs)} IOCs")
                    print(f"Progress: Processed {idx}/{len(iocs)} IOCs")
    except Exception as e:
        log.error(f"Session error during file processing: {e}")
        return

    # Write only CSV report
    try:
        WRITERS["csv"](outpath, results)
        log.info(f"Clean CSV report written → {outpath}")
        print(f"File processing complete! Clean report saved to {outpath}")
    except Exception as e:
        log.error(f"Failed to write CSV report: {e}")
        print(f"Error writing CSV report: {e}")

# ────────── CLI entry point ──────────
def main() -> None:
    """Main CLI entry point with robust error handling."""
    ap = argparse.ArgumentParser(description="IOC checker with async providers")
    ap.add_argument("ioc_type", nargs="?",
        choices=["ip","domain","url","hash","email","filepath","registry","wallet","asn","attack"],
        help="IOC type for single lookup")
    ap.add_argument("value", nargs="?", help="IOC value for single lookup")
    ap.add_argument("--file", help="Input file path (CSV, TSV, XLSX, TXT)")
    ap.add_argument("--csv", help="Legacy CSV path (deprecated, use --file)")
    ap.add_argument("-o", "--out", default="results.csv", help="Output filename")
    ap.add_argument("--rate", action="store_true", help="Include rate-limited providers")
    ap.add_argument("--limit", type=int, help="Limit number of IOCs to process (default: all)")
    
    # Individual provider selection
    ap.add_argument("--virustotal", action="store_true", help="Use VirusTotal")
    ap.add_argument("--greynoise", action="store_true", help="Use GreyNoise")
    ap.add_argument("--pulsedive", action="store_true", help="Use Pulsedive")
    ap.add_argument("--shodan", action="store_true", help="Use Shodan")
    
    # Allow explicit provider list from GUI
    ap.add_argument("--providers", help="Comma-separated list of providers to use")
    
    a = ap.parse_args()
    
    # Build selected providers list
    selected_providers = []
    
    # Check if providers were specified explicitly (from GUI)
    if a.providers:
        selected_providers = [p.strip() for p in a.providers.split(',')]
    else:
        # Build from individual flags
        if a.virustotal:
            selected_providers.append("virustotal")
        if a.greynoise:
            selected_providers.append("greynoise")  
        if a.pulsedive:
            selected_providers.append("pulsedive")
        if a.shodan:
            selected_providers.append("shodan")
          # If no specific providers selected, use default behavior
        if not selected_providers:
            selected_providers = None

    if a.ioc_type and a.value:
        async def _run_single():
            conn = aiohttp.TCPConnector(limit_per_host=10, ssl=False, force_close=True)
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            try:
                async with CachedSession(cache=SQLiteBackend(cache_name=".cache/ioc_cache.sqlite", expire_after=86400), connector=conn, timeout=timeout) as s:
                    res = await scan_single(s, a.value, a.rate, selected_providers)
                    print(f"\nIOC  : {res['value']}  ({res['type']})")
                    print("-"*48)
                    for k, provider_data in res["results"].items():
                        print(f"{k:<12}: {_fmt(provider_data)}")
                    print()
            except Exception as e:
                log.error(f"Single IOC scan failed: {e}")
                print(f"Error: {e}")
        
        try:
            asyncio.run(_run_single())
        except KeyboardInterrupt:
            log.info("Interrupted by user")
        except Exception as e:
            log.error(f"Async runtime error: {e}")
        return    # Handle file input (new format-agnostic or legacy CSV)
    input_file = a.file or a.csv
    if input_file:
        try:
            asyncio.run(process_file(input_file, a.out, a.rate, selected_providers, a.limit))
        except KeyboardInterrupt:
            log.info("File processing interrupted by user")
        except Exception as e:
            log.error(f"File processing failed: {e}")
        return

    ap.error("Provide either (ioc_type value) or --file/--csv")

if __name__ == "__main__":
    main()
