# ioc_checker.py
"""
Async IOC checker with robust UTF-8 handling and comprehensive error management.
• Single-IOC look-ups  • Batch CSV/TXT scans
• Clean console summaries  • Robust CSV parsing
• Cross-platform UTF-8 output
"""
from __future__ import annotations
import argparse, asyncio, csv, json, logging, pathlib, sys, aiohttp
from typing import Dict, Any
from ioc_types import detect_ioc_type
from providers import ALWAYS_ON, RATE_LIMIT
from reports   import WRITERS

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
def _fmt(raw: str | Dict[str, Any]) -> str:
    """Format provider response for console display."""
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError) as e:
        log.debug(f"Failed to parse provider response: {e}")
        return "unparseable"

    # Handle None input gracefully
    if data is None:
        return "unparseable"

    # AbuseIPDB format
    if "abuseConfidenceScore" in str(data):
        try:
            s = data["data"]["abuseConfidenceScore"]
            wl = data["data"]["isWhitelisted"]
            return "Clean (whitelisted)" if wl else ("Clean" if s == 0 else f"Malicious – score {s}")
        except (KeyError, TypeError) as e:
            log.debug(f"AbuseIPDB parsing error: {e}")
            return "Parse error"    # VirusTotal format
    if "last_analysis_stats" in str(data):
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
            return "Parse error"

    # OTX format
    if "pulse_info" in str(data):
        try:
            c = data["pulse_info"]["count"]
            return "Clean" if c == 0 else f"Malicious – {c} OTX pulse{'s' if c!=1 else ''}"
        except (KeyError, TypeError) as e:
            log.debug(f"OTX parsing error: {e}")
            return "Parse error"

    # ThreatFox format
    if "query_status" in str(data):
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
        # Fix: Merge default always-on providers with user selections
        all_providers = list(ALWAYS_ON) + list(RATE_LIMIT)
        # Get always-on providers + specifically selected providers
        always_on_names = [p.name for p in ALWAYS_ON]
        combined_names = always_on_names + selected_providers
        provs = [p for p in all_providers if p.name in combined_names]
    else:
        # Default behavior: always-on + rate-limited if enabled
        provs = list(ALWAYS_ON) + (list(RATE_LIMIT) if rate else [])
    
    tasks = [p.query(session, typ, val) for p in provs if typ in p.ioc_kinds]
    try:
        outs = await asyncio.gather(*tasks, return_exceptions=True)
        results = {}
        for p, o in zip([q for q in provs if typ in q.ioc_kinds], outs):
            if isinstance(o, Exception):
                log.warning(f"Provider {p.name} failed: {o}")
                results[p.name] = f"error: {str(o)}"
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

# ────────── robust CSV processing ──────────
async def process_csv(csv_path: str, out: str, rate: bool, selected_providers: list = None) -> None:
    """Process CSV file with robust parsing and error handling."""
    inpath, outpath = pathlib.Path(csv_path), pathlib.Path(out)
    
    if not inpath.exists():
        log.error(f"Input file not found: {csv_path}")
        return
        
    # Add debug logging for GUI
    log.debug(f"CSV selected: {csv_path}")
    
    # Detect CSV delimiter
    try:
        with inpath.open("rb") as fh:
            sample = fh.read(8192).decode("utf-8", "ignore")
            # Handle empty files
            if not sample.strip():
                log.warning(f"Empty file: {csv_path}")
                return
            delim = csv.Sniffer().sniff(sample).delimiter
    except Exception as e:
        log.warning(f"Could not detect delimiter, using comma: {e}")
        delim = ","

    # Read and filter CSV rows
    try:
        with inpath.open(encoding="utf-8", errors="ignore") as fh:
            rdr = csv.DictReader(fh, delimiter=delim)
            rows = []
            for row_num, row in enumerate(rdr, 1):
                if any(c.strip() for c in row.values() if c):
                    rows.append(row)
                elif row_num <= 10:  # Only log first few empty rows
                    log.debug(f"Skipping empty row {row_num}")
    except Exception as e:
        log.error(f"Failed to read CSV file: {e}")
        return

    if not rows:
        log.warning(f"No usable rows in {csv_path}")
        return
    
    # Add debug logging for parsed IOC count
    ioc_count = sum(1 for row in rows for v in row.values() if v and v.strip())
    log.debug(f"Parsed {ioc_count} IOCs from {len(rows)} rows")
    log.info(f"Loaded {len(rows)} rows from {csv_path} (delimiter={repr(delim)})")

    # Process IOCs
    results = []
    try:
        conn = aiohttp.TCPConnector(limit_per_host=10, ssl=False, force_close=True)
    except Exception as e:
        log.error(f"Failed to create connector: {e}")
        return
    
    try:
        async with aiohttp.ClientSession(connector=conn) as sess:
            for idx, row in enumerate(rows, 1):
                for col_name, v in row.items():
                    if v and v.strip():
                        try:
                            # Add progress output for GUI
                            print(f"Processing IOC: {v.strip()}")
                            result = await scan_single(sess, v.strip(), rate, selected_providers)
                            results.append(result)
                            
                            # Add debug logging and console output for each result
                            log.debug(f"Result row added: {v.strip()}")
                            
                            # Format result for display like single IOC mode
                            print(f"Result: {result['value']} ({result['type']})")
                            for provider, raw_result in result['results'].items():
                                formatted = _fmt(raw_result)
                                print(f"  {provider}: {formatted}")
                            print()  # Empty line for readability
                            
                        except Exception as e:
                            log.error(f"Failed to scan IOC '{v}': {e}")
                            print(f"Error processing {v.strip()}: {e}")
                            results.append({
                                "value": v.strip(),
                                "type": "error",
                                "results": {"error": str(e)}
                            })
                if idx % 50 == 0:
                    log.info(f"Processed {idx}/{len(rows)} rows")
                    print(f"Progress: Processed {idx}/{len(rows)} rows")
    except Exception as e:
        log.error(f"Session error during CSV processing: {e}")
        return

    # Write reports
    try:
        WRITERS["csv"](outpath, results)
        WRITERS["json"](outpath.with_suffix(".json"), results)
        WRITERS["xlsx"](outpath.with_suffix(".xlsx"), results)
        WRITERS["html"](outpath.with_suffix(".html"), results)
        log.info(f"Reports written → {outpath}*")
        print(f"CSV processing complete! Reports saved to {outpath}*")
    except Exception as e:
        log.error(f"Failed to write reports: {e}")
        print(f"Error writing reports: {e}")

# ────────── CLI entry point ──────────
def main() -> None:
    """Main CLI entry point with robust error handling."""
    ap = argparse.ArgumentParser(description="IOC checker with async providers")
    ap.add_argument("ioc_type", nargs="?",
        choices=["ip","domain","url","hash","email","filepath","registry","wallet","asn","attack"],
        help="IOC type for single lookup")
    ap.add_argument("value", nargs="?", help="IOC value for single lookup")
    ap.add_argument("--csv", help="Batch CSV/TXT path")
    ap.add_argument("-o", "--out", default="results.csv", help="Output filename (batch)")
    ap.add_argument("--rate", action="store_true", help="Include rate-limited providers")
    
    # Individual provider selection
    ap.add_argument("--virustotal", action="store_true", help="Use VirusTotal")
    ap.add_argument("--greynoise", action="store_true", help="Use GreyNoise")
    ap.add_argument("--pulsedive", action="store_true", help="Use Pulsedive")
    ap.add_argument("--shodan", action="store_true", help="Use Shodan")
    
    a = ap.parse_args()
    
    # Build selected providers list
    selected_providers = []
    if a.virustotal:
        selected_providers.append("virustotal")
    if a.greynoise:
        selected_providers.append("greynoise")  
    if a.pulsedive:
        selected_providers.append("pulsedive")
    if a.shodan:
        selected_providers.append("shodan")
        
    # If no specific providers selected, use the rate flag behavior
    if not selected_providers:
        selected_providers = None

    if a.ioc_type and a.value:
        async def _run_single():
            conn = aiohttp.TCPConnector(limit_per_host=10, ssl=False, force_close=True)
            try:
                async with aiohttp.ClientSession(connector=conn) as s:
                    res = await scan_single(s, a.value, a.rate, selected_providers)
                    print(f"\nIOC  : {res['value']}  ({res['type']})")
                    print("-"*48)
                    for k, raw in res["results"].items():
                        print(f"{k:<12}: {_fmt(raw)}")
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
        return

    if a.csv:
        try:
            asyncio.run(process_csv(a.csv, a.out, a.rate, selected_providers))
        except KeyboardInterrupt:
            log.info("CSV processing interrupted by user")
        except Exception as e:
            log.error(f"CSV processing failed: {e}")
        return

    ap.error("Provide either (ioc_type value) or --csv")

if __name__ == "__main__":
    main()
