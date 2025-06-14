"""
Clean CSV report writer with structured IOC analysis.
• Single CSV output only • Clear status columns • UTF-8 encoding
"""
from __future__ import annotations
import csv, pathlib, logging
from typing import List, Dict, Any

log = logging.getLogger("reports")

def _calculate_overall_risk(provider_results: Dict[str, Dict[str, Any]]) -> str:
    """Calculate overall risk level from provider statuses."""
    risk_scores = {"malicious": 3, "suspicious": 2, "clean": 1, "n/a": 0}
    max_risk = 0
    
    for provider_data in provider_results.values():
        if isinstance(provider_data, dict) and "status" in provider_data:
            status = provider_data["status"]
            max_risk = max(max_risk, risk_scores.get(status, 0))
    
    if max_risk >= 3:
        return "HIGH"
    elif max_risk >= 2:
        return "MEDIUM"
    elif max_risk >= 1:
        return "LOW"
    else:
        return "LOW"

def write_clean_csv(path: pathlib.Path, results: List[Dict[str, Any]]) -> None:
    """Write clean CSV report with structured columns."""
    if not results:
        log.warning("No data to write to CSV")
        return
    
    try:
        # Build clean rows with structured columns
        clean_rows = []
        for result in results:
            ioc = result.get("value", "")
            ioc_type = result.get("type", "unknown")
            provider_results = result.get("results", {})
            
            # Extract status for each major provider
            row = {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "vt_status": "n/a",
                "otx_status": "n/a", 
                "abuseipdb_status": "n/a",
                "threatfox_status": "n/a",
                "urlhaus_status": "n/a"
            }
            
            # Map provider results to status columns with correct name mapping
            provider_mapping = {
                "virustotal": "vt_status",
                "otx": "otx_status", 
                "abuseipdb": "abuseipdb_status",
                "threatfox": "threatfox_status",
                "urlhaus": "urlhaus_status"
            }
            
            for provider_name, provider_data in provider_results.items():
                status_key = provider_mapping.get(provider_name)
                if status_key:
                    if isinstance(provider_data, dict) and "status" in provider_data:
                        row[status_key] = provider_data["status"]
                    elif isinstance(provider_data, str):
                        # Handle legacy string responses
                        if provider_data.startswith("error:") or provider_data == "nokey":
                            row[status_key] = "n/a"
                        else:
                            row[status_key] = "clean"  # Conservative fallback
            
            # Calculate overall risk
            row["overall"] = _calculate_overall_risk(provider_results)
            clean_rows.append(row)
        
        # Write to CSV
        with path.open("w", newline="", encoding="utf-8") as fh:
            fieldnames = ["ioc", "ioc_type", "vt_status", "otx_status", "abuseipdb_status", "threatfox_status", "urlhaus_status", "overall"]
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(clean_rows)
        
        log.info(f"Clean CSV report written: {path}")
        
    except Exception as e:
        log.error(f"Failed to write clean CSV report: {e}")

# Single CSV writer - remove all other formats
WRITERS = {"csv": write_clean_csv}
