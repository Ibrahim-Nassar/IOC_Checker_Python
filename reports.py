"""
Clean CSV report writer with structured IOC analysis.
• Single CSV output only • Clear status columns • UTF-8 encoding
"""
from __future__ import annotations
import csv
import pathlib
import logging
import os
from typing import List, Dict, Any

log = logging.getLogger("reports")

CSV_FILENAME = "results.csv"

def write_csv(results: List[Dict[str, str]]) -> str:
    """
    Write the list of result dictionaries to a CSV file.
    Returns the file path of the written CSV.
    """
    if not results:
        return ""
    
    # Determine all possible fieldnames from all result dicts
    all_fieldnames = set()
    for result in results:
        all_fieldnames.update(result.keys())
    
    # Convert to sorted list for consistent column order
    fieldnames = sorted(list(all_fieldnames))
    
    # Open with newline='' to avoid extra CR on Windows, use utf-8-sig for BOM
    with open(CSV_FILENAME, mode="w", newline="", encoding="utf-8-sig") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in results:
            # Fill missing fields with empty strings
            complete_row = {field: row.get(field, '') for field in fieldnames}
            writer.writerow(complete_row)
    return os.path.abspath(CSV_FILENAME)

def write_clean_csv(path: pathlib.Path, results: List[Dict[str, Any]]) -> None:
    """Write clean CSV report with structured columns for only active providers."""
    try:
        if not results:
            log.warning("No data to write to CSV, creating empty file with headers")
            # Create empty CSV with just basic headers
            with path.open("w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=["ioc", "ioc_type", "overall"])
                writer.writeheader()
            log.info(f"Empty CSV report written: {path}")
            return

        # Determine which providers actually returned data
        active_providers = set()
        for result in results:
            provider_results = result.get("results", {})
            for provider_name in provider_results.keys():
                if provider_name != "error":  # Exclude error entries
                    active_providers.add(provider_name)
        
        log.info(f"Active providers detected: {sorted(active_providers)}")
        
        # Build dynamic fieldnames based on active providers
        base_fields = ["ioc", "ioc_type"]
        provider_fields = []
        provider_mapping = {}
        
        # Only add columns for providers that actually returned data
        for provider in sorted(active_providers):
            if provider == "virustotal":
                field_name = "vt_status"
            elif provider == "abuseipdb":
                field_name = "abuseipdb_status"
            elif provider == "otx":
                field_name = "otx_status"
            elif provider == "threatfox":
                field_name = "threatfox_status"
            elif provider == "urlhaus":
                field_name = "urlhaus_status"
            elif provider == "malwarebazaar":
                field_name = "malwarebazaar_status"
            elif provider == "greynoise":
                field_name = "greynoise_status"
            elif provider == "pulsedive":
                field_name = "pulsedive_status"
            elif provider == "shodan":
                field_name = "shodan_status"
            else:
                field_name = f"{provider}_status"
            
            provider_fields.append(field_name)
            provider_mapping[provider] = field_name
        
        fieldnames = base_fields + provider_fields + ["overall"]
        log.info(f"CSV columns: {fieldnames}")

        # Build clean rows with dynamic columns
        clean_rows = []
        for result in results:
            ioc = result.get("value", "")
            ioc_type = result.get("type", "unknown")
            provider_results = result.get("results", {})
            
            # Initialize row with base fields
            row = {"ioc": ioc, "ioc_type": ioc_type}
            
            # Add status for each active provider
            for provider_name, field_name in provider_mapping.items():
                provider_data = provider_results.get(provider_name)
                if provider_data:
                    if isinstance(provider_data, dict) and "status" in provider_data:
                        row[field_name] = provider_data["status"]
                    elif isinstance(provider_data, str):
                        # Handle legacy string responses
                        if provider_data.startswith("error:") or provider_data == "nokey":
                            row[field_name] = "n/a"
                        else:
                            row[field_name] = "clean"  # Conservative fallback
                else:
                    row[field_name] = "n/a"
            
            # Calculate overall risk with improved accuracy
            row["overall"] = _calculate_overall_risk(provider_results)
            clean_rows.append(row)
        
        # Write to CSV
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(clean_rows)
        
        log.info(f"Clean CSV report written: {path}")
        
    except Exception as e:
        log.error(f"Failed to write clean CSV report: {e}")
        # Try to create an error file so user knows something was attempted
        try:
            with path.open("w", newline="", encoding="utf-8") as fh:
                fh.write("# Error occurred during CSV generation\n")
                fh.write(f"# Error: {str(e)}\n")
            log.info(f"Error CSV file created: {path}")
        except Exception as write_error:
            log.error(f"Could not even create error file: {write_error}")

def _calculate_overall_risk(provider_results: Dict[str, Dict[str, Any]]) -> str:
    """Calculate overall risk level with improved accuracy and threat detection."""
    if not provider_results:
        return "LOW"
    
    # Count status types and their severity
    malicious_count = 0
    suspicious_count = 0
    clean_count = 0
    total_responses = 0
    
    # Track high-confidence providers separately
    high_confidence_malicious = 0
    
    for provider_name, provider_data in provider_results.items():
        if provider_name == "error":
            continue
            
        if isinstance(provider_data, dict) and "status" in provider_data:
            status = provider_data["status"]
            total_responses += 1
            
            if status == "malicious":
                malicious_count += 1
                # URLhaus and ThreatFox are high-confidence for malicious URLs
                if provider_name in ["urlhaus", "threatfox"]:
                    high_confidence_malicious += 1
            elif status == "suspicious":
                suspicious_count += 1
            elif status == "clean":
                clean_count += 1
    
    # No valid responses
    if total_responses == 0:
        return "LOW"
    
    # Risk calculation with improved logic
    if malicious_count > 0:
        # Any malicious detection from high-confidence providers = HIGH
        if high_confidence_malicious > 0:
            return "HIGH"
        # Multiple providers detecting malicious = HIGH
        elif malicious_count >= 2:
            return "HIGH"
        # Single malicious detection = HIGH (conservative approach)
        else:
            return "HIGH"
    
    # Suspicious detections
    elif suspicious_count > 0:
        if suspicious_count >= 2:
            return "MEDIUM"
        else:
            return "MEDIUM"  # Even one suspicious is worth noting
    
    # All clean or mostly clean
    elif clean_count > 0:
        return "LOW"
    
    # Fallback
    return "LOW"

# Single CSV writer - remove all other formats
WRITERS = {"csv": write_clean_csv}
