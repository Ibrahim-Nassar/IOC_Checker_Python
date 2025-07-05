"""
Services module for IOC Checker GUI - extracted functionality for provider selection, 
batch processing, and export operations.
"""
from __future__ import annotations

import asyncio
import csv
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any

from ioc_types import IOCStatus, IOCResult, validate_ioc, detect_ioc_type
from providers import get_providers
from ioc_checker import scan_ioc, aggregate_verdict


class IOCProcessingService:
    """Service for processing IOCs in batches."""
    
    def __init__(self):
        self.processed_iocs: set[str] = set()
    
    def clear_processed(self) -> None:
        """Clear the set of processed IOCs."""
        self.processed_iocs.clear()
    
    def analyze_ioc_types(self, iocs: List[Dict[str, str]]) -> Tuple[set[str], List[Dict[str, str]], Dict[str, List[str]]]:
        """Analyze IOC types and find provider mismatches."""
        ioc_types_found = set()
        unsupported_iocs = []
        provider_type_map = {}
        
        # Get current providers and their supported types
        providers = get_providers()
        for provider in providers:
            provider_name = provider.NAME.lower()
            # Use provider's SUPPORTED_TYPES if available, fallback to empty set
            supported_types = getattr(provider, 'SUPPORTED_TYPES', set())
            provider_type_map[provider_name] = list(supported_types)
        
        # Analyze each IOC
        for ioc_data in iocs:
            ioc_value = ioc_data.get('value', str(ioc_data))
            is_valid, ioc_type, normalized_ioc, error_message = validate_ioc(ioc_value)
            
            if is_valid:
                ioc_types_found.add(ioc_type)
                
                # Check if any provider supports this IOC type
                supported_by_any = False
                for provider_types in provider_type_map.values():
                    if ioc_type in provider_types:
                        supported_by_any = True
                        break
                
                if not supported_by_any:
                    unsupported_iocs.append({
                        'original': ioc_value,
                        'normalized': normalized_ioc,
                        'type': ioc_type,
                        'reason': f"No active providers support {ioc_type} IOCs"
                    })
        
        return ioc_types_found, unsupported_iocs, provider_type_map
    
    async def process_batch(self, iocs: List[Dict[str, str]], providers: List[Any], 
                          progress_callback=None) -> Tuple[List[Dict[str, str]], int, int, int]:
        """Process a batch of IOCs and return results."""
        valid_count = 0
        invalid_count = 0
        duplicate_count = 0
        processed = 0  # Separate counter for progress tracking
        csv_results = []
        
        for i, ioc_data in enumerate(iocs):
            ioc_value = ioc_data.get('value', str(ioc_data))
            
            # Check for duplicates
            if ioc_value in self.processed_iocs:
                duplicate_count += 1
                continue
            
            self.processed_iocs.add(ioc_value)
            
            # Validate each IOC before processing
            is_valid, ioc_type, normalized_ioc, error_message = validate_ioc(ioc_value)
            
            if is_valid:
                valid_count += 1
                results = await scan_ioc(normalized_ioc, ioc_type, providers)
                
                # Determine overall verdict for CSV
                overall_verdict = aggregate_verdict(list(results.values()))
                flagged_providers = [name for name, result in results.items() 
                                   if result.status == IOCStatus.MALICIOUS]
                
                verdict_text = "malicious" if overall_verdict == IOCStatus.MALICIOUS else "clean"
                if overall_verdict == IOCStatus.ERROR:
                    verdict_text = "error"
                
                csv_results.append({
                    'type': ioc_type,
                    'ioc': normalized_ioc,
                    'verdict': verdict_text,
                    'flagged_by': ', '.join(flagged_providers),
                    'results': results
                })
            else:
                invalid_count += 1
                csv_results.append({
                    'type': 'invalid',
                    'ioc': ioc_value,
                    'verdict': 'error',
                    'flagged_by': f'Validation Error: {error_message}',
                    'results': {}
                })
            
            # Increment processed counter and update progress after successful processing
            processed += 1
            if progress_callback:
                progress_callback(processed, len(iocs))
        
        return csv_results, valid_count, invalid_count, duplicate_count


class ExportService:
    """Service for exporting IOC results to various formats."""
    
    @staticmethod
    def export_unsupported_iocs(filename: str, unsupported_iocs: List[Dict[str, str]]) -> str | None:
        """Export unsupported IOCs to a CSV file."""
        try:
            base_path = Path(filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            unsupported_path = base_path.parent / f"{base_path.stem}_unsupported_{timestamp}.csv"
            
            with open(unsupported_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['original_ioc', 'normalized_ioc', 'type', 'reason']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for ioc in unsupported_iocs:
                    writer.writerow({
                        'original_ioc': ioc['original'],
                        'normalized_ioc': ioc['normalized'],
                        'type': ioc['type'],
                        'reason': ioc['reason']
                    })
            
            return str(unsupported_path)
        except Exception as e:
            return None
    
    @staticmethod
    def export_batch_results(input_filename: str, results: List[Dict[str, str]], cancelled: bool = False) -> str:
        """Export batch results to a CSV file."""
        base_path = Path(input_filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        status_suffix = "_cancelled" if cancelled else "_results"
        output_path = base_path.parent / f"{base_path.stem}{status_suffix}_{timestamp}.csv"
        
        with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['type', 'ioc', 'verdict', 'flagged_by']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for result in results:
                writer.writerow({
                    'type': result['type'],
                    'ioc': result['ioc'],
                    'verdict': result['verdict'],
                    'flagged_by': result['flagged_by']
                })
        
        return str(output_path)


class ProviderService:
    """Service for managing provider configurations."""
    
    @staticmethod
    def get_available_providers() -> List[Tuple[str, str, str, str, List[str]]]:
        """Get information about available providers."""
        return [
            ("virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", "Universal threat intelligence platform", ["ip", "domain", "url", "hash"]),
            ("abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", "IP reputation and abuse reports", ["ip"]),
            ("otx", "AlienVault OTX", "OTX_API_KEY", "Open threat exchange platform", ["ip", "domain", "url", "hash"]),
            ("threatfox", "ThreatFox", "THREATFOX_API_KEY", "Malware IOCs from abuse.ch", ["ip", "domain", "url", "hash"]),
            ("greynoise", "GreyNoise", "GREYNOISE_API_KEY", "Internet background noise analysis", ["ip"]),
        ]
    
    @staticmethod
    def get_provider_config() -> Dict[str, bool]:
        """Get default provider configuration."""
        return {
            'virustotal': False,
            'abuseipdb': False,
            'otx': False,
            'threatfox': False,
            'greynoise': False,
        }


__all__ = ["IOCProcessingService", "ExportService", "ProviderService"] 