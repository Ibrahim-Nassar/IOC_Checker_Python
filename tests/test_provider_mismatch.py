#!/usr/bin/env python3
"""Test provider type mismatch detection functionality."""

import pytest
import tempfile
import csv
from pathlib import Path
from unittest.mock import Mock, MagicMock

from ioc_gui_tk import IOCCheckerGUI


class TestProviderMismatch:
    """Test provider type mismatch detection."""
    
    def setup_method(self):
        """Set up test environment."""
        self.gui = IOCCheckerGUI()
        
        # Mock selected providers - only AbuseIPDB (IP only)
        mock_provider = Mock()
        mock_provider.NAME = "AbuseIPDB"
        self.gui._selected_providers = Mock(return_value=[mock_provider])
        
        # Keep the original providers_info
        self.gui.providers_info = [
            ("virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", "Universal threat intelligence platform", ["ip", "domain", "url", "hash"]),
            ("abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", "IP reputation and abuse reports", ["ip"]),
            ("otx", "AlienVault OTX", "OTX_API_KEY", "Open threat exchange platform", ["ip", "domain", "url", "hash"]),
            ("threatfox", "ThreatFox", "THREATFOX_API_KEY", "Malware IOCs from abuse.ch", ["ip", "domain", "url", "hash"]),
            ("greynoise", "GreyNoise", "GREYNOISE_API_KEY", "Internet background noise analysis", ["ip"]),
        ]

    def create_test_csv(self, iocs):
        """Create a temporary CSV file with test IOCs."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
        
        with open(temp_file.name, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['IOC', 'Type'])  # Header
            for ioc, ioc_type in iocs:
                writer.writerow([ioc, ioc_type])
        
        return temp_file.name

    def test_analyze_ioc_types_with_ip_only_provider(self):
        """Test IOC type analysis with IP-only provider selected."""
        # Test data: mix of IOC types
        test_iocs = [
            {'value': '8.8.8.8', 'type': 'ip'},
            {'value': 'malicious.com', 'type': 'domain'},
            {'value': 'https://evil.com/path', 'type': 'url'},
            {'value': 'd41d8cd98f00b204e9800998ecf8427e', 'type': 'hash'}
        ]
        
        ioc_types_found, unsupported_iocs, provider_type_map = self.gui._analyze_ioc_types(test_iocs)
        
        # Should find all IOC types
        assert ioc_types_found == {'ip', 'domain', 'url', 'hash'}
        
        # AbuseIPDB only supports IP, so domain, url, hash should be unsupported
        assert len(unsupported_iocs) == 3
        unsupported_types = {ioc['type'] for ioc in unsupported_iocs}
        assert unsupported_types == {'domain', 'url', 'hash'}
        
        # Provider type map should show AbuseIPDB supports only IP
        assert provider_type_map == {'AbuseIPDB': {'ip'}}

    def test_analyze_ioc_types_with_universal_provider(self):
        """Test IOC type analysis with universal provider (VirusTotal)."""
        # Mock VirusTotal as selected provider
        mock_provider = Mock()
        mock_provider.NAME = "VirusTotal"
        self.gui._selected_providers = Mock(return_value=[mock_provider])
        
        test_iocs = [
            {'value': '8.8.8.8', 'type': 'ip'},
            {'value': 'malicious.com', 'type': 'domain'},
            {'value': 'https://evil.com/path', 'type': 'url'},
            {'value': 'd41d8cd98f00b204e9800998ecf8427e', 'type': 'hash'}
        ]
        
        ioc_types_found, unsupported_iocs, provider_type_map = self.gui._analyze_ioc_types(test_iocs)
        
        # Should find all IOC types
        assert ioc_types_found == {'ip', 'domain', 'url', 'hash'}
        
        # VirusTotal supports all types, so no unsupported IOCs
        assert len(unsupported_iocs) == 0
        
        # Provider type map should show VirusTotal supports all types
        assert provider_type_map == {'VirusTotal': {'ip', 'domain', 'url', 'hash'}}

    def test_analyze_ioc_types_with_mixed_providers(self):
        """Test IOC type analysis with mixed providers."""
        # Mock AbuseIPDB + GreyNoise (both IP only)
        mock_abuse = Mock()
        mock_abuse.NAME = "AbuseIPDB"
        mock_grey = Mock()
        mock_grey.NAME = "GreyNoise"
        self.gui._selected_providers = Mock(return_value=[mock_abuse, mock_grey])
        
        test_iocs = [
            {'value': '8.8.8.8', 'type': 'ip'},
            {'value': '1.1.1.1', 'type': 'ip'},
            {'value': 'malicious.com', 'type': 'domain'},
        ]
        
        ioc_types_found, unsupported_iocs, provider_type_map = self.gui._analyze_ioc_types(test_iocs)
        
        # Should find IP and domain types
        assert ioc_types_found == {'ip', 'domain'}
        
        # Only domain should be unsupported
        assert len(unsupported_iocs) == 1
        assert unsupported_iocs[0]['type'] == 'domain'
        assert unsupported_iocs[0]['value'] == 'malicious.com'
        
        # Both providers support only IP
        expected_map = {
            'AbuseIPDB': {'ip'},
            'GreyNoise': {'ip'}
        }
        assert provider_type_map == expected_map

    def test_analyze_ioc_types_with_invalid_iocs(self):
        """Test IOC type analysis with invalid IOCs."""
        test_iocs = [
            {'value': '8.8.8.8', 'type': 'ip'},
            {'value': 'invalid-ioc-value', 'type': 'unknown'},
            {'value': '', 'type': 'empty'},
        ]
        
        ioc_types_found, unsupported_iocs, provider_type_map = self.gui._analyze_ioc_types(test_iocs)
        
        # Only IP should be found as valid
        assert ioc_types_found == {'ip'}
        
        # No unsupported IOCs since invalid ones are filtered out during validation
        assert len(unsupported_iocs) == 0

    def test_export_unsupported_iocs(self):
        """Test exporting unsupported IOCs to CSV."""
        unsupported_iocs = [
            {'type': 'domain', 'value': 'malicious.com', 'normalized': 'malicious.com'},
            {'type': 'url', 'value': 'https://evil.com', 'normalized': 'https://evil.com'},
            {'type': 'hash', 'value': 'd41d8cd98f00b204e9800998ecf8427e', 'normalized': 'd41d8cd98f00b204e9800998ecf8427e'}
        ]
        
        # Create a temporary input file to determine output location
        temp_input = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
        temp_input.close()
        
        try:
            # Export unsupported IOCs
            output_path = self.gui._export_unsupported_iocs(temp_input.name, unsupported_iocs)
            
            assert output_path is not None
            assert Path(output_path).exists()
            
            # Verify CSV content
            with open(output_path, 'r', newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                
                assert len(rows) == 3
                
                # Check first row
                assert rows[0]['type'] == 'domain'
                assert rows[0]['ioc'] == 'malicious.com'
                assert 'domain' in rows[0]['reason']
                
                # Check second row
                assert rows[1]['type'] == 'url'
                assert rows[1]['ioc'] == 'https://evil.com'
                assert 'url' in rows[1]['reason']
                
                # Check third row
                assert rows[2]['type'] == 'hash'
                assert rows[2]['ioc'] == 'd41d8cd98f00b204e9800998ecf8427e'
                assert 'hash' in rows[2]['reason']
            
            # Clean up
            Path(output_path).unlink()
            
        finally:
            Path(temp_input.name).unlink()

    def test_analyze_empty_ioc_list(self):
        """Test analyzing an empty IOC list."""
        ioc_types_found, unsupported_iocs, provider_type_map = self.gui._analyze_ioc_types([])
        
        assert len(ioc_types_found) == 0
        assert len(unsupported_iocs) == 0
        assert provider_type_map == {'AbuseIPDB': {'ip'}}

    def teardown_method(self):
        """Clean up after tests."""
        if hasattr(self.gui, 'root'):
            self.gui.root.destroy() 