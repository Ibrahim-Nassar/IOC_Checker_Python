"""
Test clean CSV report generation functionality.
"""
import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch

from reports import write_clean_csv, _calculate_overall_risk, WRITERS


class TestCleanCSVWriter:
    """Test the clean CSV writer functionality."""

    def test_write_clean_csv_basic(self, temp_dir):
        """Test basic CSV writing functionality."""
        test_data = [
            {
                "value": "8.8.8.8",
                "type": "ip", 
                "results": {
                    "abuseipdb": {"status": "clean", "score": 0, "raw": {}},
                    "otx": {"status": "clean", "score": 0, "raw": {}}
                }
            }
        ]
        
        output_path = temp_dir / "test_output.csv"
        write_clean_csv(output_path, test_data)
        
        assert output_path.exists()
        
        content = output_path.read_text(encoding='utf-8')
        assert "ioc,ioc_type,vt_status,otx_status,abuseipdb_status,threatfox_status,urlhaus_status,overall" in content
        assert "8.8.8.8,ip,n/a,clean,clean,n/a,n/a,LOW" in content

    def test_write_clean_csv_empty_data(self, temp_dir):
        """Test CSV writer with empty data."""
        output_path = temp_dir / "empty.csv"
        write_clean_csv(output_path, [])
        
        # Should not create file for empty data
        assert not output_path.exists()

    def test_overall_risk_calculation(self):
        """Test the overall risk calculation function."""
        # Test HIGH risk
        assert _calculate_overall_risk({"vt": {"status": "malicious", "score": 90}}) == "HIGH"
        
        # Test MEDIUM risk  
        assert _calculate_overall_risk({"vt": {"status": "suspicious", "score": 60}}) == "MEDIUM"
        
        # Test LOW risk
        assert _calculate_overall_risk({"vt": {"status": "clean", "score": 0}}) == "LOW"
        
        # Test n/a risk
        assert _calculate_overall_risk({"vt": {"status": "n/a", "score": 0}}) == "LOW"

    def test_writers_dict_only_csv(self):
        """Test that WRITERS only contains CSV writer."""
        assert len(WRITERS) == 1
        assert "csv" in WRITERS
        assert WRITERS["csv"] == write_clean_csv

    def test_provider_mapping(self, temp_dir):
        """Test that provider names are correctly mapped to columns."""
        test_data = [
            {
                "value": "test.com",
                "type": "domain",
                "results": {
                    "virustotal": {"status": "malicious", "score": 90, "raw": {}},
                    "abuseipdb": {"status": "clean", "score": 0, "raw": {}},
                    "otx": {"status": "suspicious", "score": 60, "raw": {}},
                    "threatfox": {"status": "n/a", "score": 0, "raw": {}},
                    "urlhaus": {"status": "clean", "score": 0, "raw": {}}
                }
            }
        ]
        
        output_path = temp_dir / "mapping.csv"
        write_clean_csv(output_path, test_data)
        
        content = output_path.read_text(encoding='utf-8')
        assert "test.com,domain,malicious,suspicious,clean,n/a,clean,HIGH" in content

    def test_legacy_string_handling(self, temp_dir):
        """Test handling of legacy string responses."""
        test_data = [
            {
                "value": "legacy.com",
                "type": "domain",
                "results": {
                    "virustotal": "Clean response",  # Legacy string
                    "abuseipdb": "error: timeout",   # Error string
                    "otx": {"status": "clean", "score": 0, "raw": {}}  # New format
                }
            }
        ]
        
        output_path = temp_dir / "legacy.csv"
        write_clean_csv(output_path, test_data)
        
        content = output_path.read_text(encoding='utf-8')
        # Legacy string should become "clean", error should become "n/a"
        assert "legacy.com,domain,clean,clean,n/a,n/a,n/a,LOW" in content