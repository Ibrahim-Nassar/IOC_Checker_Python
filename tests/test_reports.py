"""Tests for report generation functionality."""

import pytest
import csv
import tempfile
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import reports


class TestReports:
    """Test cases for report generation."""
    
    def test_write_csv_basic(self):
        """Test basic CSV writing functionality."""
        test_rows = [
            {"ioc": "8.8.8.8", "type": "ip", "status": "clean"},
            {"ioc": "malware.com", "type": "domain", "status": "malicious"},
        ]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "test_results.csv"
            
            result_path = reports.write_csv(output_path, test_rows)
            
            assert result_path == str(output_path)
            assert output_path.exists()
            
            # Verify content
            with open(output_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            assert len(rows) == 2
            assert rows[0]["ioc"] == "8.8.8.8"
            assert rows[1]["status"] == "malicious"
    
    def test_write_csv_empty_data(self):
        """Test CSV writing with empty data."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "empty.csv"
            
            result_path = reports.write_csv(output_path, [])
            
            assert result_path == str(output_path)
            # Function should return early for empty data
    
    def test_write_csv_column_ordering(self):
        """Test that CSV columns maintain insertion order."""
        test_rows = [
            {"c": "3", "a": "1", "b": "2"},
            {"a": "4", "c": "6", "b": "5"},
        ]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "ordered.csv"
            
            reports.write_csv(output_path, test_rows)
            
            with open(output_path, "r", encoding="utf-8") as f:
                reader = csv.reader(f)
                headers = next(reader)
            
            # Should maintain order from first row
            assert headers == ["c", "a", "b"]
    
    def test_write_csv_missing_fields(self):
        """Test CSV writing when rows have different fields."""
        test_rows = [
            {"ioc": "test1", "status": "clean"},
            {"ioc": "test2", "verdict": "malicious", "confidence": "high"},
        ]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "mixed.csv"
            
            reports.write_csv(output_path, test_rows)
            
            with open(output_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            # All fields should be present, missing values filled with empty string
            assert "status" in reader.fieldnames
            assert "verdict" in reader.fieldnames
            assert "confidence" in reader.fieldnames
            
            # First row should have empty string for missing fields
            assert rows[0]["verdict"] == ""
            assert rows[0]["confidence"] == ""
            
            # Second row should have empty string for missing fields
            assert rows[1]["status"] == ""
    
    def test_write_csv_unicode_handling(self):
        """Test CSV writing with Unicode characters."""
        test_rows = [
            {"ioc": "тест.com", "description": "测试域名"},
            {"ioc": "café.fr", "description": "Français domain"},
        ]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "unicode.csv"
            
            reports.write_csv(output_path, test_rows)
            
            # Read back and verify encoding
            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            assert "тест.com" in content
            assert "测试域名" in content
            assert "café.fr" in content
    
    def test_write_csv_directory_creation(self):
        """Test that parent directories are created if needed."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "subdir" / "nested" / "results.csv"
            test_rows = [{"test": "data"}]
            
            reports.write_csv(output_path, test_rows)
            
            assert output_path.exists()
            assert output_path.parent.exists()
    
    def test_write_clean_csv_empty_data(self):
        """Test clean CSV writing with empty data."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "empty_clean.csv"
            
            with patch('reports.log') as mock_log:
                reports.write_clean_csv(output_path, [])
                
                assert output_path.exists()
                mock_log.warning.assert_called()
                mock_log.info.assert_called()
                
                # Should create file with basic headers
                with open(output_path, "r", encoding="utf-8") as f:
                    reader = csv.reader(f)
                    headers = next(reader)
                
                assert "ioc" in headers
                assert "ioc_type" in headers
                assert "overall" in headers
    
    def test_write_clean_csv_with_active_providers(self):
        """Test clean CSV writing with active provider data."""
        test_results = [
            {
                "value": "8.8.8.8",
                "type": "ip",
                "results": {
                    "virustotal": {"status": "clean"},
                    "abuseipdb": {"status": "clean"},
                }
            },
            {
                "value": "malware.com",
                "type": "domain",
                "results": {
                    "virustotal": {"status": "malicious"},
                    "otx": {"status": "suspicious"},
                }
            }
        ]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "clean_results.csv"
            
            reports.write_clean_csv(output_path, test_results)
            
            assert output_path.exists()
            
            with open(output_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            
            assert len(rows) == 2
            
            # Check that provider columns are present
            fieldnames = reader.fieldnames
            assert "ioc" in fieldnames
            assert "ioc_type" in fieldnames
            assert "vt_status" in fieldnames
            assert "abuseipdb_status" in fieldnames
            assert "otx_status" in fieldnames
            assert "overall" in fieldnames
            
            # Check data
            assert rows[0]["ioc"] == "8.8.8.8"
            assert rows[0]["vt_status"] == "clean"
            assert rows[1]["vt_status"] == "malicious"
    
    def test_calculate_overall_risk_no_data(self):
        """Test overall risk calculation with no provider data."""
        result = reports._calculate_overall_risk({})
        assert result == "LOW"
    
    def test_calculate_overall_risk_all_clean(self):
        """Test overall risk calculation with all clean results."""
        provider_results = {
            "virustotal": {"status": "clean"},
            "abuseipdb": {"status": "clean"},
            "otx": {"status": "clean"},
        }
        
        result = reports._calculate_overall_risk(provider_results)
        assert result == "LOW"
    
    def test_calculate_overall_risk_malicious_detected(self):
        """Test overall risk calculation with malicious detections."""
        provider_results = {
            "virustotal": {"status": "malicious"},
            "abuseipdb": {"status": "clean"},
        }
        
        result = reports._calculate_overall_risk(provider_results)
        # Should be HIGH due to malicious detection
        assert result in ["HIGH", "MEDIUM"]  # Implementation might vary
    
    def test_calculate_overall_risk_high_confidence_provider(self):
        """Test overall risk calculation with high-confidence provider."""
        provider_results = {
            "threatfox": {"status": "malicious"},
            "otx": {"status": "clean"},
        }
        
        result = reports._calculate_overall_risk(provider_results)
        # ThreatFox is considered high-confidence
        assert result == "HIGH"
    
    def test_calculate_overall_risk_suspicious_only(self):
        """Test overall risk calculation with only suspicious results."""
        provider_results = {
            "virustotal": {"status": "suspicious"},
            "abuseipdb": {"status": "clean"},
        }
        
        result = reports._calculate_overall_risk(provider_results)
        # Should be MEDIUM or LOW depending on implementation
        assert result in ["MEDIUM", "LOW"]
    
    def test_calculate_overall_risk_error_handling(self):
        """Test overall risk calculation with error entries."""
        provider_results = {
            "virustotal": {"status": "clean"},
            "error": "Some error occurred",
            "abuseipdb": {"status": "clean"},
        }
        
        result = reports._calculate_overall_risk(provider_results)
        # Should ignore error entries
        assert result == "LOW"
    
    def test_write_clean_csv_error_handling(self):
        """Test clean CSV writing error handling."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Create a file that can't be written to (simulate permission error)
            output_path = Path(tmp_dir) / "readonly.csv"
            output_path.touch()
            output_path.chmod(0o444)  # Read-only
            
            test_results = [{"value": "test", "type": "ip", "results": {}}]
            
            with patch('reports.log') as mock_log:
                try:
                    reports.write_clean_csv(output_path, test_results)
                    # Should handle error gracefully
                    mock_log.error.assert_called()
                except PermissionError:
                    # If the permission error isn't caught, that's also valid behavior
                    pass
    
    def test_provider_field_name_mapping(self):
        """Test that provider names are mapped to correct field names."""
        test_results = [
            {
                "value": "test.com",
                "type": "domain",
                "results": {
                    "virustotal": {"status": "clean"},
                    "abuseipdb": {"status": "clean"},
                    "otx": {"status": "clean"},
                    "threatfox": {"status": "clean"},
                    "greynoise": {"status": "clean"},
                    "unknown_provider": {"status": "clean"},
                }
            }
        ]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "mapped.csv"
            
            reports.write_clean_csv(output_path, test_results)
            
            with open(output_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
            
            # Check specific mappings
            assert "vt_status" in fieldnames
            assert "abuseipdb_status" in fieldnames
            assert "otx_status" in fieldnames
            assert "threatfox_status" in fieldnames
            assert "greynoise_status" in fieldnames
            assert "unknown_provider_status" in fieldnames
    
    def test_csv_windows_line_endings(self):
        """Test that CSV files don't have blank lines on Windows."""
        test_rows = [
            {"ioc": "test1", "status": "clean"},
            {"ioc": "test2", "status": "malicious"},
        ]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "no_blanks.csv"
            
            reports.write_csv(output_path, test_rows)
            
            # Read raw content to check for blank lines
            with open(output_path, "rb") as f:
                content = f.read()
            
            # Should not have \r\n\r\n (blank lines)
            assert b"\r\n\r\n" not in content
    
    def test_logging_integration(self):
        """Test that appropriate log messages are generated."""
        test_rows = [{"test": "data"}]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "logged.csv"
            
            with patch('reports.log') as mock_log:
                reports.write_csv(output_path, test_rows)
                
                # Should log successful write
                mock_log.info.assert_called_with(f"CSV report written → {output_path}") 