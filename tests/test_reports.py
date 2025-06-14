"""
Comprehensive tests for reports.py module.
Tests all report writers and error handling.
"""
import pytest
import json
import csv
import pathlib
from unittest.mock import patch, Mock
from reports import (
    write_csv, write_json, write_excel, write_html, 
    WRITERS, PANDAS_AVAILABLE
)


class TestCSVWriter:
    """Test CSV report writer."""
    
    def test_write_csv_success(self, temp_dir):
        """Test successful CSV writing."""
        test_data = [
            {"value": "8.8.8.8", "type": "ip", "provider1": "clean", "provider2": "malicious"},
            {"value": "example.com", "type": "domain", "provider1": "clean", "provider2": "clean"}
        ]
        
        output_path = temp_dir / "test_output.csv"
        write_csv(output_path, test_data)
        
        assert output_path.exists()
        
        # Verify content
        with output_path.open(encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            assert len(rows) == 2
            assert rows[0]["value"] == "8.8.8.8"
            assert rows[1]["type"] == "domain"
    
    def test_write_csv_empty_data(self, temp_dir):
        """Test CSV writing with empty data."""
        output_path = temp_dir / "empty.csv"
        write_csv(output_path, [])
        
        # Should not create file for empty data
        assert not output_path.exists()
    
    def test_write_csv_unicode(self, temp_dir):
        """Test CSV writing with Unicode characters."""
        test_data = [
            {"value": "münchen.de", "type": "domain", "result": "清洁的"}
        ]
        
        output_path = temp_dir / "unicode.csv"
        write_csv(output_path, test_data)
        
        assert output_path.exists()
        
        # Verify Unicode handling
        with output_path.open(encoding="utf-8") as f:
            content = f.read()
            assert "münchen.de" in content
            assert "清洁的" in content
    
    def test_write_csv_error_handling(self, temp_dir):
        """Test CSV writing error handling."""
        test_data = [{"key": "value"}]
        
        # Try to write to a directory instead of file
        output_path = temp_dir / "subdir"
        output_path.mkdir()
        
        # Should handle error gracefully
        write_csv(output_path, test_data)  # This should log error but not raise


class TestJSONWriter:
    """Test JSON report writer."""
    
    def test_write_json_success(self, temp_dir):
        """Test successful JSON writing."""
        test_data = [
            {"value": "8.8.8.8", "type": "ip", "results": {"provider1": "clean"}},
            {"value": "example.com", "type": "domain", "results": {"provider1": "suspicious"}}
        ]
        
        output_path = temp_dir / "test_output.json"
        write_json(output_path, test_data)
        
        assert output_path.exists()
        
        # Verify content
        with output_path.open(encoding="utf-8") as f:
            loaded_data = json.load(f)
            assert len(loaded_data) == 2
            assert loaded_data[0]["value"] == "8.8.8.8"
            assert loaded_data[1]["results"]["provider1"] == "suspicious"
    
    def test_write_json_unicode(self, temp_dir):
        """Test JSON writing with Unicode characters."""
        test_data = [
            {"value": "тест.com", "result": "测试"}
        ]
        
        output_path = temp_dir / "unicode.json"
        write_json(output_path, test_data)
        
        assert output_path.exists()
        
        # Verify Unicode handling
        with output_path.open(encoding="utf-8") as f:
            content = f.read()
            assert "тест.com" in content
            assert "测试" in content
    
    def test_write_json_pretty_format(self, temp_dir):
        """Test JSON writing produces pretty formatted output."""
        test_data = [{"key": "value", "nested": {"inner": "data"}}]
        
        output_path = temp_dir / "pretty.json"
        write_json(output_path, test_data)
        
        with output_path.open(encoding="utf-8") as f:
            content = f.read()
            # Pretty formatted JSON should have indentation
            assert "  " in content  # Indentation
            assert "\n" in content  # Newlines
    
    def test_write_json_error_handling(self, temp_dir):
        """Test JSON writing error handling."""
        test_data = [{"key": "value"}]
        
        # Try to write to invalid path
        output_path = temp_dir / "nonexistent" / "test.json"
        
        # Should handle error gracefully
        write_json(output_path, test_data)


class TestExcelWriter:
    """Test Excel report writer."""
    
    def test_write_excel_with_pandas(self, temp_dir):
        """Test Excel writing when pandas is available."""
        if not PANDAS_AVAILABLE:
            pytest.skip("Pandas not available")
        
        test_data = [
            {"value": "8.8.8.8", "type": "ip", "score": 0},
            {"value": "example.com", "type": "domain", "score": 5}
        ]
        
        output_path = temp_dir / "test_output.xlsx"
        write_excel(output_path, test_data)
        
        assert output_path.exists()
        assert output_path.stat().st_size > 0
    
    def test_write_excel_without_pandas(self, temp_dir):
        """Test Excel writing when pandas is not available."""
        test_data = [{"key": "value"}]
        output_path = temp_dir / "test.xlsx"
        
        with patch('reports.PANDAS_AVAILABLE', False):
            write_excel(output_path, test_data)
            # Should not create file when pandas unavailable
            assert not output_path.exists()
    
    def test_write_excel_empty_data(self, temp_dir):
        """Test Excel writing with empty data."""
        if not PANDAS_AVAILABLE:
            pytest.skip("Pandas not available")
        
        output_path = temp_dir / "empty.xlsx"
        write_excel(output_path, [])
        
        # Should not create file for empty data
        assert not output_path.exists()
    
    def test_write_excel_error_handling(self, temp_dir):
        """Test Excel writing error handling."""
        if not PANDAS_AVAILABLE:
            pytest.skip("Pandas not available")
        
        test_data = [{"key": "value"}]
        
        # Mock pandas to raise an exception
        with patch('reports.pd.DataFrame') as mock_df:
            mock_df.side_effect = Exception("Pandas error")
            
            output_path = temp_dir / "error.xlsx"
            write_excel(output_path, test_data)
            # Should handle error gracefully


class TestHTMLWriter:
    """Test HTML report writer."""
    
    def test_write_html_with_pandas(self, temp_dir):
        """Test HTML writing when pandas is available."""
        if not PANDAS_AVAILABLE:
            pytest.skip("Pandas not available")
        
        test_data = [
            {"value": "8.8.8.8", "type": "ip", "result": "clean"},
            {"value": "example.com", "type": "domain", "result": "malicious"}
        ]
        
        output_path = temp_dir / "test_output.html"
        write_html(output_path, test_data)
        
        assert output_path.exists()
        
        # Verify HTML content
        with output_path.open(encoding="utf-8") as f:
            content = f.read()
            assert "table" in content.lower()  # pandas creates table with different attributes
            assert "<meta charset='utf-8'>" in content
            assert "8.8.8.8" in content
            assert "example.com" in content
    
    def test_write_html_without_pandas(self, temp_dir):
        """Test HTML writing fallback when pandas is not available."""
        test_data = [
            {"value": "8.8.8.8", "type": "ip", "result": "clean"},
            {"value": "example.com", "type": "domain", "result": "malicious"}
        ]
        
        output_path = temp_dir / "fallback.html"
        
        with patch('reports.PANDAS_AVAILABLE', False):
            write_html(output_path, test_data)
        
        assert output_path.exists()
        
        # Verify fallback HTML content
        with output_path.open(encoding="utf-8") as f:
            content = f.read()
            assert "<table>" in content
            assert "<meta charset='utf-8'>" in content
            assert "8.8.8.8" in content
            assert "example.com" in content
            assert "<th>" in content  # Headers
            assert "<td>" in content  # Data cells
    
    def test_write_html_unicode(self, temp_dir):
        """Test HTML writing with Unicode characters."""
        test_data = [
            {"domain": "münchen.de", "result": "清洁的"}
        ]
        
        output_path = temp_dir / "unicode.html"
        write_html(output_path, test_data)
        
        assert output_path.exists()
        
        with output_path.open(encoding="utf-8") as f:
            content = f.read()
            assert "münchen.de" in content
            assert "清洁的" in content
    
    def test_write_html_empty_data(self, temp_dir):
        """Test HTML writing with empty data."""
        output_path = temp_dir / "empty.html"
        write_html(output_path, [])
        
        # Should not create file for empty data
        assert not output_path.exists()
    
    def test_write_html_fallback_empty_data(self, temp_dir):
        """Test HTML fallback with empty data."""
        output_path = temp_dir / "empty_fallback.html"
        
        with patch('reports.PANDAS_AVAILABLE', False):
            write_html(output_path, [])
        
        # Should not create file for empty data even in fallback
        assert not output_path.exists()
    
    def test_write_html_styling(self, temp_dir):
        """Test HTML output includes proper styling."""
        test_data = [{"key": "value"}]
        output_path = temp_dir / "styled.html"
        
        write_html(output_path, test_data)
        
        with output_path.open(encoding="utf-8") as f:
            content = f.read()
            assert "border-collapse:collapse" in content
            assert "border:1px solid" in content
            assert "padding:4px" in content
    
    def test_write_html_error_handling(self, temp_dir):
        """Test HTML writing error handling."""
        test_data = [{"key": "value"}]
        
        # Try to write to invalid path
        output_path = temp_dir / "nonexistent" / "test.html"
        
        # Should handle error gracefully
        write_html(output_path, test_data)


class TestWritersDict:
    """Test the WRITERS dictionary."""
    
    def test_writers_dict_completeness(self):
        """Test that all expected writers are present."""
        expected_writers = {"csv", "json", "xlsx", "html"}
        assert set(WRITERS.keys()) == expected_writers
    
    def test_writers_are_callable(self):
        """Test that all writers are callable functions."""
        for writer in WRITERS.values():
            assert callable(writer)
    
    def test_writers_function_mapping(self):
        """Test that writers map to correct functions."""
        assert WRITERS["csv"] == write_csv
        assert WRITERS["json"] == write_json
        assert WRITERS["xlsx"] == write_excel
        assert WRITERS["html"] == write_html


class TestReportIntegration:
    """Integration tests for report functionality."""
    
    def test_all_writers_with_same_data(self, temp_dir):
        """Test all writers with the same data set."""
        test_data = [
            {
                "value": "8.8.8.8", 
                "type": "ip", 
                "results": {
                    "abuseipdb": "clean",
                    "virustotal": "malicious",
                    "otx": "suspicious"
                }
            },
            {
                "value": "example.com",
                "type": "domain",
                "results": {
                    "abuseipdb": "N/A",
                    "virustotal": "clean",
                    "otx": "clean"
                }
            }
        ]
        
        # Test all writers
        base_path = temp_dir / "integrated_test"
        
        WRITERS["csv"](base_path.with_suffix(".csv"), test_data)
        WRITERS["json"](base_path.with_suffix(".json"), test_data)
        WRITERS["html"](base_path.with_suffix(".html"), test_data)
        
        if PANDAS_AVAILABLE:
            WRITERS["xlsx"](base_path.with_suffix(".xlsx"), test_data)
        
        # Verify all files were created
        assert base_path.with_suffix(".csv").exists()
        assert base_path.with_suffix(".json").exists()
        assert base_path.with_suffix(".html").exists()
        
        if PANDAS_AVAILABLE:
            assert base_path.with_suffix(".xlsx").exists()
    
    def test_writers_with_complex_data(self, temp_dir):
        """Test writers with complex nested data."""
        test_data = [
            {
                "value": "complex.test.com",
                "type": "domain",
                "results": {
                    "provider1": {"status": "clean", "score": 0, "details": {"reason": "trusted"}},
                    "provider2": {"status": "malicious", "score": 10, "details": {"threats": ["malware", "phishing"]}}
                },
                "metadata": {
                    "timestamp": "2025-06-14T12:00:00Z",
                    "source": "automated_scan"
                }
            }
        ]
        
        # Test that writers handle complex data structures
        base_path = temp_dir / "complex_test"
        
        # JSON should handle nested data perfectly
        WRITERS["json"](base_path.with_suffix(".json"), test_data)
        with base_path.with_suffix(".json").open() as f:
            loaded = json.load(f)
            assert loaded[0]["results"]["provider1"]["details"]["reason"] == "trusted"
        
        # CSV should flatten or represent nested data as strings
        WRITERS["csv"](base_path.with_suffix(".csv"), test_data)
        assert base_path.with_suffix(".csv").exists()
        
        # HTML should handle nested data (likely as string representation)
        WRITERS["html"](base_path.with_suffix(".html"), test_data)
        assert base_path.with_suffix(".html").exists()
    
    def test_writers_with_special_characters(self, temp_dir):
        """Test writers handle special characters and edge cases."""
        test_data = [
            {
                "value": "test,with,commas.com",
                "type": "domain", 
                "result": 'String with "quotes" and newlines\nand tabs\t',
                "unicode": "Ñiño@münchen.de",
                "symbols": "!@#$%^&*()_+-=[]{}|;:,.<>?"
            }
        ]
        
        base_path = temp_dir / "special_chars"
        
        # Test all writers handle special characters
        for format_type, writer in WRITERS.items():
            if format_type == "xlsx" and not PANDAS_AVAILABLE:
                continue
            
            output_path = base_path.with_suffix(f".{format_type}")
            writer(output_path, test_data)
            assert output_path.exists()
            
            # Verify file has content
            assert output_path.stat().st_size > 0


class TestErrorConditions:
    """Test various error conditions and edge cases."""
    
    def test_writers_with_invalid_data_types(self, temp_dir):
        """Test writers handle invalid data types gracefully."""
        # Test with non-serializable objects
        class NonSerializable:
            def __str__(self):
                return "non_serializable_object"
        
        test_data = [
            {
                "value": "test.com",
                "object": NonSerializable(),
                "none_value": None,
                "empty_string": "",
                "zero": 0
            }
        ]
        
        base_path = temp_dir / "invalid_types"
        
        # CSV and HTML should handle this (converting to strings)
        WRITERS["csv"](base_path.with_suffix(".csv"), test_data)
        WRITERS["html"](base_path.with_suffix(".html"), test_data)
        
        # JSON might have issues with non-serializable objects, but should handle gracefully
        WRITERS["json"](base_path.with_suffix(".json"), test_data)
    
    def test_writers_with_readonly_directory(self, temp_dir):
        """Test writers handle permission errors gracefully."""
        test_data = [{"key": "value"}]
        
        # Create a subdirectory and try to make it readonly
        readonly_dir = temp_dir / "readonly"
        readonly_dir.mkdir()
        
        try:
            readonly_dir.chmod(0o444)  # Read-only
            output_path = readonly_dir / "test.csv"
            
            # Should handle permission error gracefully
            write_csv(output_path, test_data)
            
        except PermissionError:
            # On some systems, we might not be able to set readonly
            pass
        finally:
            # Restore permissions for cleanup
            try:
                readonly_dir.chmod(0o755)
            except:
                pass
    
    def test_pandas_availability_detection(self):
        """Test pandas availability detection."""
        # Test that PANDAS_AVAILABLE is a boolean
        assert isinstance(PANDAS_AVAILABLE, bool)
        
        # Test behavior when pandas is mocked as unavailable
        with patch('reports.PANDAS_AVAILABLE', False):
            from reports import PANDAS_AVAILABLE as mocked_pandas
            assert mocked_pandas is False