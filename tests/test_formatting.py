# tests/test_formatting.py
"""Test output formatting functionality."""
import pytest
import json
from ioc_checker import _fmt

class TestFormatting:
    """Test console output formatting."""
    
    def test_fmt_abuseipdb_clean(self):
        """Test AbuseIPDB clean response formatting."""
        data = {"data": {"abuseConfidenceScore": 0, "isWhitelisted": False}}
        result = _fmt(data)
        assert "Clean" in result
    
    def test_fmt_abuseipdb_malicious(self):
        """Test AbuseIPDB malicious response formatting."""
        data = {"data": {"abuseConfidenceScore": 85, "isWhitelisted": False}}
        result = _fmt(data)
        assert "Malicious" in result
        assert "85" in result
    
    def test_fmt_abuseipdb_whitelisted(self):
        """Test AbuseIPDB whitelisted response formatting."""
        data = {"data": {"abuseConfidenceScore": 50, "isWhitelisted": True}}
        result = _fmt(data)
        assert "Clean (whitelisted)" in result
    
    def test_fmt_otx_clean(self):
        """Test OTX clean response formatting."""
        data = {"pulse_info": {"count": 0}}
        result = _fmt(data)
        assert "Clean" in result
    
    def test_fmt_otx_malicious(self):
        """Test OTX malicious response formatting."""
        data = {"pulse_info": {"count": 3}}
        result = _fmt(data)
        assert "Malicious" in result
        assert "3 OTX pulses" in result
    
    def test_fmt_threatfox_no_result(self):
        """Test ThreatFox no result response formatting."""
        data = {"query_status": "no_result"}
        result = _fmt(data)
        assert "Clean" in result
    
    def test_fmt_json_string_input(self):
        """Test formatting with JSON string input."""
        json_str = '{"data": {"abuseConfidenceScore": 0}}'
        result = _fmt(json_str)
        assert "Clean" in result
    
    def test_fmt_invalid_json(self):
        """Test formatting with invalid JSON."""
        result = _fmt("invalid json {")
        assert "unparseable" in result
    
    def test_fmt_parse_error(self):
        """Test formatting with parsing errors."""
        data = {"data": "malformed"}
        result = _fmt(data)
        assert "Parse error" in result
    
    def test_fmt_unknown_format(self):
        """Test formatting with unknown response format."""
        data = {"unknown_field": "value"}
        result = _fmt(data)
        assert result in ["Unknown", "Malicious"]
