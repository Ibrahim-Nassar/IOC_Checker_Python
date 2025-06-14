"""
Test clean CSV format output with structured status columns.
"""
import pytest
import tempfile
import os
from unittest.mock import Mock, AsyncMock, patch
from pathlib import Path
import csv


def test_csv_format_structure():
    """Test that CSV output has exactly the required columns."""
    # Create mock results with structured provider data
    mock_results = [
        {
            "value": "8.8.8.8",
            "type": "ip",
            "results": {
                "virustotal": {"status": "clean", "score": 0, "raw": {}},
                "abuseipdb": {"status": "clean", "score": 0, "raw": {}},
                "otx": {"status": "malicious", "score": 80, "raw": {}}
            }
        },
        {
            "value": "malicious.com",
            "type": "domain", 
            "results": {
                "virustotal": {"status": "malicious", "score": 90, "raw": {}},
                "otx": {"status": "malicious", "score": 80, "raw": {}},
                "threatfox": {"status": "clean", "score": 0, "raw": {}}
            }
        },
        {
            "value": "http://bad.url",
            "type": "url",
            "results": {
                "urlhaus": {"status": "malicious", "score": 85, "raw": {}},
                "otx": {"status": "clean", "score": 0, "raw": {}}
            }
        }
    ]
    
    # Test the clean CSV writer
    from reports import write_clean_csv
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        csv_path = Path(f.name)
    
    try:
        # Write the clean CSV
        write_clean_csv(csv_path, mock_results)
        
        # Verify the file exists
        assert csv_path.exists(), "CSV file should be created"
        
        # Read and verify the structure
        with csv_path.open('r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            
            # Check header columns
            expected_columns = {"ioc", "ioc_type", "vt_status", "otx_status", "abuseipdb_status", "threatfox_status", "urlhaus_status", "overall"}
            assert set(reader.fieldnames) == expected_columns, f"Expected columns {expected_columns}, got {set(reader.fieldnames)}"
            
            # Check number of rows
            assert len(rows) == 3, f"Expected 3 rows, got {len(rows)}"
            
            # Check first row content
            row1 = rows[0]
            assert row1["ioc"] == "8.8.8.8"
            assert row1["ioc_type"] == "ip"
            assert row1["vt_status"] == "clean"
            assert row1["otx_status"] == "malicious"
            assert row1["abuseipdb_status"] == "clean"
            assert row1["overall"] == "HIGH"  # Should be HIGH due to malicious OTX
            
            # Check second row
            row2 = rows[1]
            assert row2["ioc"] == "malicious.com"
            assert row2["ioc_type"] == "domain"
            assert row2["vt_status"] == "malicious"
            assert row2["otx_status"] == "malicious"
            assert row2["overall"] == "HIGH"
            
            # Check third row
            row3 = rows[2]
            assert row3["ioc"] == "http://bad.url"
            assert row3["ioc_type"] == "url"
            assert row3["urlhaus_status"] == "malicious"
            assert row3["otx_status"] == "clean"
            assert row3["overall"] == "HIGH"
            
    finally:
        if csv_path.exists():
            os.unlink(csv_path)


def test_overall_risk_calculation():
    """Test the overall risk calculation logic."""
    from reports import _calculate_overall_risk
    
    # Test HIGH risk (malicious present)
    high_risk = {
        "virustotal": {"status": "malicious", "score": 90},
        "abuseipdb": {"status": "clean", "score": 0}
    }
    assert _calculate_overall_risk(high_risk) == "HIGH"
    
    # Test MEDIUM risk (suspicious present)
    medium_risk = {
        "virustotal": {"status": "suspicious", "score": 60},
        "abuseipdb": {"status": "clean", "score": 0}
    }
    assert _calculate_overall_risk(medium_risk) == "MEDIUM"
    
    # Test LOW risk (only clean)
    low_risk = {
        "virustotal": {"status": "clean", "score": 0},
        "abuseipdb": {"status": "clean", "score": 0}
    }
    assert _calculate_overall_risk(low_risk) == "LOW"
    
    # Test LOW risk (only n/a)
    na_risk = {
        "virustotal": {"status": "n/a", "score": 0},
        "abuseipdb": {"status": "n/a", "score": 0}
    }
    assert _calculate_overall_risk(na_risk) == "LOW"


def test_legacy_string_handling():
    """Test handling of legacy string responses during transition."""
    mock_results = [
        {
            "value": "test.com",
            "type": "domain",
            "results": {
                "virustotal": "Clean",  # Legacy string format
                "abuseipdb": {"status": "clean", "score": 0, "raw": {}},  # New format
                "otx": "error: timeout"  # Error string
            }
        }
    ]
    
    from reports import write_clean_csv
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        csv_path = Path(f.name)
    
    try:
        write_clean_csv(csv_path, mock_results)
        
        with csv_path.open('r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            row = next(reader)
            
            # Legacy string should be mapped to clean (conservative)
            assert row["vt_status"] == "clean"
            assert row["abuseipdb_status"] == "clean"
            assert row["otx_status"] == "n/a"  # Error should be n/a
            
    finally:
        if csv_path.exists():
            os.unlink(csv_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])