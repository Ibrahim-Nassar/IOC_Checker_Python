# tests/test_reports.py
"""Test report generation functionality."""
import pytest
import tempfile
from pathlib import Path
from reports import write_csv, write_json, WRITERS

class TestReports:
    """Test report writing functionality."""
    
    def test_write_csv_basic(self):
        """Test basic CSV writing."""
        data = [
            {"value": "8.8.8.8", "type": "ip", "result": "clean"},
            {"value": "google.com", "type": "domain", "result": "clean"}
        ]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            csv_path = Path(f.name)
        
        try:
            write_csv(csv_path, data)
            assert csv_path.exists()
            
            content = csv_path.read_text(encoding='utf-8')
            assert "value,type,result" in content
            assert "8.8.8.8,ip,clean" in content
            
        finally:
            csv_path.unlink()
    
    def test_write_csv_empty_data(self):
        """Test CSV writing with empty data."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            csv_path = Path(f.name)
        
        try:
            write_csv(csv_path, [])
            # Should not crash, file may or may not exist
        finally:
            if csv_path.exists():
                csv_path.unlink()
    
    def test_write_json_basic(self):
        """Test basic JSON writing."""
        data = [{"value": "8.8.8.8", "type": "ip"}]
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json_path = Path(f.name)
        
        try:
            write_json(json_path, data)
            assert json_path.exists()
            
            content = json_path.read_text(encoding='utf-8')
            assert '"value": "8.8.8.8"' in content
            
        finally:
            json_path.unlink()
    
    def test_writers_dict_exists(self):
        """Test that WRITERS dictionary is properly configured."""
        assert "csv" in WRITERS
        assert "json" in WRITERS
        assert callable(WRITERS["csv"])
        assert callable(WRITERS["json"])
