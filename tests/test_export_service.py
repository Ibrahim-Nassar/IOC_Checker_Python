"""Tests for ExportService functionality."""
import pytest
import tempfile
import os
from unittest.mock import patch, mock_open
from pathlib import Path

from services import ExportService


class TestExportService:
    """Test ExportService methods."""
    
    def test_export_unsupported_iocs_success(self):
        """Test successful export of unsupported IOCs."""
        unsupported_iocs = [
            {
                'original': 'example.com',
                'normalized': 'example.com',
                'type': 'domain',
                'reason': 'No active providers support domain IOCs'
            },
            {
                'original': 'http://malicious.com',
                'normalized': 'http://malicious.com',
                'type': 'url',
                'reason': 'No active providers support url IOCs'
            }
        ]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = os.path.join(tmp_dir, "test.csv")
            result = ExportService.export_unsupported_iocs(test_file, unsupported_iocs)
            
            # Should return a path to the created file
            assert result is not None
            assert os.path.exists(result)
            
            # Check file content
            with open(result, 'r') as f:
                content = f.read()
                assert 'original_ioc,normalized_ioc,type,reason' in content
                assert 'example.com' in content
                assert 'http://malicious.com' in content
    
    def test_export_unsupported_iocs_io_error(self):
        """Test export_unsupported_iocs with IO error."""
        unsupported_iocs = [{'original': 'test', 'normalized': 'test', 'type': 'ip', 'reason': 'test'}]
        
        with patch('builtins.open', mock_open()) as mock_file:
            mock_file.side_effect = IOError("Permission denied")
            
            result = ExportService.export_unsupported_iocs("/invalid/path/test.csv", unsupported_iocs)
            
            # Should return None on IO error
            assert result is None
    
    def test_export_batch_results_success(self):
        """Test successful export of batch results."""
        results = [
            {
                'type': 'ip',
                'ioc': '1.1.1.1',
                'verdict': 'clean',
                'flagged_by': ''
            },
            {
                'type': 'domain',
                'ioc': 'malicious.com',
                'verdict': 'malicious',
                'flagged_by': 'VirusTotal'
            }
        ]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = os.path.join(tmp_dir, "input.csv")
            result = ExportService.export_batch_results(test_file, results)
            
            # Should return a path to the created file
            assert result is not None
            assert os.path.exists(result)
            
            # Check file content
            with open(result, 'r') as f:
                content = f.read()
                assert 'type,ioc,verdict,flagged_by' in content
                assert '1.1.1.1' in content
                assert 'malicious.com' in content
    
    def test_export_batch_results_cancelled(self):
        """Test export_batch_results with cancelled flag."""
        results = [{'type': 'ip', 'ioc': '1.1.1.1', 'verdict': 'clean', 'flagged_by': ''}]
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_file = os.path.join(tmp_dir, "input.csv")
            result = ExportService.export_batch_results(test_file, results, cancelled=True)
            
            # Should include "_cancelled" in filename
            assert "_cancelled" in result
            assert os.path.exists(result)
    
    def test_export_batch_results_io_error(self):
        """Test export_batch_results with IO error."""
        results = [{'type': 'ip', 'ioc': '1.1.1.1', 'verdict': 'clean', 'flagged_by': ''}]
        
        with patch('builtins.open', mock_open()) as mock_file:
            mock_file.side_effect = IOError("Disk full")
            
            with pytest.raises(IOError):
                ExportService.export_batch_results("/invalid/path/test.csv", results) 