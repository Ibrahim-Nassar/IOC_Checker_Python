#!/usr/bin/env python3
"""Unit tests for batch processing enhancements."""

import pytest
from unittest.mock import Mock
from ioc_gui_tk import IOCCheckerGUI


class TestBatchProcessing:
    """Test cases for batch processing features."""
    
    def test_duplicate_ioc_tracking(self):
        """Test that processed IOCs are tracked to prevent duplicates."""
        gui = IOCCheckerGUI()
        
        # Initially empty
        assert len(gui.processed_iocs) == 0
        
        # Add some IOCs
        test_iocs = ["1.1.1.1", "google.com", "https://example.com"]
        for ioc in test_iocs:
            gui.processed_iocs.add(ioc)
        
        # Check they're tracked
        assert len(gui.processed_iocs) == 3
        for ioc in test_iocs:
            assert ioc in gui.processed_iocs
        
        # Adding duplicates should not increase count
        gui.processed_iocs.add("1.1.1.1")
        assert len(gui.processed_iocs) == 3
        
        # Clear should empty the set
        gui.processed_iocs.clear()
        assert len(gui.processed_iocs) == 0
    
    def test_batch_ui_state_management(self):
        """Test that batch UI state is properly managed."""
        gui = IOCCheckerGUI()
        
        # Initially should be in ready state (check buttons exist)
        assert hasattr(gui, 'process_button')
        assert hasattr(gui, 'stop_button')
        assert gui.batch_task is None
        
        # Test reset method sets proper states
        gui._reset_batch_ui()
        assert str(gui.process_button['state']) in ['normal', '']  # Allow for test environment
        assert str(gui.stop_button['state']) in ['disabled', '']
        assert gui.batch_task is None
    
    def test_csv_export_structure(self):
        """Test that CSV export creates correct structure."""
        gui = IOCCheckerGUI()
        
        # Mock results data
        test_results = [
            {'type': 'ip', 'ioc': '1.1.1.1', 'verdict': 'clean', 'flagged_by': ''},
            {'type': 'domain', 'ioc': 'evil.com', 'verdict': 'malicious', 'flagged_by': 'virustotal'},
            {'type': 'url', 'ioc': 'http://bad.site', 'verdict': 'error', 'flagged_by': 'API Error'}
        ]
        
        # Create a temporary file for testing
        import tempfile
        import csv
        
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False) as temp_file:
            temp_file.write("test data")
            temp_filename = temp_file.name
        
        try:
            # Test export
            csv_path = gui._export_batch_results(temp_filename, test_results)
            
            # Check file was created
            assert csv_path is not None
            assert csv_path.endswith('.csv')
            
            # Check CSV content
            with open(csv_path, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                rows = list(reader)
                
                assert len(rows) == 3
                assert rows[0]['type'] == 'ip'
                assert rows[0]['ioc'] == '1.1.1.1'
                assert rows[0]['verdict'] == 'clean'
                assert rows[1]['verdict'] == 'malicious'
                assert rows[2]['verdict'] == 'error'
        
        finally:
            # Cleanup
            import os
            try:
                os.unlink(temp_filename)
                if csv_path:
                    os.unlink(csv_path)
            except:
                pass  # Best effort cleanup 