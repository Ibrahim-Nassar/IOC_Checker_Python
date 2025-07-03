#!/usr/bin/env python3
"""Integration test for provider mismatch handling in batch processing."""

import pytest
import tempfile
import csv
from pathlib import Path
from unittest.mock import Mock, patch
from ioc_gui_tk import IOCCheckerGUI


class TestProviderMismatchIntegration:
    """Integration tests for provider mismatch detection in batch processing."""
    
    def setup_method(self):
        """Set up test environment."""
        self.gui = IOCCheckerGUI()
        
        # Mock selected providers - only AbuseIPDB (IP only)
        mock_provider = Mock()
        mock_provider.NAME = "AbuseIPDB"
        self.gui._selected_providers = Mock(return_value=[mock_provider])
        
        # Mock messagebox to avoid GUI popups during tests
        self.messagebox_patches = [
            patch('ioc_gui_tk.messagebox.showerror'),
            patch('ioc_gui_tk.messagebox.showinfo'),
            patch('ioc_gui_tk.messagebox.showwarning'),
        ]
        
        self.mock_showerror = self.messagebox_patches[0].start()
        self.mock_showinfo = self.messagebox_patches[1].start()
        self.mock_showwarning = self.messagebox_patches[2].start()

    def teardown_method(self):
        """Clean up after tests."""
        for patch in self.messagebox_patches:
            patch.stop()
        if hasattr(self.gui, 'root'):
            self.gui.root.destroy()

    def test_mismatch_detection_in_start_batch(self):
        """Test that mismatch detection is properly integrated into _start_batch."""
        # Create test CSV content
        csv_content = "IOC,Type\n8.8.8.8,ip\nmalicious.com,domain\n"
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
        temp_file.write(csv_content)
        temp_file.close()
        
        try:
            self.gui.file_var.set(temp_file.name)
            
            # Mock the dialog to return 'cancel' to test integration
            with patch.object(self.gui, '_show_provider_mismatch_dialog') as mock_dialog:
                mock_dialog.return_value = ('cancel', False)
                
                with patch('loader.load_iocs') as mock_load:
                    mock_load.return_value = [
                        {'value': '8.8.8.8', 'type': 'ip'},
                        {'value': 'malicious.com', 'type': 'domain'},
                    ]
                    
                    # Call the actual method
                    self.gui._start_batch()
                    
                    # Verify the dialog was called (proving integration works)
                    mock_dialog.assert_called_once()
                    
        finally:
            Path(temp_file.name).unlink()

    def test_no_mismatch_scenario(self):
        """Test batch processing when all IOCs are supported."""
        # Create test CSV content with only IP addresses
        csv_content = "IOC,Type\n8.8.8.8,ip\n1.1.1.1,ip\n"
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
        temp_file.write(csv_content)
        temp_file.close()
        
        try:
            self.gui.file_var.set(temp_file.name)
            
            with patch.object(self.gui, '_show_provider_mismatch_dialog') as mock_dialog:
                with patch('loader.load_iocs') as mock_load:
                    mock_load.return_value = [
                        {'value': '8.8.8.8', 'type': 'ip'},
                        {'value': '1.1.1.1', 'type': 'ip'},
                    ]
                    
                    with patch('asyncio.run_coroutine_threadsafe') as mock_async:
                        # Call the method
                        self.gui._start_batch()
                        
                        # Dialog should NOT be called since no mismatch
                        mock_dialog.assert_not_called()
                        
        finally:
            Path(temp_file.name).unlink() 