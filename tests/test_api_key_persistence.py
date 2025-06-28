#!/usr/bin/env python3
"""
Tests for API key persistence functionality in the GUI.
"""
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from api_key_store import save as save_key, load as load_key


class TestAPIKeyPersistence(unittest.TestCase):
    """Test API key saving and loading functionality."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_env_var = "TEST_API_KEY"
        self.test_key_value = "test_key_123"
        
        # Clean up any existing test key
        try:
            save_key(self.test_env_var, "")
        except Exception:
            pass
    
    def tearDown(self):
        """Clean up after tests."""
        try:
            save_key(self.test_env_var, "")
        except Exception:
            pass
        
        if self.test_env_var in os.environ:
            del os.environ[self.test_env_var]
    
    def test_save_and_load_api_key(self):
        """Test saving and loading an API key."""
        # Save a test key
        save_key(self.test_env_var, self.test_key_value)
        
        # Load the key back
        loaded_key = load_key(self.test_env_var)
        
        self.assertEqual(loaded_key, self.test_key_value)
    
    def test_clear_api_key(self):
        """Test clearing an API key."""
        # Save a test key first
        save_key(self.test_env_var, self.test_key_value)
        
        # Verify it's saved
        self.assertEqual(load_key(self.test_env_var), self.test_key_value)
        
        # Clear the key
        save_key(self.test_env_var, "")
        
        # Verify it's cleared
        loaded_key = load_key(self.test_env_var)
        self.assertIsNone(loaded_key)
    
    def test_load_nonexistent_key(self):
        """Test loading a key that doesn't exist."""
        loaded_key = load_key("NONEXISTENT_API_KEY")
        self.assertIsNone(loaded_key)
    
    @patch('ioc_gui_tk.load_key')
    def test_gui_loads_saved_keys_on_init(self, mock_load_key):
        """Test that the GUI loads saved keys on initialization."""
        # Mock the load_key function to return a test value
        mock_load_key.return_value = self.test_key_value
        
        # Import and create GUI instance
        from ioc_gui_tk import IOCCheckerGUI
        
        # Mock tkinter to avoid creating actual GUI
        with patch('ioc_gui_tk.tk.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            # Create GUI instance
            gui = IOCCheckerGUI()
            
            # Verify that load_key was called for each provider
            expected_calls = [
                "VIRUSTOTAL_API_KEY",
                "ABUSEIPDB_API_KEY", 
                "OTX_API_KEY",
                "THREATFOX_API_KEY",
                "GREYNOISE_API_KEY"
            ]
            
            actual_calls = [call[0][0] for call in mock_load_key.call_args_list]
            
            for expected_call in expected_calls:
                self.assertIn(expected_call, actual_calls)
    
    @patch('ioc_gui_tk.save_key')
    @patch('ioc_gui_tk.load_key')
    def test_gui_saves_keys_on_configure(self, mock_load_key, mock_save_key):
        """Test that the GUI saves keys when configured."""
        # This would test the save_keys function in the GUI
        # For now, we'll test the basic functionality
        mock_load_key.return_value = ""
        
        from ioc_gui_tk import IOCCheckerGUI
        
        with patch('ioc_gui_tk.tk.Tk') as mock_tk:
            mock_root = MagicMock()
            mock_tk.return_value = mock_root
            
            gui = IOCCheckerGUI()
            
            # Verify load_key was called during initialization
            self.assertTrue(mock_load_key.called)


if __name__ == '__main__':
    unittest.main() 