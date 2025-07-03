#!/usr/bin/env python3
"""
Comprehensive tests for API key persistence across GUI lifecycles.
Ensures all provider keys persist reliably across sessions.
"""
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import pytest

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from api_key_store import save as save_key, load as load_key


class TestAPIKeyLifecycle(unittest.TestCase):
    """Test API key persistence across complete GUI lifecycles."""
    
    def setUp(self):
        """Set up test environment with clean state."""
        self.test_providers = [
            "VIRUSTOTAL_API_KEY",
            "ABUSEIPDB_API_KEY", 
            "OTX_API_KEY",
            "THREATFOX_API_KEY",
            "GREYNOISE_API_KEY"
        ]
        
        self.test_keys = {
            "VIRUSTOTAL_API_KEY": "vt_dummy_key_123",
            "ABUSEIPDB_API_KEY": "abuse_dummy_key_456", 
            "OTX_API_KEY": "otx_dummy_key_789",
            "THREATFOX_API_KEY": "tf_dummy_key_abc",
            "GREYNOISE_API_KEY": "gn_dummy_key_def"
        }
        
        # Clean up any existing test keys
        for var in self.test_providers:
            save_key(var, "")
            os.environ.pop(var, None)
    
    def tearDown(self):
        """Clean up after tests."""
        for var in self.test_providers:
            save_key(var, "")
            os.environ.pop(var, None)
    
    @patch('api_key_store._KEYRING_AVAILABLE', False)  # Force JSON fallback
    def test_all_provider_keys_persist_json_fallback(self):
        """Test all provider keys persist across sessions using JSON fallback."""
        # Phase 1: Save all keys
        for var, key in self.test_keys.items():
            save_key(var, key)
        
        # Verify immediate persistence
        for var, expected_key in self.test_keys.items():
            loaded_key = load_key(var)
            self.assertEqual(loaded_key, expected_key, f"Failed to load {var} immediately after save")
        
        # Phase 2: Simulate GUI restart - clear environment
        for var in self.test_providers:
            os.environ.pop(var, None)
        
        # Phase 3: Simulate GUI startup - reload keys
        loaded_keys_round2 = {}
        for var in self.test_providers:
            val = load_key(var)
            if val:
                os.environ[var] = val
                loaded_keys_round2[var] = val
        
        # Verify all keys survived the restart
        self.assertEqual(len(loaded_keys_round2), len(self.test_keys))
        for var, expected_key in self.test_keys.items():
            self.assertIn(var, loaded_keys_round2)
            self.assertEqual(loaded_keys_round2[var], expected_key)
            self.assertEqual(os.environ[var], expected_key)
    
    def test_selective_key_clearing_preserves_others(self):
        """Test that clearing some keys doesn't affect others."""
        # Save all keys
        for var, key in self.test_keys.items():
            save_key(var, key)
        
        # Clear only two keys
        keys_to_clear = ["VIRUSTOTAL_API_KEY", "GREYNOISE_API_KEY"]
        keys_to_keep = [k for k in self.test_providers if k not in keys_to_clear]
        
        for var in keys_to_clear:
            save_key(var, "")
        
        # Verify cleared keys are gone
        for var in keys_to_clear:
            self.assertIsNone(load_key(var))
        
        # Verify remaining keys are intact
        for var in keys_to_keep:
            loaded_key = load_key(var)
            self.assertEqual(loaded_key, self.test_keys[var])
    
    def test_gui_lifecycle_simulation(self):
        """Test complete GUI initialization and key loading cycles."""
        # Phase 1: Simulate first GUI startup with empty storage
        loaded_count_startup1 = 0
        for var in self.test_providers:
            val = load_key(var)
            if val:
                os.environ[var] = val
                loaded_count_startup1 += 1
        
        self.assertEqual(loaded_count_startup1, 0, "Should start with no saved keys")
        
        # Phase 2: User configures API keys (simulate save_keys dialog logic)
        saved_count = 0
        cleared_count = 0
        
        for var, new_key in self.test_keys.items():
            original_val = ""  # No original value
            current_val = new_key.strip()
            
            if current_val:
                save_key(var, current_val)
                os.environ[var] = current_val
                saved_count += 1
            elif original_val and not current_val:
                save_key(var, "")
                os.environ.pop(var, None)
                cleared_count += 1
        
        self.assertEqual(saved_count, len(self.test_keys))
        self.assertEqual(cleared_count, 0)
        
        # Phase 3: Simulate GUI restart
        for var in self.test_providers:
            os.environ.pop(var, None)
        
        # Phase 4: Second GUI startup - should load all saved keys
        loaded_keys_startup2 = []
        for var in self.test_providers:
            val = load_key(var)
            if val:
                os.environ[var] = val
                loaded_keys_startup2.append(var)
        
        self.assertEqual(len(loaded_keys_startup2), len(self.test_keys))
        for var in self.test_providers:
            self.assertIn(var, loaded_keys_startup2)
            self.assertEqual(os.environ[var], self.test_keys[var])
    
    def test_empty_string_handling(self):
        """Test that empty strings properly clear keys instead of saving empties."""
        var = "VIRUSTOTAL_API_KEY"
        test_key = "some_test_key"
        
        # Save a key first
        save_key(var, test_key)
        self.assertEqual(load_key(var), test_key)
        
        # Clear with empty string
        save_key(var, "")
        self.assertIsNone(load_key(var))
        
        # Clear with whitespace-only string
        save_key(var, test_key)  # Save again
        save_key(var, "   \t\n   ")  # Clear with whitespace
        self.assertIsNone(load_key(var))
    
    def test_whitespace_normalization(self):
        """Test that keys are properly normalized (trimmed)."""
        var = "VIRUSTOTAL_API_KEY"
        test_key = "clean_key_123"
        
        # Save key with whitespace
        save_key(var, f"  {test_key}  \t\n")
        
        # Should load back clean
        loaded = load_key(var)
        self.assertEqual(loaded, test_key)
    
    @patch('api_key_store._KEYRING_AVAILABLE', True)
    @patch('api_key_store.keyring')
    def test_keyring_fallback_behavior(self, mock_keyring):
        """Test that keyring failures gracefully fall back to JSON."""
        from api_key_store import KeyringError
        
        var = "VIRUSTOTAL_API_KEY"
        test_key = "keyring_fallback_test"
        
        # Ensure clean state first (clear any existing key)
        save_key(var, "")
        
        # Make all keyring operations fail to force JSON fallback
        mock_keyring.set_password.side_effect = KeyringError("Simulated keyring failure")
        mock_keyring.get_password.side_effect = KeyringError("Simulated keyring failure")
        mock_keyring.delete_password.side_effect = KeyringError("Simulated keyring failure")
        
        # Save should fall back to JSON without errors
        save_key(var, test_key)
        
        # Load should also fall back to JSON
        loaded = load_key(var)
        self.assertEqual(loaded, test_key)
        
        # Clear should also work with JSON fallback
        # Since all keyring operations fail, it will use JSON fallback for clearing too
        save_key(var, "")
        loaded_after_clear = load_key(var)
        self.assertIsNone(loaded_after_clear)


@pytest.mark.parametrize("provider_var,test_key", [
    ("VIRUSTOTAL_API_KEY", "vt_param_test_123"),
    ("ABUSEIPDB_API_KEY", "abuse_param_test_456"), 
    ("OTX_API_KEY", "otx_param_test_789"),
    ("THREATFOX_API_KEY", "tf_param_test_abc"),
    ("GREYNOISE_API_KEY", "gn_param_test_def")
])
def test_individual_provider_persistence(provider_var, test_key):
    """Parametrized test ensuring each provider's key persists individually."""
    # Clean slate
    save_key(provider_var, "")
    
    # Save key
    save_key(provider_var, test_key)
    
    # Verify immediate persistence
    assert load_key(provider_var) == test_key
    
    # Simulate restart by clearing environment
    os.environ.pop(provider_var, None)
    
    # Reload key (simulate GUI startup)
    reloaded_key = load_key(provider_var)
    assert reloaded_key == test_key
    
    # Clean up
    save_key(provider_var, "")


if __name__ == "__main__":
    unittest.main() 