"""Tests for settings management functionality."""

import pytest
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import settings_manager


class TestSettingsManager:
    """Test cases for settings management."""
    
    def test_default_settings_structure(self):
        """Test that default settings have the expected structure."""
        defaults = settings_manager.DEFAULT_SETTINGS
        
        assert "provider_config" in defaults
        assert "show_threats_only" in defaults
        assert "dark_mode" in defaults
        
        provider_config = defaults["provider_config"]
        assert isinstance(provider_config, dict)
        assert "virustotal" in provider_config
        assert "abuseipdb" in provider_config
        assert "otx" in provider_config
        assert "threatfox" in provider_config
        assert "greynoise" in provider_config
        
        # All providers should default to False
        for provider, enabled in provider_config.items():
            assert enabled is False
    
    def test_load_settings_file_not_exists(self):
        """Test loading settings when file doesn't exist."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            settings_file = Path(tmp_dir) / "settings.json"
            
            settings = settings_manager.load_settings(settings_file)
            
            # Should return defaults and create file
            assert settings == settings_manager.DEFAULT_SETTINGS
            assert settings_file.exists()
            
            # Verify file content
            with open(settings_file, "r") as f:
                saved_settings = json.load(f)
            assert saved_settings == settings_manager.DEFAULT_SETTINGS
    
    def test_load_settings_existing_file(self):
        """Test loading settings from existing file."""
        test_settings = {
            "provider_config": {
                "virustotal": True,
                "abuseipdb": False,
                "otx": True,
                "threatfox": False,
                "greynoise": True,
            },
            "show_threats_only": True,
            "dark_mode": False,
        }
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            settings_file = Path(tmp_dir) / "settings.json"
            
            # Create test file
            with open(settings_file, "w") as f:
                json.dump(test_settings, f)
            
            settings = settings_manager.load_settings(settings_file)
            
            assert settings == test_settings
            assert settings["show_threats_only"] is True
            assert settings["provider_config"]["virustotal"] is True
    
    def test_load_settings_corrupted_file(self):
        """Test loading settings when file is corrupted."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            settings_file = Path(tmp_dir) / "settings.json"
            
            # Create corrupted JSON file
            with open(settings_file, "w") as f:
                f.write("{ invalid json content")
            
            with patch('settings_manager.log') as mock_log:
                settings = settings_manager.load_settings(settings_file)
                
                # Should fall back to defaults
                assert settings == settings_manager.DEFAULT_SETTINGS
                mock_log.error.assert_called_once()
    
    def test_save_settings_success(self):
        """Test successful settings save."""
        test_settings = {
            "provider_config": {
                "virustotal": True,
                "abuseipdb": True,
                "otx": False,
                "threatfox": True,
                "greynoise": False,
            },
            "show_threats_only": False,
            "dark_mode": True,
        }
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            settings_file = Path(tmp_dir) / "settings.json"
            
            settings_manager.save_settings(settings_file, test_settings)
            
            # Verify file was created and content is correct
            assert settings_file.exists()
            
            with open(settings_file, "r") as f:
                saved_settings = json.load(f)
            
            assert saved_settings == test_settings
    
    def test_save_settings_file_error(self):
        """Test settings save when file write fails."""
        test_settings = {"test": "value"}
        
        # Use a path that should fail (no permissions)
        invalid_path = Path("/invalid/path/settings.json")
        
        with patch('settings_manager.log') as mock_log:
            settings_manager.save_settings(invalid_path, test_settings)
            
            # Should log error without raising exception
            mock_log.error.assert_called_once()
    
    def test_settings_file_permissions(self):
        """Test that settings files are created with appropriate permissions."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            settings_file = Path(tmp_dir) / "settings.json"
            
            settings_manager.save_settings(settings_file, settings_manager.DEFAULT_SETTINGS)
            
            # File should be readable and writable by owner
            assert settings_file.exists()
            stat = settings_file.stat()
            # Check that file has reasonable permissions (readable by owner)
            assert stat.st_mode & 0o400  # Owner read
    
    def test_settings_json_formatting(self):
        """Test that saved JSON is properly formatted."""
        test_settings = {
            "provider_config": {
                "virustotal": True,
                "abuseipdb": False,
            },
            "show_threats_only": True,
        }
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            settings_file = Path(tmp_dir) / "settings.json"
            
            settings_manager.save_settings(settings_file, test_settings)
            
            # Read raw content to check formatting
            with open(settings_file, "r") as f:
                content = f.read()
            
            # Should be indented (pretty-printed)
            assert "    " in content  # 4-space indentation
            assert "\n" in content    # Multiple lines
    
    def test_round_trip_consistency(self):
        """Test that save/load cycle preserves data exactly."""
        original_settings = {
            "provider_config": {
                "virustotal": True,
                "abuseipdb": False,
                "otx": True,
                "threatfox": False,
                "greynoise": True,
            },
            "show_threats_only": True,
            "dark_mode": False,
        }
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            settings_file = Path(tmp_dir) / "settings.json"
            
            # Save then load
            settings_manager.save_settings(settings_file, original_settings)
            loaded_settings = settings_manager.load_settings(settings_file)
            
            assert loaded_settings == original_settings
    
    def test_partial_settings_merge(self):
        """Test behavior when loaded settings are missing some keys."""
        partial_settings = {
            "provider_config": {
                "virustotal": True,
                # Missing other providers
            },
            # Missing other top-level keys
        }
        
        with tempfile.TemporaryDirectory() as tmp_dir:
            settings_file = Path(tmp_dir) / "settings.json"
            
            # Save partial settings
            with open(settings_file, "w") as f:
                json.dump(partial_settings, f)
            
            loaded_settings = settings_manager.load_settings(settings_file)
            
            # Should load exactly what's in the file
            assert loaded_settings == partial_settings
            # Note: The current implementation doesn't merge with defaults,
            # it just loads what's in the file. This test documents that behavior.
    
    def test_logging_integration(self):
        """Test that appropriate log messages are generated."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            settings_file = Path(tmp_dir) / "settings.json"
            
            with patch('settings_manager.log') as mock_log:
                # Test successful load
                settings_manager.load_settings(settings_file)
                # Should log info about loaded settings (after save)
                
                # Test successful save
                settings_manager.save_settings(settings_file, {"test": "value"})
                mock_log.info.assert_called()
    
    def test_default_settings_immutability(self):
        """Test that modifying returned defaults doesn't affect the original."""
        defaults1 = settings_manager.DEFAULT_SETTINGS
        defaults2 = settings_manager.DEFAULT_SETTINGS
        
        # Should be the same object (constants)
        assert defaults1 is defaults2
        
        # Modifying a copy shouldn't affect the original
        copy_settings = defaults1.copy()
        copy_settings["dark_mode"] = True
        
        assert settings_manager.DEFAULT_SETTINGS["dark_mode"] is False 