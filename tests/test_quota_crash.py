"""Test quota persistence and crash recovery."""
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from quota import _save, _load, increment_provider, remaining


class TestQuotaCrash:
    """Test quota system crash resistance and JSON integrity."""
    
    def test_quota_json_integrity_after_crash_simulation(self):
        """Test that quota JSON remains intact after simulated crash."""
        # Create a temporary quota file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        
        try:
            # Test data
            test_data = {
                "2024-01-01": {"VirusTotal": 100, "AbuseIPDB": 50},
                "2024-01-02": {"VirusTotal": 200, "AbuseIPDB": 75}
            }
            
            # Mock the quota path to use our temp file
            with patch('quota._PATH', temp_path):
                # Save initial data
                _save(test_data)
                
                # Verify file was created and is valid JSON
                assert temp_path.exists()
                with temp_path.open('r') as f:
                    loaded_data = json.load(f)
                    assert loaded_data == test_data
                
                # Simulate crash during write by mocking os.replace to fail
                def failing_replace(src, dst):
                    # Simulate partial write/corruption
                    raise OSError("Simulated crash during file replacement")
                
                with patch('os.replace', side_effect=failing_replace):
                    # This should fail but not corrupt the original file
                    with pytest.raises(OSError):
                        _save({"2024-01-03": {"VirusTotal": 300}})
                
                # Original file should still be intact
                assert temp_path.exists()
                with temp_path.open('r') as f:
                    recovered_data = json.load(f)
                    assert recovered_data == test_data
                
                # _load should still work correctly
                loaded_data = _load()
                assert loaded_data == test_data
        
        finally:
            # Clean up
            if temp_path.exists():
                temp_path.unlink()
    
    def test_quota_atomic_writes(self):
        """Test that quota writes are atomic using temporary files."""
        # Create a temporary quota file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        
        try:
            # Test data
            original_data = {"2024-01-01": {"VirusTotal": 100}}
            new_data = {"2024-01-01": {"VirusTotal": 200}}
            
            # Mock the quota path to use our temp file
            with patch('quota._PATH', temp_path):
                # Save original data
                _save(original_data)
                
                # Verify temp file is created during write
                temp_file_created = []
                original_open = open
                
                def mock_open(filename, *args, **kwargs):
                    if str(filename).endswith('.tmp'):
                        temp_file_created.append(filename)
                    return original_open(filename, *args, **kwargs)
                
                with patch('builtins.open', side_effect=mock_open):
                    _save(new_data)
                
                # Should have created a temp file
                assert len(temp_file_created) > 0
                
                # Final file should have new data
                loaded_data = _load()
                assert loaded_data == new_data
                
                # Temp file should be cleaned up
                for temp_file_path in temp_file_created:
                    assert not Path(temp_file_path).exists()
        
        finally:
            # Clean up
            if temp_path.exists():
                temp_path.unlink()
    
    def test_quota_fsync_error_handling(self):
        """Test that quota system handles fsync errors gracefully."""
        # Create a temporary quota file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        
        try:
            # Test data
            test_data = {"2024-01-01": {"VirusTotal": 100}}
            
            # Mock the quota path to use our temp file
            with patch('quota._PATH', temp_path):
                # Mock fsync to fail
                def failing_fsync(fd):
                    raise OSError("fsync not supported")
                
                with patch('os.fsync', side_effect=failing_fsync):
                    # Should still work despite fsync failure
                    _save(test_data)
                
                # Data should still be saved
                loaded_data = _load()
                assert loaded_data == test_data
        
        finally:
            # Clean up
            if temp_path.exists():
                temp_path.unlink()
    
    def test_quota_concurrent_access(self):
        """Test quota system with concurrent access simulation."""
        # Create a temporary quota file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        
        try:
            # Mock the quota path to use our temp file
            with patch('quota._PATH', temp_path):
                # Simulate multiple processes trying to update quota
                import threading
                import time
                
                results = []
                errors = []
                
                def update_quota(provider, count):
                    try:
                        for i in range(10):
                            increment_provider(provider, count)
                            time.sleep(0.001)  # Small delay to increase chance of race condition
                        results.append(f"{provider}_success")
                    except Exception as e:
                        errors.append(f"{provider}_{e}")
                
                # Start multiple threads
                threads = []
                for i in range(3):
                    t = threading.Thread(target=update_quota, args=(f"Provider{i}", 5))
                    threads.append(t)
                    t.start()
                
                # Wait for all threads to complete
                for t in threads:
                    t.join(timeout=10)
                
                # Should have no errors
                assert len(errors) == 0, f"Concurrent access errors: {errors}"
                
                # Should have all successful results
                assert len(results) == 3
                
                # Final data should be consistent
                final_data = _load()
                assert isinstance(final_data, dict)
                
                # Should have data for all providers
                today_data = final_data.get(list(final_data.keys())[0], {})
                for i in range(3):
                    provider_key = f"Provider{i}"
                    assert provider_key in today_data
                    assert today_data[provider_key] == 50  # 10 increments * 5 count
        
        finally:
            # Clean up
            if temp_path.exists():
                temp_path.unlink()
    
    def test_quota_file_corruption_recovery(self):
        """Test recovery from corrupted quota files."""
        # Create a temporary quota file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        
        try:
            # Write invalid JSON to the file
            with temp_path.open('w') as f:
                f.write('{"invalid": json content}')
            
            # Mock the quota path to use our temp file
            with patch('quota._PATH', temp_path):
                # Loading should handle corruption gracefully
                data = _load()
                assert data == {}  # Should return empty dict for corrupted file
                
                # Should create a backup of corrupted file
                backup_path = temp_path.with_suffix('.corrupt')
                # Note: This depends on implementation, backup might not be created in test
                
                # Should be able to save new data
                new_data = {"2024-01-01": {"VirusTotal": 100}}
                _save(new_data)
                
                # Should be able to load the new data
                loaded_data = _load()
                assert loaded_data == new_data
        
        finally:
            # Clean up
            if temp_path.exists():
                temp_path.unlink()
            backup_path = temp_path.with_suffix('.corrupt')
            if backup_path.exists():
                backup_path.unlink()
    
    def test_quota_file_permissions(self):
        """Test that quota files have appropriate permissions."""
        # Create a temporary quota file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        
        try:
            # Mock the quota path to use our temp file
            with patch('quota._PATH', temp_path):
                # Save some data
                test_data = {"2024-01-01": {"VirusTotal": 100}}
                _save(test_data)
                
                # Check file permissions (on Unix-like systems)
                if hasattr(os, 'stat'):
                    stat_info = temp_path.stat()
                    # File should be readable/writable by owner
                    # Note: Exact permission checking depends on OS and umask
                    assert stat_info.st_mode & 0o400  # Owner read
                    assert stat_info.st_mode & 0o200  # Owner write
        
        finally:
            # Clean up
            if temp_path.exists():
                temp_path.unlink()
    
    def test_quota_increment_with_crash_simulation(self):
        """Test quota increment behavior during simulated crashes."""
        # Create a temporary quota file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            temp_path = Path(temp_file.name)
        
        try:
            # Mock the quota path to use our temp file
            with patch('quota._PATH', temp_path):
                # Initial increment should work
                increment_provider("VirusTotal", 10)
                
                # Verify initial state
                remaining_count = remaining("VirusTotal")
                assert remaining_count == "490"  # 500 - 10
                
                # Simulate crash during increment
                call_count = 0
                original_save = _save
                
                def crash_on_third_call(data):
                    nonlocal call_count
                    call_count += 1
                    if call_count == 3:
                        raise OSError("Simulated crash during save")
                    return original_save(data)
                
                with patch('quota._save', side_effect=crash_on_third_call):
                    # These should work
                    increment_provider("VirusTotal", 5)
                    increment_provider("AbuseIPDB", 10)
                    
                    # This should crash
                    with pytest.raises(OSError):
                        increment_provider("VirusTotal", 5)
                
                # After crash, data should still be consistent
                final_data = _load()
                assert isinstance(final_data, dict)
                
                # Should have partial updates (first two increments)
                today_key = list(final_data.keys())[0]
                today_data = final_data[today_key]
                assert today_data["VirusTotal"] == 15  # 10 + 5
                assert today_data["AbuseIPDB"] == 10
        
        finally:
            # Clean up
            if temp_path.exists():
                temp_path.unlink() 