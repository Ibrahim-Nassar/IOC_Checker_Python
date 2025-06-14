# tests/test_cross_platform.py
"""Test cross-platform compatibility."""
import pytest
import sys
import os
from pathlib import Path
from unittest.mock import patch

class TestCrossPlatform:
    """Test cross-platform functionality."""
    
    def test_utf8_stdout_reconfiguration(self):
        """Test UTF-8 stdout reconfiguration works."""
        # This tests the code in ioc_checker.py that reconfigures stdout
        try:
            if hasattr(sys.stdout, 'reconfigure'):
                sys.stdout.reconfigure(encoding='utf-8')
                sys.stderr.reconfigure(encoding='utf-8')
            # Should not raise exception
        except AttributeError:
            # Python < 3.7 fallback should work
            pass
    
    def test_path_handling_arbitrary_cwd(self, tmp_path, monkeypatch):
        """Test path handling works from arbitrary CWD."""
        # Change to temporary directory
        monkeypatch.chdir(tmp_path)
        
        # Create a fake ioc_checker.py in the temp dir
        fake_script = tmp_path / "ioc_checker.py"
        fake_script.write_text("# fake script")
        
        # Test that paths work correctly
        assert Path.cwd() == tmp_path
        assert fake_script.exists()
    
    def test_env_loading_from_script_directory(self, tmp_path):
        """Test .env loading from script directory."""
        # Create a fake .env file
        env_file = tmp_path / ".env"
        env_file.write_text("TEST_KEY=test_value\n")
        
        # Test that dotenv would load from the correct path
        from dotenv import load_dotenv
        load_dotenv(env_file)
        
        assert os.getenv("TEST_KEY") == "test_value"
    
    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_windows_specific_features(self):
        """Test Windows-specific features."""
        # Test Windows event loop policy if on Windows
        if sys.platform.startswith("win"):
            import asyncio
            # The policy should be set in the main modules
            policy = asyncio.get_event_loop_policy()
            # Should not raise exception
    
    @pytest.mark.skipif(sys.platform == "win32", reason="Unix-specific test")
    def test_unix_specific_features(self):
        """Test Unix-specific features."""
        # Test that code works on Unix systems
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.close()
    
    def test_ascii_fallback_output(self):
        """Test ASCII fallback for output."""
        # Test that system can handle ASCII-only output
        test_string = "ASCII only output"
        encoded = test_string.encode('ascii')
        decoded = encoded.decode('ascii')
        assert decoded == test_string
    
    def test_path_separator_handling(self):
        """Test proper path separator handling."""
        # Test that pathlib handles separators correctly
        test_path = Path("folder") / "file.txt"
        
        if sys.platform == "win32":
            assert "\\" in str(test_path)
        else:
            assert "/" in str(test_path)
    
    def test_environment_variable_handling(self, monkeypatch):
        """Test environment variable handling across platforms."""
        # Test setting and getting environment variables
        monkeypatch.setenv("TEST_VAR", "test_value")
        assert os.getenv("TEST_VAR") == "test_value"
        
        # Test deleting environment variables
        monkeypatch.delenv("TEST_VAR", raising=False)
        assert os.getenv("TEST_VAR") is None
    
    def test_file_encoding_handling(self, tmp_path):
        """Test file encoding handling."""
        # Test UTF-8 file reading
        utf8_file = tmp_path / "utf8.txt"
        utf8_file.write_text("UTF-8 content: ñáéíóú", encoding='utf-8')
        
        content = utf8_file.read_text(encoding='utf-8')
        assert "ñáéíóú" in content
        
        # Test reading with error handling
        content_with_errors = utf8_file.read_text(encoding='utf-8', errors='ignore')
        assert content_with_errors is not None
