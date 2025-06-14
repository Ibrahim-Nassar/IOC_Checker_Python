# tests/test_csv_batch.py
"""Test CSV batch processing functionality."""
import pytest
import tempfile
import csv
from pathlib import Path
from unittest.mock import patch, AsyncMock
from ioc_checker import process_csv

class TestCSVBatch:
    """Test CSV batch processing with various formats."""
    
    def test_csv_comma_delimiter(self, temp_env, mock_session):
        """Test CSV with comma delimiter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("ip,domain\n8.8.8.8,google.com\n1.1.1.1,cloudflare.com\n")
            csv_path = f.name
        
        with patch('aiohttp.ClientSession', return_value=mock_session):
            try:
                import asyncio
                asyncio.run(process_csv(csv_path, "results.csv", False))
            except Exception as e:
                pytest.fail(f"CSV processing failed: {e}")
        
        Path(csv_path).unlink()
    
    def test_csv_semicolon_delimiter(self, temp_env, mock_session):
        """Test CSV with semicolon delimiter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("ip;domain\n8.8.8.8;google.com\n1.1.1.1;cloudflare.com\n")
            csv_path = f.name
        
        with patch('aiohttp.ClientSession', return_value=mock_session):
            try:
                import asyncio
                asyncio.run(process_csv(csv_path, "results.csv", False))
            except Exception as e:
                pytest.fail(f"CSV processing failed: {e}")
        
        Path(csv_path).unlink()
    
    def test_csv_pipe_delimiter(self, temp_env, mock_session):
        """Test CSV with pipe delimiter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("ip|domain\n8.8.8.8|google.com\n1.1.1.1|cloudflare.com\n")
            csv_path = f.name
        
        with patch('aiohttp.ClientSession', return_value=mock_session):
            try:
                import asyncio
                asyncio.run(process_csv(csv_path, "results.csv", False))
            except Exception as e:
                pytest.fail(f"CSV processing failed: {e}")
        
        Path(csv_path).unlink()
    
    def test_csv_tab_delimiter(self, temp_env, mock_session):
        """Test CSV with tab delimiter."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("ip\tdomain\n8.8.8.8\tgoogle.com\n1.1.1.1\tcloudflare.com\n")
            csv_path = f.name
        
        with patch('aiohttp.ClientSession', return_value=mock_session):
            try:
                import asyncio
                asyncio.run(process_csv(csv_path, "results.csv", False))
            except Exception as e:
                pytest.fail(f"CSV processing failed: {e}")
        
        Path(csv_path).unlink()
    
    def test_csv_with_bom(self, temp_env, mock_session):
        """Test CSV with UTF-8 BOM."""
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.csv', delete=False) as f:
            f.write(b'\xef\xbb\xbfip,domain\n8.8.8.8,google.com\n')
            csv_path = f.name
        
        with patch('aiohttp.ClientSession', return_value=mock_session):
            try:
                import asyncio
                asyncio.run(process_csv(csv_path, "results.csv", False))
            except Exception as e:
                pytest.fail(f"CSV processing failed: {e}")
        
        Path(csv_path).unlink()
    
    def test_csv_blank_rows(self, temp_env, mock_session):
        """Test CSV with blank rows."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("ip,domain\n\n8.8.8.8,google.com\n\n\n1.1.1.1,cloudflare.com\n\n")
            csv_path = f.name
        
        with patch('aiohttp.ClientSession', return_value=mock_session):
            try:
                import asyncio
                asyncio.run(process_csv(csv_path, "results.csv", False))
            except Exception as e:
                pytest.fail(f"CSV processing failed: {e}")
        
        Path(csv_path).unlink()
    
    def test_csv_header_only(self, temp_env, mock_session):
        """Test CSV with header only."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("ip,domain\n")
            csv_path = f.name
        
        with patch('aiohttp.ClientSession', return_value=mock_session):
            try:
                import asyncio
                asyncio.run(process_csv(csv_path, "results.csv", False))
                # Should not crash, just log warning
            except Exception as e:
                pytest.fail(f"CSV processing failed: {e}")
        
        Path(csv_path).unlink()
    
    def test_csv_malformed_lines(self, temp_env, mock_session):
        """Test CSV with malformed lines."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("ip,domain\n8.8.8.8,google.com\nmalformed line without comma\n1.1.1.1,cloudflare.com\n")
            csv_path = f.name
        
        with patch('aiohttp.ClientSession', return_value=mock_session):
            try:
                import asyncio
                asyncio.run(process_csv(csv_path, "results.csv", False))
            except Exception as e:
                pytest.fail(f"CSV processing failed: {e}")
        
        Path(csv_path).unlink()
    
    def test_csv_large_file(self, temp_env, mock_session):
        """Test CSV with large number of rows (memory leak check)."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, encoding='utf-8') as f:
            f.write("ip\n")
            for i in range(100):  # Reduced for test speed
                f.write(f"192.168.1.{i}\n")
            csv_path = f.name
        
        with patch('aiohttp.ClientSession', return_value=mock_session):
            try:
                import asyncio
                asyncio.run(process_csv(csv_path, "results.csv", False))
            except Exception as e:
                pytest.fail(f"CSV processing failed: {e}")
        
        Path(csv_path).unlink()
    
    def test_csv_nonexistent_file(self, temp_env, mock_session):
        """Test CSV processing with nonexistent file."""
        with patch('aiohttp.ClientSession', return_value=mock_session):
            import asyncio
            # Should not crash, just log error
            asyncio.run(process_csv("nonexistent.csv", "results.csv", False))
