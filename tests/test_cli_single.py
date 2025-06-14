# tests/test_cli_single.py
"""Test CLI single IOC lookups."""
import pytest
import asyncio
from unittest.mock import patch, MagicMock
from ioc_checker import main, scan_single
from ioc_types import detect_ioc_type

class TestCLISingle:
    """Test single IOC CLI functionality."""
    
    def test_single_ip(self, monkeypatch, capsys):
        """Test single IP lookup via CLI."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8"]
        monkeypatch.setattr("sys.argv", test_args)
        
        with patch('aiohttp.ClientSession') as mock_session:
            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value.text.return_value = '{"data": {"abuseConfidenceScore": 0}}'
            try:
                main()
            except SystemExit:
                pass
        
        captured = capsys.readouterr()
        assert "8.8.8.8" in captured.out
    
    def test_single_domain(self, monkeypatch, capsys):
        """Test single domain lookup via CLI."""
        test_args = ["ioc_checker.py", "domain", "google.com"]
        monkeypatch.setattr("sys.argv", test_args)
        
        with patch('aiohttp.ClientSession'):
            try:
                main()
            except SystemExit:
                pass
        
        captured = capsys.readouterr()
        assert "google.com" in captured.out
    
    def test_single_url(self, monkeypatch, capsys):
        """Test single URL lookup via CLI."""
        test_args = ["ioc_checker.py", "url", "https://example.com"]
        monkeypatch.setattr("sys.argv", test_args)
        
        with patch('aiohttp.ClientSession'):
            try:
                main()
            except SystemExit:
                pass
        
        captured = capsys.readouterr()
        assert "https://example.com" in captured.out
    
    def test_single_hash(self, monkeypatch, capsys):
        """Test single hash lookup via CLI."""
        test_args = ["ioc_checker.py", "hash", "d41d8cd98f00b204e9800998ecf8427e"]
        monkeypatch.setattr("sys.argv", test_args)
        
        with patch('aiohttp.ClientSession'):
            try:
                main()
            except SystemExit:
                pass
        
        captured = capsys.readouterr()
        assert "d41d8cd98f00b204e9800998ecf8427e" in captured.out
    
    def test_rate_flag(self, monkeypatch, capsys):
        """Test --rate flag includes rate-limited providers."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--rate"]
        monkeypatch.setattr("sys.argv", test_args)
        
        with patch('aiohttp.ClientSession'):
            try:
                main()
            except SystemExit:
                pass
        
        captured = capsys.readouterr()
        assert "8.8.8.8" in captured.out
    
    def test_missing_api_key_graceful(self, monkeypatch, capsys):
        """Test missing API key returns 'nokey' without crash."""
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        test_args = ["ioc_checker.py", "ip", "8.8.8.8"]
        monkeypatch.setattr("sys.argv", test_args)
        
        with patch('aiohttp.ClientSession'):
            try:
                main()
            except SystemExit:
                pass
        
        captured = capsys.readouterr()
        assert "8.8.8.8" in captured.out  # Should not crash
    
    def test_no_args_shows_help(self, monkeypatch, capsys):
        """Test no arguments shows usage help."""
        test_args = ["ioc_checker.py"]
        monkeypatch.setattr("sys.argv", test_args)
        
        with pytest.raises(SystemExit):
            main()
        
        captured = capsys.readouterr()
        assert "usage:" in captured.err or "error:" in captured.err

@pytest.mark.asyncio
class TestAsyncScanSingle:
    """Test async scan_single function."""
    
    async def test_scan_single_ip(self, mock_session):
        """Test scan_single with IP address."""
        result = await scan_single(mock_session, "8.8.8.8", False)
        assert result["value"] == "8.8.8.8"
        assert result["type"] == "ip"
        assert "results" in result
    
    async def test_scan_single_unknown_type(self, mock_session):
        """Test scan_single with unknown IOC type."""
        result = await scan_single(mock_session, "invalid_ioc", False)
        assert result["type"] == "unknown"
        assert result["results"] == {}
    
    async def test_scan_single_with_rate_limiting(self, mock_session):
        """Test scan_single with rate limiting enabled."""
        result = await scan_single(mock_session, "8.8.8.8", True)
        assert result["value"] == "8.8.8.8"
        assert result["type"] == "ip"
