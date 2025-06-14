"""
Test error handling paths and edge cases to boost coverage.
Covers provider errors, network timeouts, malformed data, and system failures.
"""
import pytest
import asyncio
import aiohttp
import json
from unittest.mock import patch, Mock, AsyncMock
from pathlib import Path
import tempfile
import os

from ioc_checker import _fmt, _query, scan_single, process_csv, main
from providers import AbuseIPDB, VirusTotal, OTX, ThreatFox
import ioc_types


class TestErrorFormatting:
    """Test _fmt function with various error conditions."""
    
    def test_fmt_json_decode_error(self):
        """Test _fmt with invalid JSON."""
        result = _fmt("invalid{json")
        assert result == "unparseable"
    
    def test_fmt_none_input(self):
        """Test _fmt with None input."""
        result = _fmt(None)
        assert result == "unparseable"
    
    def test_fmt_malformed_abuseipdb(self):
        """Test _fmt with malformed AbuseIPDB response."""
        malformed = {"data": {"missing_score": True}}
        result = _fmt(malformed)
        assert result == "Parse error"
    
    def test_fmt_malformed_virustotal(self):
        """Test _fmt with malformed VirusTotal response.""" 
        malformed = {"data": {"attributes": {"missing_stats": True}}}
        result = _fmt(malformed)
        assert result == "Parse error"
    
    def test_fmt_malformed_otx(self):
        """Test _fmt with malformed OTX response."""
        malformed = {"pulse_info": {"missing_count": True}}
        result = _fmt(malformed)
        assert result == "Parse error"
    
    def test_fmt_type_error_handling(self):
        """Test _fmt with TypeError scenarios."""
        with patch('json.loads', side_effect=TypeError("Type error")):
            result = _fmt("some_string")
            assert result == "unparseable"


@pytest.mark.asyncio
class TestProviderErrors:
    """Test provider error scenarios and timeouts."""
    
    async def test_query_orchestration_failure(self):
        """Test _query when asyncio.gather fails."""
        session = Mock()
        
        with patch('asyncio.gather', side_effect=RuntimeError("Gather failed")):
            result = await _query(session, "ip", "8.8.8.8", False)
            assert "error" in result
            assert "Gather failed" in result["error"]
    
    async def test_provider_timeout(self):
        """Test provider timeout handling."""
        session = Mock()
        provider = Mock()
        provider.name = "test_provider"
        provider.ioc_kinds = ("ip",)
        provider.query = AsyncMock(side_effect=asyncio.TimeoutError("Timeout"))
        
        with patch('ioc_checker.ALWAYS_ON', [provider]):
            result = await _query(session, "ip", "8.8.8.8", False)
            assert "test_provider" in result
            assert "error: Timeout" in result["test_provider"]
    
    async def test_provider_connection_error(self):
        """Test provider connection error handling."""
        session = Mock()
        provider = Mock()
        provider.name = "test_provider"
        provider.ioc_kinds = ("ip",)
        provider.query = AsyncMock(side_effect=aiohttp.ClientConnectorError(
            Mock(), OSError("Connection failed")))
        
        with patch('ioc_checker.ALWAYS_ON', [provider]):
            result = await _query(session, "ip", "8.8.8.8", False)
            assert "test_provider" in result
            assert "error:" in result["test_provider"]
    
    async def test_scan_single_unknown_ioc(self):
        """Test scan_single with unknown IOC type."""
        session = Mock()
        
        with patch('ioc_types.detect_ioc_type', return_value=("unknown", "test")):
            result = await scan_single(session, "unknown_ioc", False)
            assert result["type"] == "unknown"
            assert result["results"] == {}


@pytest.mark.asyncio 
class TestCSVProcessingErrors:
    """Test CSV processing error scenarios."""
    
    async def test_process_csv_file_not_found(self, caplog):
        """Test process_csv with non-existent file."""
        await process_csv("nonexistent.csv", "out.csv", False)
        assert "Input file not found" in caplog.text
    
    async def test_process_csv_empty_file(self, caplog):
        """Test process_csv with empty file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("")  # Empty file
            
        try:
            await process_csv(f.name, "out.csv", False)
            assert "Empty file" in caplog.text
        finally:
            os.unlink(f.name)
    
    async def test_process_csv_delimiter_detection_failure(self, caplog):
        """Test CSV with delimiter detection failure."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("malformed|data|without|proper|csv|structure")
            
        try:
            with patch('csv.Sniffer.sniff', side_effect=Exception("Sniff failed")):
                await process_csv(f.name, "out.csv", False)
                assert "Could not detect delimiter" in caplog.text
        finally:
            os.unlink(f.name)
    
    async def test_process_csv_read_failure(self, caplog):
        """Test CSV read failure."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("test,data\n1,2")
            
        try:
            with patch('pathlib.Path.open', side_effect=PermissionError("Access denied")):
                await process_csv(f.name, "out.csv", False)
                assert "Failed to read CSV file" in caplog.text
        finally:
            os.unlink(f.name)
    
    async def test_process_csv_connector_failure(self, caplog):
        """Test TCP connector creation failure."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("value\n8.8.8.8")
            
        try:
            with patch('aiohttp.TCPConnector', side_effect=RuntimeError("Connector failed")):
                await process_csv(f.name, "out.csv", False)
                assert "Failed to create connector" in caplog.text
        finally:
            os.unlink(f.name)
    
    async def test_process_csv_session_error(self, caplog):
        """Test session error during processing."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("value\n8.8.8.8")
            
        try:
            mock_session = AsyncMock()
            mock_session.__aenter__.side_effect = RuntimeError("Session failed")
            
            with patch('aiohttp.ClientSession', return_value=mock_session):
                await process_csv(f.name, "out.csv", False)
                assert "Session error during CSV processing" in caplog.text
        finally:
            os.unlink(f.name)
    
    async def test_process_csv_scan_failure(self, caplog):
        """Test individual IOC scan failure."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("value\n8.8.8.8")
            
        try:
            with patch('ioc_checker.scan_single', side_effect=Exception("Scan failed")):
                await process_csv(f.name, "out.csv", False)
                assert "Failed to scan IOC" in caplog.text
        finally:
            os.unlink(f.name)
    
    async def test_process_csv_report_write_failure(self, caplog):
        """Test report writing failure."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("value\n8.8.8.8")
            
        try:
            with patch('ioc_checker.WRITERS', {"csv": Mock(side_effect=Exception("Write failed"))}):
                await process_csv(f.name, "out.csv", False)
                assert "Failed to write reports" in caplog.text
        finally:
            os.unlink(f.name)


class TestMainFunctionErrors:
    """Test main function error scenarios."""
    
    def test_main_single_ioc_keyboard_interrupt(self, caplog):
        """Test main function with keyboard interrupt during single IOC scan."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run', side_effect=KeyboardInterrupt):
                main()
                assert "Interrupted by user" in caplog.text
    
    def test_main_single_ioc_async_error(self, caplog):
        """Test main function with async runtime error."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run', side_effect=RuntimeError("Async failed")):
                main()
                assert "Async runtime error" in caplog.text
    
    def test_main_csv_keyboard_interrupt(self, caplog):
        """Test main function with keyboard interrupt during CSV processing."""
        test_args = ["ioc_checker.py", "--csv", "test.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run', side_effect=KeyboardInterrupt):
                main()
                assert "CSV processing interrupted" in caplog.text
    
    def test_main_csv_processing_error(self, caplog):
        """Test main function with CSV processing error."""
        test_args = ["ioc_checker.py", "--csv", "test.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run', side_effect=Exception("CSV failed")):
                main()
                assert "CSV processing failed" in caplog.text
    
    def test_main_single_scan_exception(self, caplog):
        """Test exception in single scan execution."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8"]
        
        with patch('sys.argv', test_args):
            with patch('ioc_checker.scan_single', side_effect=Exception("Scan error")):
                with patch('aiohttp.ClientSession'):
                    main()
                    assert "Single IOC scan failed" in caplog.text


@pytest.mark.asyncio
class TestProviderSpecificErrors:
    """Test specific provider error conditions."""
    
    async def test_abuseipdb_no_key(self):
        """Test AbuseIPDB with no API key."""
        provider = AbuseIPDB()
        provider.key = None
        
        session = Mock()
        result = await provider.query(session, "ip", "8.8.8.8")
        assert result == "nokey"
    
    async def test_virustotal_request_exception(self):
        """Test VirusTotal with request exception."""
        provider = VirusTotal()
        provider.key = "test_key"
        
        session = Mock()
        session.get.side_effect = aiohttp.ClientError("Request failed")
        
        with patch('aiohttp.ClientSession.get', side_effect=aiohttp.ClientError("Request failed")):
            result = await provider.query(session, "ip", "8.8.8.8")
            assert "error:" in result


class TestSystemErrors:
    """Test system-level error conditions."""
    
    def test_utf8_reconfigure_failure(self):
        """Test UTF-8 reconfigure failure (Python < 3.7)."""
        with patch('sys.stdout.reconfigure', side_effect=AttributeError):
            with patch('sys.stderr.reconfigure', side_effect=AttributeError):
                # Should not raise exception - fallback handling
                import importlib
                import ioc_checker
                importlib.reload(ioc_checker)
    
    def test_logging_setup_with_errors(self):
        """Test logging setup resilience."""
        with patch('logging.basicConfig', side_effect=Exception("Logging failed")):
            # Should not crash the module
            import importlib
            import ioc_checker
            importlib.reload(ioc_checker)


if __name__ == "__main__":
    pytest.main([__file__])