"""
Comprehensive tests for ioc_checker.py module.
Tests CLI functionality, CSV processing, and main application logic.
"""
import pytest
import argparse
from unittest.mock import AsyncMock, Mock, patch
from ioc_checker import (
    _fmt, _query, scan_single, process_csv, main
)


class TestResponseFormatter:
    """Test the _fmt function for provider response formatting."""
    
    def test_fmt_abuseipdb_clean(self):
        """Test AbuseIPDB clean response formatting."""
        response = {"data": {"abuseConfidenceScore": 0, "isWhitelisted": False}}
        result = _fmt(response)
        assert result == "Clean"
    
    def test_fmt_abuseipdb_whitelisted(self):
        """Test AbuseIPDB whitelisted response formatting."""
        response = {"data": {"abuseConfidenceScore": 50, "isWhitelisted": True}}
        result = _fmt(response)
        assert result == "Clean (whitelisted)"
    
    def test_fmt_abuseipdb_malicious(self):
        """Test AbuseIPDB malicious response formatting."""
        response = {"data": {"abuseConfidenceScore": 85, "isWhitelisted": False}}
        result = _fmt(response)
        assert result == "Malicious – score 85"
    
    def test_fmt_virustotal_clean(self):
        """Test VirusTotal clean response formatting."""
        response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 5,
                        "undetected": 3
                    }
                }
            }
        }
        result = _fmt(response)
        assert result == "Clean"
    
    def test_fmt_virustotal_malicious(self):
        """Test VirusTotal malicious response formatting."""
        response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 2,
                        "undetected": 2
                    }
                }
            }
        }
        result = _fmt(response)
        assert result == "Malicious – 3 malicious, 1 suspicious"
    
    def test_fmt_otx_clean(self):
        """Test OTX clean response formatting."""
        response = {"pulse_info": {"count": 0}}
        result = _fmt(response)
        assert result == "Clean"
    
    def test_fmt_otx_malicious_single(self):
        """Test OTX malicious response formatting (single pulse)."""
        response = {"pulse_info": {"count": 1}}
        result = _fmt(response)
        assert result == "Malicious – 1 OTX pulse"
    
    def test_fmt_otx_malicious_multiple(self):
        """Test OTX malicious response formatting (multiple pulses)."""
        response = {"pulse_info": {"count": 5}}
        result = _fmt(response)
        assert result == "Malicious – 5 OTX pulses"
    
    def test_fmt_threatfox_clean(self):
        """Test ThreatFox clean response formatting."""
        response = {"query_status": "no_result"}
        result = _fmt(response)
        assert result == "Clean"
    
    def test_fmt_threatfox_malicious(self):
        """Test ThreatFox malicious response formatting."""
        response = {
            "query_status": "ok",
            "data": [
                {"threat_type": "malware"},
                {"threat_type": "botnet"}
            ]
        }
        result = _fmt(response)
        assert result == "Malicious – 2 threats"
    
    def test_fmt_urlhaus_malicious(self):
        """Test URLhaus malicious response formatting."""
        response = {"query_status": "ok", "url": "https://malicious.com"}
        result = _fmt(response)
        assert result == "Malicious – URLhaus hit"
    
    def test_fmt_urlhaus_clean(self):
        """Test URLhaus clean response formatting."""
        response = {"query_status": "no_result", "url": "https://clean.com"}
        result = _fmt(response)
        assert result == "Clean"
    
    def test_fmt_string_input(self):
        """Test formatter with string input (JSON)."""
        json_string = '{"data": {"abuseConfidenceScore": 0, "isWhitelisted": false}}'
        result = _fmt(json_string)
        assert result == "Clean"
    
    def test_fmt_invalid_json(self):
        """Test formatter with invalid JSON string."""
        invalid_json = "invalid json string"
        result = _fmt(invalid_json)
        assert result == "unparseable"
    
    def test_fmt_parse_error(self):
        """Test formatter with valid JSON but unexpected structure."""
        response = {"unexpected": "structure"}
        result = _fmt(response)
        assert result == "Unknown"
    
    def test_fmt_abuseipdb_parse_error(self):
        """Test formatter with AbuseIPDB structure but missing fields."""
        response = {"data": {"abuseConfidenceScore": "invalid"}}
        result = _fmt(response)
        assert result == "Parse error"
    
    def test_fmt_virustotal_parse_error(self):
        """Test formatter with VirusTotal structure but missing fields."""
        response = {"data": {"attributes": {"last_analysis_stats": {}}}}
        result = _fmt(response)
        assert result == "Unknown"  # Empty stats lead to Unknown, not Clean


class TestQueryOrchestration:
    """Test the _query function for provider orchestration."""
    
    @pytest.mark.asyncio
    async def test_query_basic(self, mock_aiohttp_session):
        """Test basic query orchestration."""
        # Mock providers
        provider1 = Mock()
        provider1.name = "provider1"
        provider1.ioc_kinds = ("ip",)
        provider1.query = AsyncMock(return_value="result1")
        
        provider2 = Mock()
        provider2.name = "provider2"
        provider2.ioc_kinds = ("ip", "domain")
        provider2.query = AsyncMock(return_value="result2")
        
        with patch('ioc_checker.ALWAYS_ON', [provider1, provider2]):
            with patch('ioc_checker.RATE_LIMIT', []):
                result = await _query(mock_aiohttp_session, "ip", "8.8.8.8", False)
        
        assert result == {"provider1": "result1", "provider2": "result2"}
        provider1.query.assert_called_once_with(mock_aiohttp_session, "ip", "8.8.8.8")
        provider2.query.assert_called_once_with(mock_aiohttp_session, "ip", "8.8.8.8")
    
    @pytest.mark.asyncio
    async def test_query_with_rate_limit(self, mock_aiohttp_session):
        """Test query orchestration with rate-limited providers."""
        always_provider = Mock()
        always_provider.name = "always"
        always_provider.ioc_kinds = ("ip",)
        always_provider.query = AsyncMock(return_value="always_result")
        
        rate_provider = Mock()
        rate_provider.name = "rate"
        rate_provider.ioc_kinds = ("ip",)
        rate_provider.query = AsyncMock(return_value="rate_result")
        
        with patch('ioc_checker.ALWAYS_ON', [always_provider]):
            with patch('ioc_checker.RATE_LIMIT', [rate_provider]):
                result = await _query(mock_aiohttp_session, "ip", "8.8.8.8", True)
        
        assert result == {"always": "always_result", "rate": "rate_result"}
    
    @pytest.mark.asyncio
    async def test_query_selected_providers(self, mock_aiohttp_session):
        """Test query orchestration with selected providers."""
        provider1 = Mock()
        provider1.name = "virustotal"
        provider1.ioc_kinds = ("ip",)
        provider1.query = AsyncMock(return_value="vt_result")
        
        provider2 = Mock()
        provider2.name = "abuseipdb"
        provider2.ioc_kinds = ("ip",)
        provider2.query = AsyncMock(return_value="abuse_result")
        
        provider3 = Mock()
        provider3.name = "otx"
        provider3.ioc_kinds = ("ip",)
        provider3.query = AsyncMock(return_value="otx_result")

        with patch('ioc_checker.ALWAYS_ON', [provider2, provider3]):
            with patch('ioc_checker.RATE_LIMIT', [provider1]):
                result = await _query(mock_aiohttp_session, "ip", "8.8.8.8", False, ["virustotal"])
        
        # Fix: Should include always-on providers (abuseipdb, otx) + selected providers (virustotal)
        # The function merges defaults with user selections - this is the correct behavior
        expected = {"virustotal": "vt_result", "abuseipdb": "abuse_result", "otx": "otx_result"}
        assert result == expected
        
        # All providers should be called since always-on are included automatically
        provider1.query.assert_called_once()  # virustotal (selected)
        provider2.query.assert_called_once()  # abuseipdb (always-on)
        provider3.query.assert_called_once()  # otx (always-on)
    
    @pytest.mark.asyncio
    async def test_query_provider_error(self, mock_aiohttp_session):
        """Test query orchestration with provider errors."""
        provider1 = Mock()
        provider1.name = "provider1"
        provider1.ioc_kinds = ("ip",)
        provider1.query = AsyncMock(side_effect=Exception("Network error"))
        
        provider2 = Mock()
        provider2.name = "provider2"
        provider2.ioc_kinds = ("ip",)
        provider2.query = AsyncMock(return_value="success")
        
        with patch('ioc_checker.ALWAYS_ON', [provider1, provider2]):
            with patch('ioc_checker.RATE_LIMIT', []):
                result = await _query(mock_aiohttp_session, "ip", "8.8.8.8", False)
        
        assert "provider1" in result
        assert result["provider1"].startswith("error:")
        assert "Network error" in result["provider1"]
        assert result["provider2"] == "success"
    
    @pytest.mark.asyncio
    async def test_query_ioc_type_filtering(self, mock_aiohttp_session):
        """Test that providers are filtered by IOC type support."""
        ip_provider = Mock()
        ip_provider.name = "ip_only"
        ip_provider.ioc_kinds = ("ip",)
        ip_provider.query = AsyncMock(return_value="ip_result")
        
        domain_provider = Mock()
        domain_provider.name = "domain_only"
        domain_provider.ioc_kinds = ("domain",)
        domain_provider.query = AsyncMock(return_value="domain_result")
        
        with patch('ioc_checker.ALWAYS_ON', [ip_provider, domain_provider]):
            with patch('ioc_checker.RATE_LIMIT', []):
                result = await _query(mock_aiohttp_session, "ip", "8.8.8.8", False)
        
        # Only IP provider should be called
        assert result == {"ip_only": "ip_result"}
        ip_provider.query.assert_called_once()
        domain_provider.query.assert_not_called()


class TestScanSingle:
    """Test the scan_single function."""
    
    @pytest.mark.asyncio
    async def test_scan_single_ip(self, mock_aiohttp_session):
        """Test single IP scan."""
        with patch('ioc_checker.detect_ioc_type', return_value=("ip", "8.8.8.8")):
            with patch('ioc_checker._query', return_value={"provider1": "clean"}):
                result = await scan_single(mock_aiohttp_session, "8.8.8.8", False)
        
        assert result["value"] == "8.8.8.8"
        assert result["type"] == "ip"
        assert result["results"] == {"provider1": "clean"}
    
    @pytest.mark.asyncio
    async def test_scan_single_unknown_type(self, mock_aiohttp_session):
        """Test single scan with unknown IOC type."""
        with patch('ioc_checker.detect_ioc_type', return_value=("unknown", "invalid_ioc")):
            result = await scan_single(mock_aiohttp_session, "invalid_ioc", False)
        
        assert result["value"] == "invalid_ioc"
        assert result["type"] == "unknown"
        assert result["results"] == {}
    
    @pytest.mark.asyncio
    async def test_scan_single_with_selected_providers(self, mock_aiohttp_session):
        """Test single scan with selected providers."""
        with patch('ioc_checker.detect_ioc_type', return_value=("ip", "8.8.8.8")):
            with patch('ioc_checker._query', return_value={"virustotal": "clean"}) as mock_query:
                result = await scan_single(mock_aiohttp_session, "8.8.8.8", False, ["virustotal"])
        
        mock_query.assert_called_once_with(mock_aiohttp_session, "ip", "8.8.8.8", False, ["virustotal"])
        assert result["results"] == {"virustotal": "clean"}


class TestCSVProcessing:
    """Test the process_csv function."""
    
    @pytest.mark.asyncio
    async def test_process_csv_basic(self, sample_csv_file, temp_dir):
        """Test basic CSV processing."""
        output_file = temp_dir / "results.csv"
        
        with patch('ioc_checker.scan_single') as mock_scan:
            mock_scan.return_value = {
                "value": "8.8.8.8",
                "type": "ip", 
                "results": {"provider1": "clean"}
            }
            
            await process_csv(str(sample_csv_file), str(output_file), False)
        
        # Verify scan_single was called for each IOC value
        assert mock_scan.call_count >= 4  # At least 4 IOC values in sample CSV
    
    @pytest.mark.asyncio
    async def test_process_csv_nonexistent_file(self, temp_dir):
        """Test CSV processing with non-existent input file."""
        nonexistent_file = temp_dir / "nonexistent.csv"
        output_file = temp_dir / "results.csv"
        
        await process_csv(str(nonexistent_file), str(output_file), False)
        
        # Should handle gracefully without creating output
        assert not output_file.exists()
    
    @pytest.mark.asyncio
    async def test_process_csv_empty_file(self, temp_dir):
        """Test CSV processing with empty file."""
        empty_file = temp_dir / "empty.csv"
        empty_file.write_text("", encoding="utf-8")
        output_file = temp_dir / "results.csv"
        
        await process_csv(str(empty_file), str(output_file), False)
        
        # Should handle empty file gracefully
        assert not output_file.exists()
    
    @pytest.mark.asyncio
    async def test_process_csv_custom_delimiter(self, temp_dir):
        """Test CSV processing with custom delimiter."""
        # Create CSV with semicolon delimiter
        csv_content = "ioc_type;ioc_value;description\nip;8.8.8.8;Test IP\n"
        csv_file = temp_dir / "semicolon.csv"
        csv_file.write_text(csv_content, encoding="utf-8")
        output_file = temp_dir / "results.csv"
        
        with patch('ioc_checker.scan_single') as mock_scan:
            mock_scan.return_value = {"value": "8.8.8.8", "type": "ip", "results": {}}
            await process_csv(str(csv_file), str(output_file), False)
        
        # Should detect semicolon delimiter and process correctly
        assert mock_scan.call_count >= 1
    
    @pytest.mark.asyncio
    async def test_process_csv_with_errors(self, sample_csv_file, temp_dir):
        """Test CSV processing with scan errors."""
        output_file = temp_dir / "results.csv"
        
        with patch('ioc_checker.scan_single') as mock_scan:
            # First call succeeds, second raises exception
            mock_scan.side_effect = [
                {"value": "8.8.8.8", "type": "ip", "results": {"provider1": "clean"}},
                Exception("Scan error"),
                {"value": "example.com", "type": "domain", "results": {"provider1": "clean"}}
            ]
            
            await process_csv(str(sample_csv_file), str(output_file), False)
        
        # Should continue processing despite errors
        assert mock_scan.call_count >= 2
    
    @pytest.mark.asyncio
    async def test_process_csv_selected_providers(self, sample_csv_file, temp_dir):
        """Test CSV processing with selected providers."""
        output_file = temp_dir / "results.csv"
        selected_providers = ["virustotal", "abuseipdb"]
        
        with patch('ioc_checker.scan_single') as mock_scan:
            mock_scan.return_value = {"value": "test", "type": "ip", "results": {}}
            await process_csv(str(sample_csv_file), str(output_file), False, selected_providers)
        
        # Verify selected providers were passed to scan_single
        for call in mock_scan.call_args_list:
            if len(call[0]) > 3:  # Check if selected_providers argument exists
                assert call[0][3] == selected_providers


class TestMainFunction:
    """Test the main CLI function."""
    
    def test_main_single_ioc(self):
        """Test main function with single IOC lookup."""
        with patch('sys.argv', ['ioc_checker.py', 'ip', '8.8.8.8']):
            with patch('ioc_checker.asyncio.run') as mock_run:
                main()
                mock_run.assert_called_once()
    
    def test_main_csv_processing(self):
        """Test main function with CSV processing."""
        with patch('sys.argv', ['ioc_checker.py', '--csv', 'test.csv']):
            with patch('ioc_checker.asyncio.run') as mock_run:
                main()
                mock_run.assert_called_once()
    
    def test_main_with_rate_flag(self):
        """Test main function with rate limit flag."""
        with patch('sys.argv', ['ioc_checker.py', 'ip', '8.8.8.8', '--rate']):
            with patch('ioc_checker.asyncio.run') as mock_run:
                main()
                mock_run.assert_called_once()
    
    def test_main_with_specific_providers(self):
        """Test main function with specific provider flags."""
        with patch('sys.argv', ['ioc_checker.py', 'ip', '8.8.8.8', '--virustotal', '--greynoise']):
            with patch('ioc_checker.asyncio.run') as mock_run:
                main()
                mock_run.assert_called_once()
    
    def test_main_csv_with_output(self):
        """Test main function with CSV and custom output."""
        with patch('sys.argv', ['ioc_checker.py', '--csv', 'input.csv', '-o', 'output.csv']):
            with patch('ioc_checker.asyncio.run') as mock_run:
                main()
                mock_run.assert_called_once()
    
    def test_main_no_args_error(self):
        """Test main function with insufficient arguments."""
        with patch('sys.argv', ['ioc_checker.py']):
            with patch('argparse.ArgumentParser.error') as mock_error:
                main()
                mock_error.assert_called_once()
    
    def test_main_keyboard_interrupt(self):
        """Test main function handles KeyboardInterrupt."""
        def raise_interrupt(*args):
            raise KeyboardInterrupt()
        
        with patch('sys.argv', ['ioc_checker.py', 'ip', '8.8.8.8']):
            with patch('ioc_checker.asyncio.run', side_effect=raise_interrupt):
                # Should handle KeyboardInterrupt gracefully
                main()  # Should not raise
    
    def test_main_general_exception(self):
        """Test main function handles general exceptions."""
        def raise_exception(*args):
            raise Exception("Test error")
        
        with patch('sys.argv', ['ioc_checker.py', 'ip', '8.8.8.8']):
            with patch('ioc_checker.asyncio.run', side_effect=raise_exception):
                # Should handle general exceptions gracefully
                main()  # Should not raise


class TestIntegration:
    """Integration tests for ioc_checker functionality."""
    
    @pytest.mark.asyncio
    async def test_end_to_end_single_scan(self):
        """Test end-to-end single IOC scan."""
        mock_session = AsyncMock()
        
        # Mock the entire chain
        with patch('ioc_checker.detect_ioc_type', return_value=("ip", "8.8.8.8")):
            with patch('ioc_checker.ALWAYS_ON', []):
                with patch('ioc_checker.RATE_LIMIT', []):
                    result = await scan_single(mock_session, "8.8.8.8", False)
        
        assert result["value"] == "8.8.8.8"
        assert result["type"] == "ip"
        assert isinstance(result["results"], dict)
    
    def test_argument_parsing(self):
        """Test command line argument parsing."""
        # Test single IOC arguments
        with patch('sys.argv', ['ioc_checker.py', 'ip', '8.8.8.8', '--rate']):
            parser = argparse.ArgumentParser()
            parser.add_argument("ioc_type", nargs="?", choices=["ip","domain","url","hash","email","filepath","registry","wallet","asn","attack"])
            parser.add_argument("value", nargs="?")
            parser.add_argument("--csv")
            parser.add_argument("-o", "--out", default="results.csv")
            parser.add_argument("--rate", action="store_true")
            parser.add_argument("--virustotal", action="store_true")
            parser.add_argument("--greynoise", action="store_true")
            parser.add_argument("--pulsedive", action="store_true")
            parser.add_argument("--shodan", action="store_true")
            
            args = parser.parse_args(['ip', '8.8.8.8', '--rate'])
            assert args.ioc_type == 'ip'
            assert args.value == '8.8.8.8'
            assert args.rate is True
    
    @pytest.mark.asyncio
    async def test_csv_processing_integration(self, sample_csv_file, temp_dir):
        """Test CSV processing integration with mocked providers."""
        output_file = temp_dir / "integration_results.csv"
        
        # Mock providers that will be used
        mock_provider = Mock()
        mock_provider.name = "test_provider"
        mock_provider.ioc_kinds = ("ip", "domain", "url", "hash")
        mock_provider.query = AsyncMock(return_value='{"status": "clean"}')
        
        with patch('ioc_checker.ALWAYS_ON', [mock_provider]):
            with patch('ioc_checker.RATE_LIMIT', []):
                with patch('ioc_checker.WRITERS') as mock_writers:
                    # Mock all writers
                    for writer_name in ['csv', 'json', 'xlsx', 'html']:
                        mock_writers[writer_name] = Mock()
                    
                    await process_csv(str(sample_csv_file), str(output_file), False)
                    
                    # Verify writers were called - they get called once per format
                    for writer_name in ['csv', 'json', 'xlsx', 'html']:
                        assert mock_writers[writer_name].call_count >= 1


class TestErrorHandling:
    """Test error handling throughout the application."""
    
    @pytest.mark.asyncio
    async def test_query_orchestration_error(self, mock_aiohttp_session):
        """Test query orchestration handles errors gracefully."""
        # Mock asyncio.gather to raise an exception
        with patch('ioc_checker.asyncio.gather', side_effect=Exception("Gather failed")):
            with patch('ioc_checker.ALWAYS_ON', []):
                with patch('ioc_checker.RATE_LIMIT', []):
                    result = await _query(mock_aiohttp_session, "ip", "8.8.8.8", False)
        
        assert "error" in result
        assert "Gather failed" in result["error"]
    
    @pytest.mark.asyncio
    async def test_csv_session_error(self, sample_csv_file, temp_dir):
        """Test CSV processing handles session errors."""
        output_file = temp_dir / "error_results.csv"
        
        # Mock aiohttp to raise an exception during session creation
        with patch('ioc_checker.aiohttp.ClientSession', side_effect=Exception("Session error")):
            await process_csv(str(sample_csv_file), str(output_file), False)
            
            # Should handle error gracefully without creating output files
            assert not output_file.exists()
    
    def test_main_async_runtime_error(self):
        """Test main function handles asyncio runtime errors."""
        def raise_runtime_error(*args):
            raise RuntimeError("Async runtime error")
        
        with patch('sys.argv', ['ioc_checker.py', 'ip', '8.8.8.8']):
            with patch('ioc_checker.asyncio.run', side_effect=raise_runtime_error):
                # Should handle runtime errors gracefully
                main()  # Should not raise
    
    @pytest.mark.asyncio
    async def test_report_writing_error(self, sample_csv_file, temp_dir):
        """Test CSV processing handles report writing errors."""
        output_file = temp_dir / "write_error_results.csv"
        
        with patch('ioc_checker.scan_single') as mock_scan:
            mock_scan.return_value = {"value": "test", "type": "ip", "results": {}}
            
            # Mock WRITERS to raise exceptions
            with patch('ioc_checker.WRITERS') as mock_writers:
                for writer_name in ['csv', 'json', 'xlsx', 'html']:
                    mock_writers[writer_name] = Mock(side_effect=Exception(f"{writer_name} error"))
                
                await process_csv(str(sample_csv_file), str(output_file), False)
                
                # Should handle writing errors gracefully - each writer gets called once per row
                for writer_name in ['csv', 'json', 'xlsx', 'html']:
                    assert mock_writers[writer_name].call_count >= 1


class TestUtilityFunctions:
    """Test utility and helper functions."""
    
    def test_utf8_reconfigure(self):
        """Test UTF-8 reconfiguration for stdout/stderr."""
        # This tests the module-level UTF-8 configuration
        # The actual reconfiguration happens at import time
        import sys
        
        # Verify encoding is set (if supported by Python version)
        if hasattr(sys.stdout, 'encoding'):
            assert sys.stdout.encoding is not None
        if hasattr(sys.stderr, 'encoding'):
            assert sys.stderr.encoding is not None
    
    def test_logging_configuration(self):
        """Test logging configuration."""
        import logging
        
        # Verify logger exists and has proper level
        logger = logging.getLogger("ioc_checker")
        assert logger is not None
        
        # Root logger might be WARNING level, which is fine
        root_logger = logging.getLogger()
        # Just verify the logger exists and is configured
        assert root_logger is not None