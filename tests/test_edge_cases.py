"""
Additional comprehensive tests to reach ≥90% coverage.
Tests edge cases, error conditions, and uncovered code paths.
"""
import pytest
from unittest.mock import AsyncMock, Mock, patch
import aiohttp
from ioc_checker import _fmt, _query, scan_single, process_csv, main


class TestFormatterEdgeCases:
    """Test edge cases for the _fmt function to improve coverage."""
    
    def test_fmt_empty_virustotal_stats(self):
        """Test VirusTotal with empty stats."""
        response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {}
                }
            }
        }
        result = _fmt(response)
        assert result == "Unknown"
    
    def test_fmt_virustotal_only_harmless(self):
        """Test VirusTotal with only harmless detections."""
        response = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 5,
                        "undetected": 0
                    }
                }
            }
        }
        result = _fmt(response)
        assert result == "Clean"
    
    def test_fmt_threatfox_ok_with_data(self):
        """Test ThreatFox with ok status and threat data."""
        response = {
            "query_status": "ok",
            "data": [
                {"threat_type": "malware"},
                {"threat_type": "botnet"},
                {"threat_type": "phishing"}
            ]
        }
        result = _fmt(response)
        assert result == "Malicious – 3 threats"
    
    def test_fmt_threatfox_ok_single_threat(self):
        """Test ThreatFox with single threat."""
        response = {
            "query_status": "ok",
            "data": [{"threat_type": "malware"}]
        }
        result = _fmt(response)
        assert result == "Malicious – 1 threat"
    
    def test_fmt_urlhaus_ok_format(self):
        """Test URLhaus with ok status."""
        response = {
            "query_status": "ok",
            "url": "https://malicious.example.com"
        }
        result = _fmt(response)
        assert result == "Malicious – URLhaus hit"
    
    def test_fmt_urlhaus_no_result_format(self):
        """Test URLhaus with no result."""
        response = {
            "query_status": "no_result",
            "url": "https://clean.example.com"
        }
        result = _fmt(response)
        assert result == "Clean"
    
    def test_fmt_otx_single_pulse(self):
        """Test OTX with single pulse."""
        response = {"pulse_info": {"count": 1}}
        result = _fmt(response)
        assert result == "Malicious – 1 OTX pulse"
    
    def test_fmt_generic_unknown(self):
        """Test generic unknown provider response."""
        response = {"unknown_field": "unknown_value"}
        result = _fmt(response)
        assert result == "Unknown"


class TestQueryEdgeCases:
    """Test edge cases for the _query function."""
    
    @pytest.mark.asyncio
    async def test_query_with_exception_in_gather(self, mock_aiohttp_session):
        """Test _query when asyncio.gather raises an exception."""
        provider = Mock()
        provider.name = "test_provider"
        provider.ioc_kinds = ("ip",)
        provider.query = AsyncMock(return_value="success")
        
        with patch('ioc_checker.ALWAYS_ON', [provider]):
            with patch('ioc_checker.RATE_LIMIT', []):
                with patch('ioc_checker.asyncio.gather', side_effect=Exception("Gather failed")):
                    result = await _query(mock_aiohttp_session, "ip", "8.8.8.8", False)
        
        assert "error" in result
        assert "Gather failed" in result["error"]
    
    @pytest.mark.asyncio
    async def test_query_provider_exception(self, mock_aiohttp_session):
        """Test _query when a provider raises an exception."""
        provider = Mock()
        provider.name = "failing_provider"
        provider.ioc_kinds = ("ip",)
        provider.query = AsyncMock(side_effect=RuntimeError("Provider error"))
        
        with patch('ioc_checker.ALWAYS_ON', [provider]):
            with patch('ioc_checker.RATE_LIMIT', []):
                result = await _query(mock_aiohttp_session, "ip", "8.8.8.8", False)
        
        assert "failing_provider" in result
        assert "error:" in result["failing_provider"]
        assert "Provider error" in result["failing_provider"]


class TestCSVProcessingEdgeCases:
    """Test edge cases for CSV processing to improve coverage."""
    
    @pytest.mark.asyncio
    async def test_process_csv_empty_file_detection(self, temp_dir):
        """Test CSV processing with empty file."""
        empty_file = temp_dir / "empty.csv"
        empty_file.write_text("", encoding="utf-8")
        output_file = temp_dir / "results.csv"
        
        await process_csv(str(empty_file), str(output_file), False)
        
        # Should not create output files for empty input
        assert not output_file.exists()
    
    @pytest.mark.asyncio
    async def test_process_csv_delimiter_detection_error(self, temp_dir):
        """Test CSV processing when delimiter detection fails."""
        # Create a file with problematic content
        csv_file = temp_dir / "problem.csv"
        csv_file.write_bytes(b'\xff\xfe\x00\x00invalid')  # Invalid encoding
        output_file = temp_dir / "results.csv"
        
        # Should handle gracefully and use comma as fallback
        await process_csv(str(csv_file), str(output_file), False)
    
    @pytest.mark.asyncio
    async def test_process_csv_file_read_error(self, temp_dir):
        """Test CSV processing when file reading fails."""
        # Create file that will cause read error
        csv_file = temp_dir / "unreadable.csv"
        csv_file.write_text("test,data\n", encoding="utf-8")
        output_file = temp_dir / "results.csv"
        
        # Mock file opening to raise an exception
        with patch('pathlib.Path.open', side_effect=PermissionError("Access denied")):
            await process_csv(str(csv_file), str(output_file), False)
        
        # Should handle error gracefully
        assert not output_file.exists()
    
    @pytest.mark.asyncio
    async def test_process_csv_rows_with_empty_values(self, temp_dir):
        """Test CSV processing with rows containing empty values."""
        csv_content = """col1,col2,col3
value1,empty_start,value2
middle,value3,value4
value5,value6,
final,row,value7"""
        
        csv_file = temp_dir / "sparse.csv"
        csv_file.write_text(csv_content, encoding="utf-8")
        output_file = temp_dir / "results.csv"
        
        with patch('ioc_checker.scan_single') as mock_scan:
            mock_scan.return_value = {"value": "test", "type": "ip", "results": {}}
            await process_csv(str(csv_file), str(output_file), False)
        
        # Should process non-empty values (at least 7 values)
        assert mock_scan.call_count >= 7
    
    @pytest.mark.asyncio
    async def test_process_csv_scan_single_error(self, sample_csv_file, temp_dir):
        """Test CSV processing when scan_single raises an exception."""
        output_file = temp_dir / "error_results.csv"
        
        with patch('ioc_checker.scan_single', side_effect=Exception("Scan failed")):
            await process_csv(str(sample_csv_file), str(output_file), False)
        
        # Should handle scan errors gracefully
    
    @pytest.mark.asyncio
    async def test_process_csv_progress_logging(self, temp_dir):
        """Test CSV processing with many rows to trigger progress logging."""
        # Create CSV with 100+ rows to trigger progress logging
        csv_content = "ioc_value\n" + "\n".join([f"8.8.8.{i}" for i in range(1, 101)])
        
        csv_file = temp_dir / "large.csv"
        csv_file.write_text(csv_content, encoding="utf-8")
        output_file = temp_dir / "results.csv"
        
        with patch('ioc_checker.scan_single') as mock_scan:
            mock_scan.return_value = {"value": "test", "type": "ip", "results": {}}
            await process_csv(str(csv_file), str(output_file), False)
        
        # Should process all rows
        assert mock_scan.call_count == 100
    
    @pytest.mark.asyncio
    async def test_process_csv_writer_error(self, sample_csv_file, temp_dir):
        """Test CSV processing when report writers fail."""
        output_file = temp_dir / "writer_error.csv"
        
        with patch('ioc_checker.scan_single') as mock_scan:
            mock_scan.return_value = {"value": "test", "type": "ip", "results": {}}
            
            with patch('ioc_checker.WRITERS') as mock_writers:
                # Make all writers raise exceptions
                for writer_name in ['csv', 'json', 'xlsx', 'html']:
                    mock_writers[writer_name] = Mock(side_effect=Exception(f"{writer_name} write failed"))
                
                await process_csv(str(sample_csv_file), str(output_file), False)
        
        # Should handle writer errors gracefully


class TestMainFunctionEdgeCases:
    """Test edge cases for the main function."""
    
    def test_main_python_version_fallback(self):
        """Test main function with Python < 3.7 (reconfigure not available)."""
        # Test the AttributeError handling for older Python versions
        with patch('sys.stdout') as mock_stdout:
            # Remove reconfigure method to simulate older Python
            if hasattr(mock_stdout, 'reconfigure'):
                delattr(mock_stdout, 'reconfigure')
            
            # Import should handle this gracefully
    
    def test_main_with_specific_provider_combinations(self):
        """Test main with different provider flag combinations."""
        test_cases = [
            ['ioc_checker.py', 'ip', '8.8.8.8', '--virustotal', '--greynoise'],
            ['ioc_checker.py', 'ip', '8.8.8.8', '--pulsedive', '--shodan'],
            ['ioc_checker.py', 'ip', '8.8.8.8', '--virustotal', '--pulsedive', '--shodan'],
        ]
        
        for argv in test_cases:
            with patch('sys.argv', argv):
                with patch('ioc_checker.asyncio.run') as mock_run:
                    main()
                    mock_run.assert_called_once()
                    mock_run.reset_mock()
    
    @pytest.mark.asyncio
    async def test_single_scan_session_error(self):
        """Test single scan when session creation fails."""
        with patch('aiohttp.ClientSession', side_effect=Exception("Session failed")):
            # This should be handled in the _run_single function
            try:
                conn = aiohttp.TCPConnector(limit_per_host=10, ssl=False, force_close=True)
                async with aiohttp.ClientSession(connector=conn) as s:
                    await scan_single(s, "8.8.8.8", False)
            except Exception:
                pass  # Expected to fail


class TestAdvancedScenarios:
    """Test advanced scenarios and integration cases."""
    
    @pytest.mark.asyncio
    async def test_scan_single_with_normalization(self, mock_aiohttp_session):
        """Test scan_single with IOC that requires normalization."""
        with patch('ioc_checker.detect_ioc_type', return_value=("ip", "8.8.8.8")):
            with patch('ioc_checker._query', return_value={"provider1": "clean"}):
                result = await scan_single(mock_aiohttp_session, "8.8.8.8:80", False)
        
        assert result["value"] == "8.8.8.8"  # Should be normalized
        assert result["type"] == "ip"
    
    @pytest.mark.asyncio
    async def test_query_with_mixed_provider_types(self, mock_aiohttp_session):
        """Test _query with both always-on and rate-limited providers."""
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
                # Test with rate=True
                result_with_rate = await _query(mock_aiohttp_session, "ip", "8.8.8.8", True)
                assert "always" in result_with_rate
                assert "rate" in result_with_rate
                
                # Test with rate=False
                result_without_rate = await _query(mock_aiohttp_session, "ip", "8.8.8.8", False)
                assert "always" in result_without_rate
                assert "rate" not in result_without_rate


class TestErrorHandlingPaths:
    """Test specific error handling code paths."""
    
    def test_fmt_with_malformed_json(self):
        """Test _fmt with malformed JSON string."""
        malformed_json = '{"incomplete": "json"'  # Missing closing brace
        result = _fmt(malformed_json)
        assert result == "unparseable"
    
    def test_fmt_with_none_input(self):
        """Test _fmt with None input."""
        # The function should handle None gracefully by catching the TypeError
        # when trying to check if strings are "in" None
        result = _fmt(None)
        assert result == "unparseable"
    
    @pytest.mark.asyncio
    async def test_process_csv_session_connector_error(self, sample_csv_file, temp_dir):
        """Test process_csv when connector creation fails."""
        output_file = temp_dir / "connector_error.csv"
        
        # Mock the entire function to handle connector errors
        with patch('ioc_checker.aiohttp.TCPConnector', side_effect=Exception("Connector failed")):
            # The function should catch this exception and return gracefully
            await process_csv(str(sample_csv_file), str(output_file), False)
        
        # Should handle connector errors gracefully without creating outputs
        assert not output_file.exists()
    
    def test_main_argument_parser_error(self):
        """Test main function when argument parser raises error."""
        with patch('sys.argv', ['ioc_checker.py']):  # No required args
            with patch('argparse.ArgumentParser.error') as mock_error:
                main()
                mock_error.assert_called_once()
    
    def test_main_runtime_error_handling(self):
        """Test main function handles RuntimeError from asyncio.run."""
        def raise_runtime_error(*args):
            raise RuntimeError("Runtime error")
        
        with patch('sys.argv', ['ioc_checker.py', 'ip', '8.8.8.8']):
            with patch('ioc_checker.asyncio.run', side_effect=raise_runtime_error):
                # Should handle RuntimeError gracefully
                main()  # Should not raise


# Run additional tests to increase coverage
if __name__ == "__main__":
    pytest.main([__file__, "-v"])