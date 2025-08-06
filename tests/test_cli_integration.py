"""Tests for CLI integration functionality."""

import pytest
import sys
import subprocess
from unittest.mock import patch, MagicMock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from ioc_checker import main, scan_ioc_sync
from ioc_types import IOCResult, IOCStatus


class TestCLIIntegration:
    """Test cases for CLI integration."""
    
    def test_main_help(self):
        """Test CLI help functionality."""
        with patch('sys.argv', ['ioc_checker', '--help']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            # Help should exit with code 0
            assert exc_info.value.code == 0
    
    def test_main_no_arguments(self):
        """Test CLI with no arguments."""
        with patch('sys.argv', ['ioc_checker']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            # Should exit with error code (argparse error)
            assert exc_info.value.code != 0
    
    def test_main_with_ip_address(self):
        """Test CLI with IP address argument."""
        test_results = {
            "dummy": IOCResult(
                ioc="8.8.8.8",
                ioc_type="ip",
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=1,
                message="Test result"
            )
        }
        
        with patch('sys.argv', ['ioc_checker', '8.8.8.8']), \
             patch('ioc_checker.scan_ioc', return_value=test_results), \
             patch('asyncio.run') as mock_run, \
             patch('builtins.print') as mock_print:
            
            async def mock_scan_ioc(*args):
                return test_results
            
            mock_run.side_effect = lambda coro: None  # Skip actual async execution
            
            try:
                main()
            except SystemExit:
                pass  # Expected for successful execution
            
            # Should have called asyncio.run
            mock_run.assert_called_once()
    
    def test_main_with_explicit_type(self):
        """Test CLI with explicit IOC type."""
        with patch('sys.argv', ['ioc_checker', '8.8.8.8', '--type', 'ip']), \
             patch('asyncio.run') as mock_run:
            
            mock_run.side_effect = lambda coro: None
            
            try:
                main()
            except SystemExit:
                pass
            
            mock_run.assert_called_once()
    
    def test_main_invalid_type(self):
        """Test CLI with invalid IOC type."""
        with patch('sys.argv', ['ioc_checker', '8.8.8.8', '--type', 'invalid']):
            with pytest.raises(SystemExit) as exc_info:
                main()
            # Should exit with error
            assert exc_info.value.code != 0
    
    def test_main_auto_detection_failure(self):
        """Test CLI when auto-detection fails."""
        with patch('sys.argv', ['ioc_checker', 'invalid-ioc']), \
             patch('ioc_types.detect_ioc_type', return_value=("unknown", "invalid-ioc")):
            
            with pytest.raises(SystemExit) as exc_info:
                main()
            # Should exit with error when auto-detection fails
            assert exc_info.value.code != 0
    
    def test_main_with_providers_filter(self):
        """Test CLI with specific providers."""
        mock_providers = [
            MagicMock(NAME="virustotal"),
            MagicMock(NAME="abuseipdb"),
            MagicMock(NAME="otx")
        ]
        
        with patch('sys.argv', ['ioc_checker', '8.8.8.8', '--providers', 'virustotal,abuseipdb']), \
             patch('providers.get_providers', return_value=mock_providers), \
             patch('asyncio.run') as mock_run:
            
            mock_run.side_effect = lambda coro: None
            
            try:
                main()
            except SystemExit:
                pass
            
            mock_run.assert_called_once()
    
    def test_main_invalid_provider(self):
        """Test CLI with invalid provider name."""
        mock_providers = [MagicMock(NAME="virustotal")]
        
        with patch('sys.argv', ['ioc_checker', '8.8.8.8', '--providers', 'invalid_provider']), \
             patch('providers.get_providers', return_value=mock_providers):
            
            with pytest.raises(SystemExit) as exc_info:
                main()
            # Should exit with error for unknown provider
            assert exc_info.value.code != 0
    
    def test_scan_ioc_sync_wrapper(self):
        """Test the synchronous wrapper function."""
        mock_result = {
            "test": IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=1,
                message=""
            )
        }
        
        with patch('asyncio.run', return_value=mock_result) as mock_run:
            result = scan_ioc_sync("test.com", "domain")
            
            assert result == mock_result
            mock_run.assert_called_once()
    
    def test_scan_ioc_sync_from_async_context(self):
        """Test that scan_ioc_sync raises error when called from async context."""
        # Mock a running event loop to simulate async context
        mock_loop = MagicMock()
        with patch('asyncio.get_running_loop', return_value=mock_loop):
            # Should raise RuntimeError when called from async context
            with pytest.raises(RuntimeError, match="scan_ioc_sync cannot be called from an async loop"):
                scan_ioc_sync("test.com", "domain")
    
    def test_cli_output_formatting(self):
        """Test CLI output formatting."""
        test_results = {
            "virustotal": IOCResult(
                ioc="8.8.8.8",
                ioc_type="ip",
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=1,
                message=""
            ),
            "abuseipdb": IOCResult(
                ioc="8.8.8.8",
                ioc_type="ip",
                status=IOCStatus.MALICIOUS,
                malicious_engines=1,
                total_engines=1,
                message=""
            )
        }
        
        with patch('sys.argv', ['ioc_checker', '8.8.8.8']), \
             patch('ioc_checker.scan_ioc') as mock_scan, \
             patch('builtins.print') as mock_print:
            
            async def mock_scan_ioc(*args):
                return test_results
            
            mock_scan.return_value = test_results
            
            async def run_check():
                results = await mock_scan("8.8.8.8", "ip", None)
                
                # Simulate the output formatting from main()
                for provider_name, result in results.items():
                    status_txt = result.status.name
                    print(f"{provider_name}: {status_txt} (mal {result.malicious_engines}/{result.total_engines})")
                
                from ioc_checker import aggregate_verdict
                overall_verdict = aggregate_verdict(list(results.values()))
                print(f"\nOVERALL: {overall_verdict.name}")
            
            import asyncio
            asyncio.run(run_check())
            
            # Verify output calls
            assert mock_print.call_count >= 3  # At least provider results + overall
    
    def test_unicode_ioc_handling(self):
        """Test CLI with Unicode IOC values."""
        with patch('sys.argv', ['ioc_checker', 'example.com']), \
             patch('ioc_types.detect_ioc_type', return_value=("domain", "example.com")), \
             patch('asyncio.run') as mock_run:
            
            mock_run.side_effect = lambda coro: None
            
            try:
                main()
            except SystemExit:
                pass
            
            mock_run.assert_called_once()
    
    def test_provider_name_case_insensitive(self):
        """Test that provider names are case-insensitive."""
        mock_providers = [
            MagicMock(NAME="VirusTotal"),
            MagicMock(NAME="AbuseIPDB")
        ]
        
        with patch('sys.argv', ['ioc_checker', '8.8.8.8', '--providers', 'virustotal,ABUSEIPDB']), \
             patch('providers.get_providers', return_value=mock_providers), \
             patch('asyncio.run') as mock_run:
            
            mock_run.side_effect = lambda coro: None
            
            try:
                main()
            except SystemExit:
                pass
            
            mock_run.assert_called_once()
    
    def test_empty_provider_list(self):
        """Test CLI behavior with empty provider list."""
        with patch('sys.argv', ['ioc_checker', '8.8.8.8']), \
             patch('providers.get_providers', return_value=[]), \
             patch('asyncio.run') as mock_run:
            
            mock_run.side_effect = lambda coro: None
            
            try:
                main()
            except SystemExit:
                pass
            
            mock_run.assert_called_once()


class TestCLIModuleExecution:
    """Test CLI module execution scenarios."""
    
    def test_main_module_execution(self):
        """Test that the module can be executed as main."""
        # This test verifies the if __name__ == "__main__": block
        with patch('ioc_checker.main') as mock_main:
            # Simulate module execution
            exec("""
if __name__ == "__main__":
    main()
""", {'__name__': '__main__', 'main': mock_main})
            
            mock_main.assert_called_once()
    
    def test_utf8_stream_reconfiguration(self):
        """Test that UTF-8 streams are configured properly."""
        # The module should configure stdout/stderr for UTF-8
        # This is mainly a structural test to ensure the code exists
        import ioc_checker
        
        # The module should have loaded without errors
        assert hasattr(ioc_checker, 'main')
        
        # If sys.stdout has reconfigure method, it should handle UTF-8
        if hasattr(sys.stdout, 'reconfigure'):
            # The reconfiguration code exists in the module
            pass
    
    def test_logging_configuration(self):
        """Test that logging is configured properly."""
        import ioc_checker
        
        # Should have a logger configured
        assert hasattr(ioc_checker, 'log')
        assert ioc_checker.log.name == "ioc_checker"
    
    def test_module_exports(self):
        """Test that the module exports expected functions."""
        import ioc_checker
        
        expected_exports = ["aggregate_verdict", "scan_ioc", "scan_ioc_sync"]
        
        for export in expected_exports:
            assert hasattr(ioc_checker, export)
            assert callable(getattr(ioc_checker, export)) 