"""
Test CLI edge cases and argument parsing scenarios.
Covers command-line interface error conditions, argument validation, and edge cases.
"""
import pytest
from unittest.mock import patch

from ioc_checker import main


class TestCLIEdgeCases:
    """Test command-line interface edge cases."""
    
    def test_main_no_arguments_error(self):
        """Test main function with no arguments."""
        test_args = ["ioc_checker.py"]
        
        with patch('sys.argv', test_args):
            with pytest.raises(SystemExit):
                main()
    
    def test_main_invalid_ioc_type(self):
        """Test main function with invalid IOC type."""
        test_args = ["ioc_checker.py", "invalid_type", "test_value"]
        
        with patch('sys.argv', test_args):
            with pytest.raises(SystemExit):
                main()
    
    def test_main_missing_value(self):
        """Test main function with IOC type but no value."""
        test_args = ["ioc_checker.py", "ip"]
        
        with patch('sys.argv', test_args):
            with pytest.raises(SystemExit):
                main()
    
    def test_main_csv_with_output_args(self):
        """Test CSV processing with custom output file."""
        test_args = ["ioc_checker.py", "--csv", "test.csv", "-o", "custom_output.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run') as mock_run:
                main()
                mock_run.assert_called_once()
    
    def test_main_rate_limit_flag(self):
        """Test rate limit flag activation."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--rate"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_main_individual_provider_flags(self):
        """Test individual provider selection flags."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--virustotal", "--greynoise"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_main_all_provider_flags(self):
        """Test all provider flags enabled."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--virustotal", "--greynoise", "--pulsedive", "--shodan"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_main_csv_with_providers(self):
        """Test CSV processing with specific providers."""
        test_args = ["ioc_checker.py", "--csv", "test.csv", "--virustotal", "--shodan"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_main_conflicting_arguments(self):
        """Test conflicting arguments (both single IOC and CSV)."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--csv", "test.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                # Should process single IOC, not CSV (single IOC takes precedence)
                main()


class TestArgumentValidation:
    """Test argument parsing and validation."""
    
    def test_valid_ioc_types(self):
        """Test all valid IOC types are accepted."""
        valid_types = ["ip", "domain", "url", "hash", "email", "filepath", "registry", "wallet", "asn", "attack"]
        
        for ioc_type in valid_types:
            test_args = ["ioc_checker.py", ioc_type, "test_value"]
            
            with patch('sys.argv', test_args):
                with patch('asyncio.run'):
                    main()  # Should not raise exception
    
    def test_help_argument(self):
        """Test --help argument."""
        test_args = ["ioc_checker.py", "--help"]
        
        with patch('sys.argv', test_args):
            with pytest.raises(SystemExit) as exc_info:
                main()
            assert exc_info.value.code == 0  # Help should exit with code 0
    
    def test_csv_long_form(self):
        """Test --csv long form argument."""
        test_args = ["ioc_checker.py", "--csv", "test.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_output_short_form(self):
        """Test -o short form argument."""
        test_args = ["ioc_checker.py", "--csv", "test.csv", "-o", "output.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_output_long_form(self):
        """Test --out long form argument."""
        test_args = ["ioc_checker.py", "--csv", "test.csv", "--out", "output.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()


class TestSpecialCharacterHandling:
    """Test handling of special characters and edge case inputs."""
    
    def test_unicode_ioc_value(self):
        """Test IOC value with unicode characters."""
        test_args = ["ioc_checker.py", "domain", "例え.com"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_very_long_ioc_value(self):
        """Test very long IOC value."""
        long_value = "a" * 1000 + ".com"
        test_args = ["ioc_checker.py", "domain", long_value]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_ioc_with_spaces(self):
        """Test IOC value with spaces."""
        test_args = ["ioc_checker.py", "domain", "test domain.com"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_empty_csv_filename(self):
        """Test empty CSV filename."""
        test_args = ["ioc_checker.py", "--csv", ""]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_csv_with_special_characters(self):
        """Test CSV filename with special characters."""
        test_args = ["ioc_checker.py", "--csv", "test-file_with spaces&symbols.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()


class TestProviderCombinations:
    """Test various provider flag combinations."""
    
    def test_no_providers_selected(self):
        """Test when no specific providers are selected."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_single_provider_virustotal(self):
        """Test only VirusTotal provider selected."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--virustotal"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_single_provider_greynoise(self):
        """Test only GreyNoise provider selected."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--greynoise"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_single_provider_pulsedive(self):
        """Test only Pulsedive provider selected."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--pulsedive"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_single_provider_shodan(self):
        """Test only Shodan provider selected."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--shodan"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_mixed_providers_and_rate(self):
        """Test mixed provider selection with rate limiting."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--virustotal", "--shodan", "--rate"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()


class TestFileHandlingEdgeCases:
    """Test file handling edge cases in CLI."""
    
    def test_csv_file_with_no_extension(self):
        """Test CSV file without .csv extension."""
        test_args = ["ioc_checker.py", "--csv", "datafile"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_output_file_with_path(self):
        """Test output file with full path."""
        test_args = ["ioc_checker.py", "--csv", "test.csv", "-o", "/tmp/results.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_relative_path_csv(self):
        """Test relative path for CSV file."""
        test_args = ["ioc_checker.py", "--csv", "../test.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_current_directory_csv(self):
        """Test current directory CSV file."""
        test_args = ["ioc_checker.py", "--csv", "./test.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()


class TestErrorRecovery:
    """Test error recovery in CLI scenarios."""
    
    def test_invalid_argument_recovery(self):
        """Test recovery from invalid arguments."""
        test_args = ["ioc_checker.py", "--invalid-flag"]
        
        with patch('sys.argv', test_args):
            with pytest.raises(SystemExit):
                main()
    
    def test_partial_arguments(self):
        """Test partial argument specification."""
        test_args = ["ioc_checker.py", "--csv"]  # Missing CSV filename
        
        with patch('sys.argv', test_args):
            with pytest.raises(SystemExit):
                main()
    
    def test_conflicting_flags(self):
        """Test handling of potentially conflicting flags."""
        test_args = ["ioc_checker.py", "ip", "8.8.8.8", "--rate", "--virustotal"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()  # Should handle gracefully


class TestOutputHandling:
    """Test output file handling scenarios."""
    
    def test_default_output_filename(self):
        """Test default output filename."""
        test_args = ["ioc_checker.py", "--csv", "input.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_custom_output_filename(self):
        """Test custom output filename."""
        test_args = ["ioc_checker.py", "--csv", "input.csv", "-o", "custom.csv"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()
    
    def test_output_with_different_extension(self):
        """Test output file with different extension."""
        test_args = ["ioc_checker.py", "--csv", "input.csv", "-o", "output.txt"]
        
        with patch('sys.argv', test_args):
            with patch('asyncio.run'):
                main()


if __name__ == "__main__":
    pytest.main([__file__])