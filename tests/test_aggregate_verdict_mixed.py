"""Test aggregate_verdict with mixed MALICIOUS + ERROR scenarios."""
import sys
import os

# Add the parent directory to the path so we can import from IOC_Checker_Python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ioc_checker import aggregate_verdict
from ioc_types import IOCResult, IOCStatus


class TestAggregateVerdictMixed:
    """Test aggregate_verdict with mixed status scenarios."""
    
    def test_error_precedence_over_malicious(self):
        """Test that ERROR has precedence over MALICIOUS."""
        results = [
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.MALICIOUS,
                malicious_engines=5,
                total_engines=10,
                message="Detected as malicious"
            ),
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message="Provider timeout"
            ),
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=8,
                message="Clean"
            )
        ]
        
        # Should return ERROR despite having MALICIOUS
        verdict = aggregate_verdict(results)
        assert verdict == IOCStatus.ERROR
    
    def test_malicious_without_errors(self):
        """Test that MALICIOUS is returned when no errors exist."""
        results = [
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.MALICIOUS,
                malicious_engines=5,
                total_engines=10,
                message="Detected as malicious"
            ),
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=8,
                message="Clean"
            ),
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.UNSUPPORTED,
                malicious_engines=0,
                total_engines=0,
                message="Unsupported IOC type"
            )
        ]
        
        # Should return MALICIOUS
        verdict = aggregate_verdict(results)
        assert verdict == IOCStatus.MALICIOUS
    
    def test_multiple_errors_with_malicious(self):
        """Test multiple errors with malicious results."""
        results = [
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message="Provider A timeout"
            ),
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.ERROR,
                malicious_engines=0,
                total_engines=0,
                message="Provider B API key invalid"
            ),
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.MALICIOUS,
                malicious_engines=3,
                total_engines=5,
                message="Detected by multiple engines"
            )
        ]
        
        # Should return ERROR
        verdict = aggregate_verdict(results)
        assert verdict == IOCStatus.ERROR
    
    def test_unsupported_with_success(self):
        """Test UNSUPPORTED with SUCCESS (should return SUCCESS)."""
        results = [
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=10,
                message="Clean"
            ),
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.UNSUPPORTED,
                malicious_engines=0,
                total_engines=0,
                message="Unsupported IOC type"
            )
        ]
        
        # Should return SUCCESS (not UNSUPPORTED)
        verdict = aggregate_verdict(results)
        assert verdict == IOCStatus.SUCCESS
    
    def test_all_unsupported(self):
        """Test that all UNSUPPORTED returns UNSUPPORTED."""
        results = [
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.UNSUPPORTED,
                malicious_engines=0,
                total_engines=0,
                message="Provider A: Unsupported IOC type"
            ),
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.UNSUPPORTED,
                malicious_engines=0,
                total_engines=0,
                message="Provider B: Unsupported IOC type"
            )
        ]
        
        # Should return UNSUPPORTED
        verdict = aggregate_verdict(results)
        assert verdict == IOCStatus.UNSUPPORTED
    
    def test_all_success(self):
        """Test that all SUCCESS returns SUCCESS."""
        results = [
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=10,
                message="Clean"
            ),
            IOCResult(
                ioc="test.com",
                ioc_type="domain",
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=5,
                message="Clean"
            )
        ]
        
        # Should return SUCCESS
        verdict = aggregate_verdict(results)
        assert verdict == IOCStatus.SUCCESS
    
    def test_empty_results(self):
        """Test empty results list."""
        results = []
        
        # Should return SUCCESS for empty list
        verdict = aggregate_verdict(results)
        assert verdict == IOCStatus.SUCCESS
    
    def test_single_result_each_status(self):
        """Test single result for each status type."""
        # Single ERROR
        assert aggregate_verdict([
            IOCResult("test", "domain", IOCStatus.ERROR, 0, 0, "Error")
        ]) == IOCStatus.ERROR
        
        # Single MALICIOUS
        assert aggregate_verdict([
            IOCResult("test", "domain", IOCStatus.MALICIOUS, 1, 1, "Malicious")
        ]) == IOCStatus.MALICIOUS
        
        # Single UNSUPPORTED
        assert aggregate_verdict([
            IOCResult("test", "domain", IOCStatus.UNSUPPORTED, 0, 0, "Unsupported")
        ]) == IOCStatus.UNSUPPORTED
        
        # Single SUCCESS
        assert aggregate_verdict([
            IOCResult("test", "domain", IOCStatus.SUCCESS, 0, 1, "Clean")
        ]) == IOCStatus.SUCCESS
    
    def test_precedence_order(self):
        """Test the complete precedence order: ERROR > MALICIOUS > UNSUPPORTED > SUCCESS."""
        # All statuses present
        results = [
            IOCResult("test", "domain", IOCStatus.SUCCESS, 0, 1, "Clean"),
            IOCResult("test", "domain", IOCStatus.UNSUPPORTED, 0, 0, "Unsupported"),
            IOCResult("test", "domain", IOCStatus.MALICIOUS, 1, 1, "Malicious"),
            IOCResult("test", "domain", IOCStatus.ERROR, 0, 0, "Error")
        ]
        
        # Should return ERROR (highest precedence)
        verdict = aggregate_verdict(results)
        assert verdict == IOCStatus.ERROR
        
        # Without ERROR
        results_no_error = [
            IOCResult("test", "domain", IOCStatus.SUCCESS, 0, 1, "Clean"),
            IOCResult("test", "domain", IOCStatus.UNSUPPORTED, 0, 0, "Unsupported"),
            IOCResult("test", "domain", IOCStatus.MALICIOUS, 1, 1, "Malicious")
        ]
        
        # Should return MALICIOUS
        verdict = aggregate_verdict(results_no_error)
        assert verdict == IOCStatus.MALICIOUS
        
        # Without ERROR or MALICIOUS
        results_no_error_malicious = [
            IOCResult("test", "domain", IOCStatus.SUCCESS, 0, 1, "Clean"),
            IOCResult("test", "domain", IOCStatus.UNSUPPORTED, 0, 0, "Unsupported")
        ]
        
        # Should return SUCCESS (because SUCCESS is present)
        verdict = aggregate_verdict(results_no_error_malicious)
        assert verdict == IOCStatus.SUCCESS 