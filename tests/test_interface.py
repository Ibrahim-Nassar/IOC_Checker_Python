"""tests for the unified provider interface"""

import pytest
from ioc_types import IOCResult, IOCStatus
from ioc_checker import scan_ioc_sync


def test_iocresult_instantiation():
    """IOCResult should accept minimal required fields."""
    res = IOCResult(
        ioc="test",
        ioc_type="ip", 
        status=IOCStatus.SUCCESS,
        malicious_engines=0,
        total_engines=0,
        message=""
    )
    assert res.status == IOCStatus.SUCCESS
    assert res.malicious_engines == 0
    assert res.total_engines == 0
    assert res.message == ""


def test_dummy_provider_protocol():
    """A minimal provider implementing the expected interface should work."""

    class DummyProvider:
        NAME = "Dummy"

        async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=1,
                message=""
            )

    dummy = DummyProvider()
    assert dummy.NAME == "Dummy"
    assert hasattr(dummy, 'query_ioc')


def test_scan_ioc_sync_integration():
    """Test that scan_ioc_sync works with a basic IOC."""
    # This will test with whatever providers are available/configured
    results = scan_ioc_sync("8.8.8.8", "ip")
    
    # Should return a dict of provider_name -> IOCResult
    assert isinstance(results, dict)
    
    # Each result should be an IOCResult
    for provider_name, result in results.items():
        assert isinstance(result, IOCResult)
        assert result.ioc == "8.8.8.8"
        assert result.ioc_type == "ip"
        assert isinstance(result.status, IOCStatus)

