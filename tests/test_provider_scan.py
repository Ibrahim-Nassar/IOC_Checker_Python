from ioc_types import IOCResult, IOCStatus
from ioc_checker import aggregate_verdict
import providers


def test_scan_minimal(monkeypatch):
    """Two providers, one malicious hit → overall verdict MALICIOUS."""

    class DummyTrue:
        NAME = "true"
        TIMEOUT = 1

        async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.MALICIOUS,
                malicious_engines=1,
                total_engines=1,
                message=""
            )

    class DummyFalse:
        NAME = "false"
        TIMEOUT = 1

        async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=1,
                message=""
            )

    # Mock get_providers() to return instances instead of classes
    dummy_providers = [DummyTrue(), DummyFalse()]
    monkeypatch.setattr(providers, "get_providers", lambda: dummy_providers)

    # Use the actual scan_ioc function to test the full pipeline
    import asyncio
    from ioc_checker import scan_ioc
    
    async def run_test():
        results = await scan_ioc("1.1.1.1", "ip")
        return list(results.values())
    
    results = asyncio.run(run_test())
    verdict = aggregate_verdict(results)

    assert verdict is IOCStatus.MALICIOUS


def test_scan_partial_failure(monkeypatch):
    """One provider errors, one succeeds → overall verdict ERROR."""

    class Flaky:
        NAME = "flaky"
        TIMEOUT = 1

        async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
            raise RuntimeError("API down")

    class Good:
        NAME = "good"
        TIMEOUT = 1

        async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
            return IOCResult(
                ioc=ioc,
                ioc_type=ioc_type,
                status=IOCStatus.SUCCESS,
                malicious_engines=0,
                total_engines=1,
                message=""
            )

    # Mock get_providers() to return instances instead of classes
    dummy_providers = [Flaky(), Good()]
    monkeypatch.setattr(providers, "get_providers", lambda: dummy_providers)

    # Use the actual scan_ioc function to test error handling
    import asyncio
    from ioc_checker import scan_ioc
    
    async def run_test():
        results = await scan_ioc("8.8.8.8", "ip")
        return list(results.values())
    
    results = asyncio.run(run_test())
    verdict = aggregate_verdict(results)
    assert verdict is IOCStatus.ERROR


def test_virustotal_url_scanning(monkeypatch):
    """Test that VirusTotal provider can scan URLs and return malicious status."""
    from virustotal_api import VirusTotalProvider
    from unittest.mock import AsyncMock, Mock
    
    # Create a mock response for a malicious URL
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 20,
                    "suspicious": 3,
                    "undetected": 70,
                    "harmless": 0,
                    "timeout": 0
                }
            }
        }
    }
    
    # Mock the aget function in the virustotal_api module directly
    import virustotal_api
    monkeypatch.setattr(virustotal_api, "aget", AsyncMock(return_value=mock_response))
    
    # Test synchronously since we're in pytest
    provider = VirusTotalProvider(api_key="test_key")
    
    # We need to run this in an async context
    import asyncio
    
    async def run_test():
        result = await provider.query_ioc("http://evil.test", "url")
        
        assert result.status == IOCStatus.MALICIOUS
        assert result.malicious_engines == 20
        assert result.total_engines == 93  # 20+3+70+0+0
        assert result.ioc == "http://evil.test"
        assert result.ioc_type == "url"
    
    asyncio.run(run_test())


def test_virustotal_url_encoding():
    """Test that URL encoding for VirusTotal works correctly."""
    from virustotal_api import VirusTotalProvider
    
    provider = VirusTotalProvider(api_key="test_key")
    
    # Test URL encoding
    test_url = "http://evil.test"
    encoded = provider._encode_url_for_vt(test_url)
    
    # Verify it's base64url encoded without padding
    import base64
    expected = base64.urlsafe_b64encode(test_url.encode('utf-8')).decode('ascii').rstrip('=')
    assert encoded == expected
    
    # Test with URL that has different cases and whitespace
    test_url_messy = "  HTTP://EVIL.TEST  "
    encoded_messy = provider._encode_url_for_vt(test_url_messy)
    expected_clean = base64.urlsafe_b64encode("http://evil.test".encode('utf-8')).decode('ascii').rstrip('=')
    assert encoded_messy == expected_clean
