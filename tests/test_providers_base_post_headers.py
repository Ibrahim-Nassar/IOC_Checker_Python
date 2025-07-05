"""Test that POST requests in providers_base properly pass headers."""
import asyncio
import pytest
import sys
import os
from unittest.mock import AsyncMock, patch

# Add the parent directory to the path so we can import from IOC_Checker_Python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from providers_base import BaseProvider
from ioc_types import IOCResult, IOCStatus


class TestProvider(BaseProvider):
    """Test provider implementation."""
    
    NAME = "test_provider"
    SUPPORTED_TYPES = {"ip", "domain", "url", "hash"}
    
    def __init__(self, api_key: str = "test_key"):
        super().__init__(api_key)
    
    async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
        """Test implementation."""
        return IOCResult(
            ioc=ioc,
            ioc_type=ioc_type,
            status=IOCStatus.SUCCESS,
            malicious_engines=0,
            total_engines=1
        )


class TestProvidersBasePostHeaders:
    """Test POST headers functionality in providers_base."""
    
    @pytest.mark.asyncio
    async def test_post_headers_passed_to_apost(self):
        """Test that POST headers are properly passed to apost."""
        provider = TestProvider()
        
        # Mock the apost function to capture arguments
        with patch('providers_base.apost') as mock_apost:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"test": "data"}
            mock_apost.return_value = mock_response
            
            # Test headers
            test_headers = {
                "Authorization": "Bearer test_token",
                "Content-Type": "application/json",
                "X-Custom-Header": "test_value"
            }
            
            # Call _safe_request with POST method and headers
            result = await provider._safe_request(
                url="https://example.com/api",
                method="POST",
                json_data={"query": "test"},
                headers=test_headers
            )
            
            # Verify apost was called with headers
            mock_apost.assert_called_once()
            args, kwargs = mock_apost.call_args
            
            # Check that headers were passed
            assert 'headers' in kwargs
            assert kwargs['headers'] == test_headers
            
            # Check other parameters
            assert args[0] == "https://example.com/api"
            assert kwargs['json'] == {"query": "test"}
            assert kwargs['api_key'] == "test_key"
            assert kwargs['timeout'] == provider.timeout
    
    @pytest.mark.asyncio
    async def test_post_no_headers(self):
        """Test that POST works correctly when no headers are provided."""
        provider = TestProvider()
        
        with patch('providers_base.apost') as mock_apost:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"test": "data"}
            mock_apost.return_value = mock_response
            
            # Call _safe_request with POST method but no headers
            result = await provider._safe_request(
                url="https://example.com/api",
                method="POST",
                json_data={"query": "test"}
            )
            
            # Verify apost was called with None headers
            mock_apost.assert_called_once()
            args, kwargs = mock_apost.call_args
            
            # Check that headers parameter was passed as None
            assert 'headers' in kwargs
            assert kwargs['headers'] is None
    
    @pytest.mark.asyncio
    async def test_get_headers_still_work(self):
        """Test that GET requests still work with headers (regression test)."""
        provider = TestProvider()
        
        with patch('providers_base.aget') as mock_aget:
            mock_response = AsyncMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"test": "data"}
            mock_aget.return_value = mock_response
            
            test_headers = {"Authorization": "Bearer test_token"}
            
            # Call _safe_request with GET method and headers
            result = await provider._safe_request(
                url="https://example.com/api",
                method="GET",
                headers=test_headers
            )
            
            # Verify aget was called with headers
            mock_aget.assert_called_once()
            args, kwargs = mock_aget.call_args
            
            # Check that headers were passed
            assert 'headers' in kwargs
            assert kwargs['headers'] == test_headers
    
    @pytest.mark.asyncio
    async def test_retry_count_fix(self):
        """Test that retry count is correct (max_retries attempts, not max_retries + 1)."""
        provider = TestProvider()
        
        with patch('providers_base.aget') as mock_aget:
            # Mock to always fail
            mock_aget.side_effect = Exception("Connection failed")
            
            # Should try exactly 3 times (max_retries=3)
            with pytest.raises(Exception, match="Connection failed"):
                await provider._safe_request(
                    url="https://example.com/api",
                    method="GET",
                    max_retries=3
                )
            
            # Should have been called exactly 3 times
            assert mock_aget.call_count == 3
    
    @pytest.mark.asyncio
    async def test_retry_count_rate_limit(self):
        """Test that rate limit retries work correctly."""
        provider = TestProvider()
        
        with patch('providers_base.aget') as mock_aget:
            with patch('asyncio.sleep') as mock_sleep:
                # Mock responses: 429, 429, 200
                mock_responses = []
                for status in [429, 429, 200]:
                    mock_response = AsyncMock()
                    mock_response.status_code = status
                    if status == 200:
                        mock_response.json.return_value = {"success": True}
                    mock_responses.append(mock_response)
                
                mock_aget.side_effect = mock_responses
                
                # Should succeed on third try
                result = await provider._safe_request(
                    url="https://example.com/api",
                    method="GET",
                    max_retries=3
                )
                
                # Should have been called 3 times
                assert mock_aget.call_count == 3
                
                # Should have slept twice (for the two rate limit responses)
                assert mock_sleep.call_count == 2
                
                # Check exponential backoff
                sleep_calls = [call[0][0] for call in mock_sleep.call_args_list]
                assert sleep_calls == [1, 2]  # 2^0, 2^1 