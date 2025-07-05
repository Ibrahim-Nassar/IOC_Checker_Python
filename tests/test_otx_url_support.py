"""
Tests for OTX URL support functionality.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
import httpx

from otx_api import OTXProvider
from ioc_types import IOCStatus


class TestOTXURLSupport:
    """Test OTX provider URL support."""
    
    @pytest.fixture
    def otx_provider(self):
        """Create OTX provider with test API key."""
        return OTXProvider(api_key="test_api_key")
    
    @pytest.mark.asyncio
    async def test_url_in_supported_types(self, otx_provider):
        """Test that URL is now in SUPPORTED_TYPES."""
        assert "url" in otx_provider.SUPPORTED_TYPES
        assert "ip" in otx_provider.SUPPORTED_TYPES
        assert "domain" in otx_provider.SUPPORTED_TYPES
        assert "hash" in otx_provider.SUPPORTED_TYPES
    
    @pytest.mark.asyncio
    async def test_url_malicious_detection(self, otx_provider):
        """Test URL scanning returns MALICIOUS when threats are found."""
        test_url = "http://malicious-site.com/malware.exe"
        
        # Mock response with pulses (indicating malicious)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pulse_info": {
                "pulses": [
                    {
                        "id": "12345",
                        "name": "Malicious URL detected",
                        "description": "Known malware distribution site"
                    },
                    {
                        "id": "67890",
                        "name": "Phishing campaign",
                        "description": "Part of ongoing phishing campaign"
                    }
                ]
            }
        }
        
        with patch('async_cache.aget', return_value=mock_response) as mock_aget:
            result = await otx_provider.query_ioc(test_url, "url")
            
            # Verify the request was made correctly
            mock_aget.assert_called_once()
            call_args = mock_aget.call_args
            assert f"url/{test_url}/general" in call_args[0][0]
            assert call_args[1]["headers"]["X-OTX-API-KEY"] == "test_api_key"
            
            # Verify the result
            assert result.ioc == test_url
            assert result.ioc_type == "url"
            assert result.status == IOCStatus.MALICIOUS
            assert result.malicious_engines == 2
            assert result.total_engines == 2
            assert result.message == ""
    
    @pytest.mark.asyncio
    async def test_url_clean_detection(self, otx_provider):
        """Test URL scanning returns SUCCESS when no threats are found."""
        test_url = "http://safe-site.com"
        
        # Mock response with no pulses (indicating clean)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pulse_info": {
                "pulses": []
            }
        }
        
        with patch('async_cache.aget', return_value=mock_response) as mock_aget:
            result = await otx_provider.query_ioc(test_url, "url")
            
            # Verify the request was made correctly
            mock_aget.assert_called_once()
            call_args = mock_aget.call_args
            assert f"url/{test_url}/general" in call_args[0][0]
            
            # Verify the result
            assert result.ioc == test_url
            assert result.ioc_type == "url"
            assert result.status == IOCStatus.SUCCESS
            assert result.malicious_engines == 0
            assert result.total_engines == 0
            assert result.message == ""
    
    @pytest.mark.asyncio
    async def test_url_api_error_handling(self, otx_provider):
        """Test URL scanning handles API errors gracefully."""
        test_url = "http://test-site.com"
        
        # Mock HTTP error response
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = "Not Found"
        
        with patch('async_cache.aget', return_value=mock_response) as mock_aget:
            result = await otx_provider.query_ioc(test_url, "url")
            
            # Verify the result shows error
            assert result.ioc == test_url
            assert result.ioc_type == "url"
            assert result.status == IOCStatus.ERROR
            assert result.malicious_engines == 0
            assert result.total_engines == 0
            assert "HTTP 404" in result.message
    
    @pytest.mark.asyncio
    async def test_url_network_error_handling(self, otx_provider):
        """Test URL scanning handles network errors gracefully."""
        test_url = "http://test-site.com"
        
        # Mock network exception
        with patch('async_cache.aget', side_effect=httpx.ConnectError("Connection failed")) as mock_aget:
            result = await otx_provider.query_ioc(test_url, "url")
            
            # Verify the result shows error
            assert result.ioc == test_url
            assert result.ioc_type == "url"
            assert result.status == IOCStatus.ERROR
            assert result.malicious_engines == 0
            assert result.total_engines == 0
            assert "Network connection error" in result.message
    
    @pytest.mark.asyncio
    async def test_url_timeout_handling(self, otx_provider):
        """Test URL scanning handles timeouts gracefully."""
        test_url = "http://slow-site.com"
        
        # Mock timeout exception
        with patch('async_cache.aget', side_effect=httpx.ReadTimeout("Request timed out")) as mock_aget:
            result = await otx_provider.query_ioc(test_url, "url")
            
            # Verify the result shows error
            assert result.ioc == test_url
            assert result.ioc_type == "url"
            assert result.status == IOCStatus.ERROR
            assert result.malicious_engines == 0
            assert result.total_engines == 0
            assert "Connection timeout" in result.message
    
    @pytest.mark.asyncio
    async def test_url_api_endpoint_construction(self, otx_provider):
        """Test that URL API endpoint is constructed correctly."""
        test_url = "https://example.com/path?param=value"
        
        # Mock response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"pulse_info": {"pulses": []}}
        
        with patch('async_cache.aget', return_value=mock_response) as mock_aget:
            await otx_provider.query_ioc(test_url, "url")
            
            # Verify the endpoint construction
            call_args = mock_aget.call_args
            expected_url = f"https://otx.alienvault.com/api/v1/indicators/url/{test_url}/general"
            assert call_args[0][0] == expected_url
            
            # Verify headers
            assert call_args[1]["headers"]["X-OTX-API-KEY"] == "test_api_key"
            assert call_args[1]["timeout"] == 15.0
            assert call_args[1]["api_key"] == "test_api_key"
    
    @pytest.mark.asyncio
    async def test_url_pulse_counting(self, otx_provider):
        """Test that pulse counting works correctly for URLs."""
        test_url = "http://suspicious-site.com"
        
        # Mock response with multiple pulses
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "pulse_info": {
                "pulses": [
                    {"id": "1", "name": "Pulse 1"},
                    {"id": "2", "name": "Pulse 2"},
                    {"id": "3", "name": "Pulse 3"},
                    {"id": "4", "name": "Pulse 4"},
                    {"id": "5", "name": "Pulse 5"},
                ]
            }
        }
        
        with patch('async_cache.aget', return_value=mock_response):
            result = await otx_provider.query_ioc(test_url, "url")
            
            # Verify pulse counting
            assert result.status == IOCStatus.MALICIOUS
            assert result.malicious_engines == 5
            assert result.total_engines == 5
    
    def test_url_supported_types_class_attribute(self):
        """Test that URL is in the class-level SUPPORTED_TYPES."""
        assert "url" in OTXProvider.SUPPORTED_TYPES
        assert len(OTXProvider.SUPPORTED_TYPES) == 4  # ip, domain, hash, url


if __name__ == "__main__":
    pytest.main([__file__]) 