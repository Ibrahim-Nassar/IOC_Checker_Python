"""
Test provider timeout scenarios and network error conditions.
Covers timeout handling, connection failures, and rate limiting edge cases.
"""
import pytest
import asyncio
import aiohttp
from unittest.mock import patch, Mock, AsyncMock
import json

from providers import AbuseIPDB, VirusTotal, OTX, ThreatFox, GreyNoise, Pulsedive, Shodan


@pytest.mark.asyncio
class TestProviderTimeouts:
    """Test provider timeout scenarios."""
    
    async def test_abuseipdb_timeout(self):
        """Test AbuseIPDB timeout handling."""
        provider = AbuseIPDB()
        provider.key = "test_key"
        
        session = Mock()
        context_manager = AsyncMock()
        context_manager.__aenter__.side_effect = asyncio.TimeoutError("Request timeout")
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "error:" in result
        assert "Request timeout" in result
    
    async def test_virustotal_timeout(self):
        """Test VirusTotal timeout handling."""
        provider = VirusTotal()
        provider.key = "test_key"
        
        session = Mock()
        context_manager = AsyncMock()
        context_manager.__aenter__.side_effect = asyncio.TimeoutError("Request timeout")
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "error:" in result
    
    async def test_otx_timeout(self):
        """Test OTX timeout handling."""
        provider = OTX()
        provider.key = "test_key"
        
        session = Mock()
        context_manager = AsyncMock()
        context_manager.__aenter__.side_effect = asyncio.TimeoutError("Request timeout")
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "error:" in result
    
    async def test_threatfox_timeout(self):
        """Test ThreatFox timeout handling."""
        provider = ThreatFox()
        
        session = Mock()
        context_manager = AsyncMock()
        context_manager.__aenter__.side_effect = asyncio.TimeoutError("Request timeout")
        session.post.return_value = context_manager
        
        result = await provider.query(session, "hash", "d41d8cd98f00b204e9800998ecf8427e")
        assert "error:" in result


@pytest.mark.asyncio
class TestProviderConnectionErrors:
    """Test provider connection error scenarios."""
    
    async def test_abuseipdb_connection_error(self):
        """Test AbuseIPDB connection error."""
        provider = AbuseIPDB()
        provider.key = "test_key"
        
        session = Mock()
        session.get.side_effect = aiohttp.ClientConnectorError(
            Mock(), OSError("Connection refused"))
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "error:" in result
    
    async def test_virustotal_ssl_error(self):
        """Test VirusTotal SSL error."""
        provider = VirusTotal()
        provider.key = "test_key"
        
        session = Mock()
        session.get.side_effect = aiohttp.ClientSSLError("SSL verification failed")
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "error:" in result
    
    async def test_otx_dns_error(self):
        """Test OTX DNS resolution error."""
        provider = OTX()
        provider.key = "test_key"
        
        session = Mock()
        session.get.side_effect = aiohttp.ClientConnectorError(
            Mock(), OSError("Name resolution failed"))
        
        result = await provider.query(session, "domain", "example.com")
        assert "error:" in result
    
    async def test_threatfox_server_error(self):
        """Test ThreatFox server error response."""
        provider = ThreatFox()
        
        session = Mock()
        response = AsyncMock()
        response.status = 500
        response.text.return_value = "Internal Server Error"
        
        context_manager = AsyncMock()
        context_manager.__aenter__.return_value = response
        session.post.return_value = context_manager
        
        result = await provider.query(session, "hash", "test_hash")
        assert "error:" in result


@pytest.mark.asyncio
class TestProviderResponseErrors:
    """Test provider response parsing errors."""
    
    async def test_abuseipdb_invalid_json(self):
        """Test AbuseIPDB invalid JSON response."""
        provider = AbuseIPDB()
        provider.key = "test_key"
        
        session = Mock()
        response = AsyncMock()
        response.text.return_value = "invalid json response"
        
        context_manager = AsyncMock()
        context_manager.__aenter__.return_value = response
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert result == "invalid json response"  # Should return raw text
    
    async def test_virustotal_malformed_response(self):
        """Test VirusTotal malformed response structure."""
        provider = VirusTotal()
        provider.key = "test_key"
        
        session = Mock()
        response = AsyncMock()
        response.text.return_value = '{"error": "malformed"}'
        
        context_manager = AsyncMock()
        context_manager.__aenter__.return_value = response
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "malformed" in result
    
    async def test_otx_empty_response(self):
        """Test OTX empty response."""
        provider = OTX()
        provider.key = "test_key"
        
        session = Mock()
        response = AsyncMock()
        response.text.return_value = ""
        
        context_manager = AsyncMock()
        context_manager.__aenter__.return_value = response
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert result == ""


@pytest.mark.asyncio
class TestProviderRateLimiting:
    """Test provider rate limiting scenarios."""
    
    async def test_virustotal_rate_limit_response(self):
        """Test VirusTotal rate limit response."""
        provider = VirusTotal()
        provider.key = "test_key"
        
        session = Mock()
        response = AsyncMock()
        response.status = 429
        response.text.return_value = '{"error": {"code": "QuotaExceededError"}}'
        
        context_manager = AsyncMock()
        context_manager.__aenter__.return_value = response
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "QuotaExceededError" in result
    
    async def test_abuseipdb_rate_limit(self):
        """Test AbuseIPDB rate limit response."""
        provider = AbuseIPDB()
        provider.key = "test_key"
        
        session = Mock()
        response = AsyncMock()
        response.status = 429
        response.text.return_value = '{"errors": [{"detail": "Rate limit exceeded"}]}'
        
        context_manager = AsyncMock()
        context_manager.__aenter__.return_value = response
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "Rate limit exceeded" in result


@pytest.mark.asyncio
class TestProviderAuthenticationErrors:
    """Test provider authentication error scenarios."""
    
    async def test_abuseipdb_invalid_key(self):
        """Test AbuseIPDB invalid API key."""
        provider = AbuseIPDB()
        provider.key = "invalid_key"
        
        session = Mock()
        response = AsyncMock()
        response.status = 401
        response.text.return_value = '{"errors": [{"detail": "Invalid API key"}]}'
        
        context_manager = AsyncMock()
        context_manager.__aenter__.return_value = response
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "Invalid API key" in result
    
    async def test_virustotal_forbidden(self):
        """Test VirusTotal forbidden access."""
        provider = VirusTotal()
        provider.key = "restricted_key"
        
        session = Mock()
        response = AsyncMock()
        response.status = 403
        response.text.return_value = '{"error": {"code": "ForbiddenError"}}'
        
        context_manager = AsyncMock()
        context_manager.__aenter__.return_value = response
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "ForbiddenError" in result
    
    async def test_otx_unauthorized(self):
        """Test OTX unauthorized access."""
        provider = OTX()
        provider.key = "bad_key"
        
        session = Mock()
        response = AsyncMock()
        response.status = 401
        response.text.return_value = '{"detail": "Authentication credentials were not provided"}'
        
        context_manager = AsyncMock()
        context_manager.__aenter__.return_value = response
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "Authentication credentials" in result


@pytest.mark.asyncio
class TestProviderSpecificErrors:
    """Test provider-specific error conditions."""
    
    async def test_greynoise_no_key(self):
        """Test GreyNoise with no API key."""
        provider = GreyNoise()
        provider.key = None
        
        session = Mock()
        result = await provider.query(session, "ip", "8.8.8.8")
        assert result == "nokey"
    
    async def test_pulsedive_no_key(self):
        """Test Pulsedive with no API key."""
        provider = Pulsedive()
        provider.key = None
        
        session = Mock()
        result = await provider.query(session, "ip", "8.8.8.8")
        assert result == "nokey"
    
    async def test_shodan_no_key(self):
        """Test Shodan with no API key."""
        provider = Shodan()
        provider.key = None
        
        session = Mock()
        result = await provider.query(session, "ip", "8.8.8.8")
        assert result == "nokey"
    
    async def test_provider_unsupported_ioc_type(self):
        """Test provider with unsupported IOC type."""
        provider = AbuseIPDB()  # Only supports IP
        provider.key = "test_key"
        
        session = Mock()
        # Should not be called since IP provider doesn't support domains
        result = await provider.query(session, "email", "test@example.com")
        # This test depends on how the provider handles unsupported types
        # For now, we expect it to try anyway and likely fail


@pytest.mark.asyncio
class TestNetworkEdgeCases:
    """Test network-related edge cases."""
    
    async def test_partial_response_read(self):
        """Test handling of partial response reads."""
        provider = AbuseIPDB()
        provider.key = "test_key"
        
        session = Mock()
        response = AsyncMock()
        response.text.side_effect = aiohttp.ClientPayloadError("Incomplete read")
        
        context_manager = AsyncMock()
        context_manager.__aenter__.return_value = response
        session.get.return_value = context_manager
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "error:" in result
    
    async def test_connection_reset(self):
        """Test connection reset during request."""
        provider = VirusTotal()
        provider.key = "test_key"
        
        session = Mock()
        session.get.side_effect = aiohttp.ClientOSError("Connection reset by peer")
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "error:" in result
    
    async def test_too_many_redirects(self):
        """Test too many redirects error."""
        provider = OTX()
        provider.key = "test_key"
        
        session = Mock()
        session.get.side_effect = aiohttp.TooManyRedirects("Too many redirects")
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "error:" in result


@pytest.mark.asyncio
class TestProviderKeyExtraction:
    """Test provider API key extraction edge cases."""
    
    def test_ip_extraction_edge_cases(self):
        """Test IP extraction from various formats."""
        from providers import _extract_ip
        
        # Test normal IP
        assert _extract_ip("8.8.8.8") == "8.8.8.8"
        
        # Test IP with port
        assert _extract_ip("8.8.8.8:53") == "8.8.8.8"
        
        # Test IPv6 
        assert _extract_ip("2001:db8::1") == "2001:db8::1"
        
        # Test IPv6 with brackets and port
        assert _extract_ip("[2001:db8::1]:80") == "2001:db8::1"
        
        # Test malformed input
        assert _extract_ip("not.an.ip") == "not.an.ip"
        
        # Test empty string
        assert _extract_ip("") == ""
    
    def test_key_retrieval_edge_cases(self):
        """Test API key retrieval edge cases."""
        from providers import _key
        
        with patch('os.getenv') as mock_getenv:
            # Test missing key
            mock_getenv.return_value = None
            assert _key("NONEXISTENT_KEY") is None
            
            # Test empty key
            mock_getenv.return_value = ""
            assert _key("EMPTY_KEY") is None
            
            # Test whitespace-only key
            mock_getenv.return_value = "   "
            assert _key("WHITESPACE_KEY") is None
            
            # Test valid key with whitespace
            mock_getenv.return_value = "  valid_key  "
            assert _key("VALID_KEY") == "valid_key"


if __name__ == "__main__":
    pytest.main([__file__])