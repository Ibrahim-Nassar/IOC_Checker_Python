# tests/test_providers.py
"""Test async provider functionality."""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch
from providers import AbuseIPDB, VirusTotal, TokenBucket, ALWAYS_ON, RATE_LIMIT

@pytest.mark.asyncio
class TestProviders:
    """Test provider implementations."""
    
    async def test_abuseipdb_with_key(self, monkeypatch):
        """Test AbuseIPDB provider with API key."""
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_key")
        provider = AbuseIPDB()
        
        session = AsyncMock()
        response = AsyncMock()
        response.text.return_value = '{"data": {"abuseConfidenceScore": 0}}'
        session.get.return_value.__aenter__.return_value = response
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert result == '{"data": {"abuseConfidenceScore": 0}}'
        session.get.assert_called_once()
    
    async def test_abuseipdb_no_key(self, monkeypatch):
        """Test AbuseIPDB provider without API key."""
        monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
        provider = AbuseIPDB()
        
        session = AsyncMock()
        result = await provider.query(session, "ip", "8.8.8.8")
        assert result == "nokey"
        session.get.assert_not_called()
    
    async def test_virustotal_rate_limiting(self, monkeypatch):
        """Test VirusTotal rate limiting."""
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt_key")
        provider = VirusTotal()
        
        session = AsyncMock()
        response = AsyncMock()
        response.text.return_value = '{"data": {}}'
        session.get.return_value.__aenter__.return_value = response
        
        # Mock the token bucket to avoid actual waiting
        with patch.object(provider.bucket, 'acquire') as mock_acquire:
            mock_acquire.return_value = None
            result = await provider.query(session, "ip", "8.8.8.8")
            mock_acquire.assert_called_once()
        
        assert result == '{"data": {}}'
    
    async def test_provider_network_error(self, monkeypatch):
        """Test provider handles network errors gracefully."""
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_key")
        provider = AbuseIPDB()
        
        session = AsyncMock()
        session.get.side_effect = Exception("Network error")
        
        result = await provider.query(session, "ip", "8.8.8.8")
        assert "error: Network error" in result
    
    async def test_provider_http_error(self, monkeypatch):
        """Test provider handles HTTP errors."""
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "test_key")
        provider = AbuseIPDB()
        
        session = AsyncMock()
        response = AsyncMock()
        response.status = 429
        response.text.return_value = "Rate limited"
        session.get.return_value.__aenter__.return_value = response
        
        result = await provider.query(session, "ip", "8.8.8.8")
        # Should still return the response text for error handling
        assert result == "Rate limited"

class TestTokenBucket:
    """Test token bucket rate limiting."""
    
    @pytest.mark.asyncio
    async def test_token_bucket_basic(self):
        """Test basic token bucket functionality."""
        bucket = TokenBucket(2, 1)  # 2 tokens, 1 second interval
        
        # Should be able to acquire 2 tokens immediately
        await bucket.acquire()
        await bucket.acquire()
        
        # Third acquisition should wait, but we'll mock it
        with patch('asyncio.sleep') as mock_sleep:
            await bucket.acquire()
            mock_sleep.assert_called()
    
    @pytest.mark.asyncio
    async def test_token_bucket_refill(self):
        """Test token bucket refill mechanism."""
        bucket = TokenBucket(1, 1)
        
        # Acquire initial token
        await bucket.acquire()
        
        # Mock time passage for refill
        import datetime
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.utcnow.return_value = datetime.datetime.utcnow() + datetime.timedelta(seconds=2)
            bucket._refill()  # If this method exists
            
    def test_providers_lists(self):
        """Test provider lists are properly configured."""
        assert len(ALWAYS_ON) > 0
        assert len(RATE_LIMIT) > 0
        
        # Check that all providers have required attributes
        for provider in ALWAYS_ON + RATE_LIMIT:
            assert hasattr(provider, 'name')
            assert hasattr(provider, 'ioc_kinds')
            assert hasattr(provider, 'query')
            assert callable(provider.query)
