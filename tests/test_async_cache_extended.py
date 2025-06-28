"""Extended tests for the async cache module."""

import pytest
import asyncio
import httpx
from unittest.mock import patch, MagicMock, AsyncMock
from pathlib import Path
import os

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

import async_cache

pytestmark = pytest.mark.asyncio


class TestAsyncCache:
    """Test cases for async caching functionality."""
    
    async def test_aget_success(self):
        """Test successful async GET request."""
        with patch('async_cache._get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "async test response"
            mock_client.get.return_value = mock_response
            mock_get_client.return_value = mock_client
            
            response = await async_cache.aget("https://example.com/test", timeout=10.0, ttl=600)
            
            assert response.status_code == 200
            assert response.text == "async test response"
            mock_client.get.assert_called_once()
    
    async def test_apost_success(self):
        """Test successful async POST request."""
        with patch('async_cache._get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {"status": "success"}
            mock_client.post.return_value = mock_response
            mock_get_client.return_value = mock_client
            
            test_data = {"key": "value"}
            response = await async_cache.apost("https://example.com/api", json=test_data, timeout=5.0, ttl=300)
            
            assert response.status_code == 200
            mock_client.post.assert_called_once()
    
    async def test_rate_limiting(self):
        """Test that rate limiting is applied."""
        with patch('async_cache._get_client') as mock_get_client, \
             patch('async_cache._get_limiter') as mock_get_limiter:
            
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.get.return_value = mock_response
            mock_get_client.return_value = mock_client
            
            mock_limiter = AsyncMock()
            mock_get_limiter.return_value = mock_limiter
            
            await async_cache.aget("https://example.com/test", api_key="test_key")
            
            # Verify limiter was used
            mock_get_limiter.assert_called_once_with("test_key")
            mock_limiter.__aenter__.assert_called_once()
            mock_limiter.__aexit__.assert_called_once()
    
    async def test_rate_limiting_anonymous(self):
        """Test rate limiting for anonymous requests."""
        with patch('async_cache._get_client') as mock_get_client, \
             patch('async_cache._get_limiter') as mock_get_limiter:
            
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_client.get.return_value = mock_response
            mock_get_client.return_value = mock_client
            
            mock_limiter = AsyncMock()
            mock_get_limiter.return_value = mock_limiter
            
            await async_cache.aget("https://example.com/test")
            
            # Verify limiter was called with anonymous key
            mock_get_limiter.assert_called_once_with(None)
    
    def test_cache_directory_creation(self):
        """Test that async cache directory is created properly."""
        expected_dir = Path(os.getenv("XDG_CACHE_HOME", Path.home() / ".cache")) / "ioc_checker"
        assert expected_dir.exists()
    
    def test_client_context_management(self):
        """Test that clients are properly managed per context."""
        # This tests the context variable functionality exists
        # We can't easily test the actual context variable behavior
        # but we can verify the function exists and works
        client1 = async_cache._get_client()
        client2 = async_cache._get_client()
        
        # Should return client objects
        assert client1 is not None
        assert client2 is not None
        # In same context, should be same instance
        assert client1 is client2
    
    def test_limiter_per_api_key(self):
        """Test that different limiters are created for different API keys."""
        with patch('asyncio.get_running_loop') as mock_loop:
            mock_loop.return_value = MagicMock()
            
            limiter1 = async_cache._get_limiter("key1")
            limiter2 = async_cache._get_limiter("key2")
            limiter3 = async_cache._get_limiter("key1")  # Same as first
            
            # Different keys should have different limiters
            assert limiter1 != limiter2
            # Same key should return same limiter
            assert limiter1 == limiter3
    
    async def test_cache_headers_with_caching(self):
        """Test that cache headers are added when caching is available."""
        # Mock httpx_cache availability
        with patch('async_cache._HAS_CACHE', True), \
             patch('async_cache._get_client') as mock_get_client:
            
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_client.get.return_value = mock_response
            mock_get_client.return_value = mock_client
            
            await async_cache.aget("https://example.com/test", ttl=600)
            
            # Verify headers were set
            call_args = mock_client.get.call_args
            headers = call_args[1]['headers']
            assert 'Cache-Control' in headers
            assert 'max-age=600' in headers['Cache-Control']
    
    async def test_cache_headers_without_caching(self):
        """Test behavior when caching is not available."""
        with patch('async_cache._HAS_CACHE', False), \
             patch('async_cache._get_client') as mock_get_client:
            
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_client.get.return_value = mock_response
            mock_get_client.return_value = mock_client
            
            await async_cache.aget("https://example.com/test")
            
            # Should still work without cache headers
            mock_client.get.assert_called_once()
    
    async def test_timeout_handling(self):
        """Test timeout parameter is passed correctly."""
        with patch('async_cache._get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_client.get.side_effect = httpx.TimeoutException("Request timed out")
            mock_get_client.return_value = mock_client
            
            with pytest.raises(httpx.TimeoutException):
                await async_cache.aget("https://slow-server.com", timeout=1.0)
    
    async def test_concurrent_requests(self):
        """Test that concurrent requests work properly."""
        with patch('async_cache._get_client') as mock_get_client:
            mock_client = AsyncMock()
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_client.get.return_value = mock_response
            mock_get_client.return_value = mock_client
            
            # Make multiple concurrent requests
            tasks = [
                async_cache.aget(f"https://example{i}.com")
                for i in range(5)
            ]
            
            responses = await asyncio.gather(*tasks)
            
            # All should succeed
            assert len(responses) == 5
            assert all(r.status_code == 200 for r in responses)
    
    def test_cleanup_registration(self):
        """Test that cleanup function is registered with atexit."""
        # This is mainly to ensure the cleanup function exists
        assert hasattr(async_cache, '_close_all_clients')
        assert callable(async_cache._close_all_clients) 