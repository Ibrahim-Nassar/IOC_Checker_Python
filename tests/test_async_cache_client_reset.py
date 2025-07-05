"""Test that _get_client() returns new client after previous one is closed."""
import asyncio
import pytest
import sys
import os

# Add the parent directory to the path so we can import from IOC_Checker_Python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from async_cache import _get_client, _LOOP_CLIENTS, _GLOBAL_CLIENT


class TestAsyncCacheClientReset:
    """Test client reset functionality."""
    
    @pytest.mark.asyncio
    async def test_client_reset_after_close(self):
        """Test that _get_client() returns new client after previous one is closed."""
        # Get initial client
        client1 = _get_client()
        assert client1 is not None
        assert not client1.is_closed
        
        # Close the client
        await client1.aclose()
        assert client1.is_closed
        
        # Get client again - should be a new instance
        client2 = _get_client()
        assert client2 is not None
        assert not client2.is_closed
        assert client2 is not client1  # Different instance
        
        # Clean up
        await client2.aclose()
    
    @pytest.mark.asyncio
    async def test_per_loop_client_reset(self):
        """Test that per-loop clients are properly reset when closed."""
        loop = asyncio.get_running_loop()
        
        # Get initial client
        client1 = _get_client()
        assert client1 is not None
        assert not client1.is_closed
        
        # Verify it's stored in the loop clients
        assert loop in _LOOP_CLIENTS
        assert _LOOP_CLIENTS[loop] is client1
        
        # Close the client
        await client1.aclose()
        assert client1.is_closed
        
        # Get client again - should be a new instance
        client2 = _get_client()
        assert client2 is not None
        assert not client2.is_closed
        assert client2 is not client1  # Different instance
        
        # Verify the new client is stored in the loop clients
        assert loop in _LOOP_CLIENTS
        assert _LOOP_CLIENTS[loop] is client2
        
        # Clean up
        await client2.aclose()
    
    @pytest.mark.asyncio
    async def test_global_client_reset_no_loop(self):
        """Test global client reset when no event loop is running."""
        # This test is tricky since we're already in an async context
        # We'll simulate the global client scenario by testing the fallback path
        
        # Store original global client
        global _GLOBAL_CLIENT
        original_global = _GLOBAL_CLIENT
        
        try:
            # Set global client to None to test creation
            _GLOBAL_CLIENT = None
            
            # Get client (should create new global since we're testing fallback)
            client = _get_client()
            assert client is not None
            assert not client.is_closed
            
            # Clean up
            await client.aclose()
            
        finally:
            # Restore original global client
            _GLOBAL_CLIENT = original_global 