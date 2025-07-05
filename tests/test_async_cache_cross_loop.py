"""
Tests for cross-loop cleanup in async_cache module.
"""

import pytest
import asyncio
import threading
import time
from unittest.mock import patch

from async_cache import _get_client, _close_all_clients, _LOOP_CLIENTS


class TestAsyncCacheCrossLoop:
    """Test async_cache cross-loop handling."""
    
    def test_cross_loop_cleanup(self):
        """Test that _close_all_clients handles cross-loop cleanup without RuntimeError."""
        # Clear any existing clients
        _LOOP_CLIENTS.clear()
        
        clients_created = []
        loops_created = []
        
        def create_client_in_loop():
            """Create a client in a separate event loop."""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loops_created.append(loop)
            
            try:
                # Create a client in this loop
                client = _get_client()
                clients_created.append(client)
                
                # Run the loop briefly to ensure client is properly initialized
                loop.run_until_complete(asyncio.sleep(0.1))
                
            finally:
                # Stop the loop but don't close it yet
                loop.stop()
        
        # Create clients in two different loops
        thread1 = threading.Thread(target=create_client_in_loop)
        thread2 = threading.Thread(target=create_client_in_loop)
        
        thread1.start()
        thread2.start()
        
        thread1.join()
        thread2.join()
        
        # Verify we created clients in different loops
        assert len(clients_created) == 2
        assert len(loops_created) == 2
        assert loops_created[0] != loops_created[1]
        
        # Now close the loops to simulate the original issue
        for loop in loops_created:
            if not loop.is_closed():
                loop.close()
        
        # This should not raise RuntimeError even though the original loops are closed
        try:
            _close_all_clients()
        except RuntimeError as e:
            pytest.fail(f"_close_all_clients() raised RuntimeError: {e}")
        
        # Verify all clients are closed
        for client in clients_created:
            assert client.is_closed, "Client should be closed after cleanup"
    
    def test_client_creation_requires_loop(self):
        """Test that _get_client requires a running event loop."""
        # Clear any existing clients
        _LOOP_CLIENTS.clear()
        
        # Should raise RuntimeError when no loop is running
        with pytest.raises(RuntimeError, match="AsyncClient requires a running event loop"):
            _get_client()
    
    def test_same_loop_client_reuse(self):
        """Test that clients are reused within the same loop."""
        
        async def test_client_reuse():
            # Clear any existing clients
            _LOOP_CLIENTS.clear()
            
            client1 = _get_client()
            client2 = _get_client()
            
            # Should be the same client instance
            assert client1 is client2
            
            # Should be stored with the correct loop
            current_loop = asyncio.get_running_loop()
            assert current_loop in _LOOP_CLIENTS
            stored_client, stored_loop = _LOOP_CLIENTS[current_loop]
            assert stored_client is client1
            assert stored_loop is current_loop
        
        # Run the test
        asyncio.run(test_client_reuse())
    
    def test_cross_loop_client_isolation(self):
        """Test that different loops get different clients."""
        clients = []
        
        async def get_client_in_loop():
            client = _get_client()
            clients.append(client)
            return client
        
        # Create clients in different loops
        client1 = asyncio.run(get_client_in_loop())
        client2 = asyncio.run(get_client_in_loop())
        
        # Should be different clients
        assert client1 is not client2
        assert len(clients) == 2
    
    def test_closed_client_recreation(self):
        """Test that closed clients are recreated."""
        
        async def test_client_recreation():
            # Clear any existing clients
            _LOOP_CLIENTS.clear()
            
            client1 = _get_client()
            
            # Close the client
            await client1.aclose()
            
            # Getting client again should create a new one
            client2 = _get_client()
            
            # Should be different clients
            assert client1 is not client2
            assert client1.is_closed
            assert not client2.is_closed
        
        # Run the test
        asyncio.run(test_client_recreation())
    
    def test_cleanup_with_mixed_loop_states(self):
        """Test cleanup with a mix of running, stopped, and closed loops."""
        # Clear any existing clients
        _LOOP_CLIENTS.clear()
        
        clients_and_loops = []
        
        def create_client_in_loop(loop_action):
            """Create a client and perform specified action on loop."""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                client = _get_client()
                clients_and_loops.append((client, loop))
                
                # Run briefly to initialize
                loop.run_until_complete(asyncio.sleep(0.1))
                
                if loop_action == "close":
                    loop.close()
                elif loop_action == "stop":
                    loop.stop()
                # "keep" means leave running
                
            except:
                if not loop.is_closed():
                    loop.close()
                raise
        
        # Create clients with different loop states
        threads = []
        for action in ["close", "stop", "keep"]:
            thread = threading.Thread(target=create_client_in_loop, args=(action,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Verify we have 3 clients
        assert len(clients_and_loops) == 3
        
        # Cleanup should handle all states gracefully
        try:
            _close_all_clients()
        except RuntimeError as e:
            pytest.fail(f"_close_all_clients() raised RuntimeError with mixed loop states: {e}")
        
        # Clean up any remaining open loops
        for client, loop in clients_and_loops:
            if not loop.is_closed():
                loop.close()


if __name__ == "__main__":
    pytest.main([__file__]) 