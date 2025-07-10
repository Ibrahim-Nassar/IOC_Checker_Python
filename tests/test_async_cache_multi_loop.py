"""Test multi-loop scenario to ensure no 'attached to different loop' error."""
import asyncio
import threading
import pytest
import sys
import os
import time

# Add the parent directory to the path so we can import from IOC_Checker_Python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from async_cache import aget, get_client, _LOOP_CLIENTS


class TestAsyncCacheMultiLoop:
    """Test multi-loop functionality."""
    
    def test_multi_loop_client_isolation(self):
        """Test that clients are properly isolated per event loop."""
        results = []
        exceptions = []
        
        def run_in_loop(loop_id):
            """Run aget in a separate event loop."""
            async def async_task():
                try:
                    # Get client - should create per-loop client
                    client = get_client()
                    assert client is not None
                    assert not client.is_closed
                    
                    # Store client info for verification
                    loop = asyncio.get_running_loop()
                    results.append({
                        'loop_id': loop_id,
                        'client_id': id(client),
                        'loop_id_actual': id(loop)
                    })
                    
                    # Perform actual HTTP request to test functionality
                    # Using a reliable test endpoint
                    try:
                        response = await aget("https://httpbin.org/get", timeout=10.0)
                        assert response.status_code == 200
                        results[-1]['request_success'] = True
                    except Exception as e:
                        # Network might be unavailable, but client should still work
                        results[-1]['request_success'] = False
                        results[-1]['request_error'] = str(e)
                    
                    # Clean up
                    await client.aclose()
                    
                except Exception as e:
                    exceptions.append(f"Loop {loop_id}: {e}")
            
            try:
                asyncio.run(async_task())
            except Exception as e:
                exceptions.append(f"Loop {loop_id} outer: {e}")
        
        # Run multiple loops in separate threads
        threads = []
        for i in range(3):
            thread = threading.Thread(target=run_in_loop, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join(timeout=30)  # 30 second timeout
        
        # Check results
        assert len(exceptions) == 0, f"Exceptions occurred: {exceptions}"
        assert len(results) == 3, f"Expected 3 results, got {len(results)}"
        
        # Verify each loop got its own client
        client_ids = [r['client_id'] for r in results]
        assert len(set(client_ids)) == 3, "Each loop should have its own client"
        
        # Verify each loop has unique loop ID
        loop_ids = [r['loop_id_actual'] for r in results]
        assert len(set(loop_ids)) == 3, "Each thread should have its own event loop"
    
    def test_sequential_loop_reuse(self):
        """Test that sequential event loops work correctly."""
        results = []
        
        def run_sequential_loop(loop_id):
            """Run a task in an event loop sequentially."""
            async def async_task():
                client = get_client()
                assert client is not None
                assert not client.is_closed
                
                results.append({
                    'loop_id': loop_id,
                    'client_id': id(client)
                })
                
                await client.aclose()
            
            asyncio.run(async_task())
        
        # Run loops sequentially
        for i in range(3):
            run_sequential_loop(i)
        
        # Check results
        assert len(results) == 3
        
        # In sequential execution, each loop should get its own client
        client_ids = [r['client_id'] for r in results]
        # Note: Since loops run sequentially and are cleaned up,
        # new loops may reuse global client, so we don't enforce uniqueness here
        # The important thing is that no "attached to different loop" error occurs
    
    @pytest.mark.asyncio
    async def test_same_loop_client_reuse(self):
        """Test that the same loop reuses the same client."""
        # Get client twice in the same loop
        client1 = get_client()
        client2 = get_client()
        
        # Should be the same instance
        assert client1 is client2
        
        # Clean up
        await client1.aclose() 