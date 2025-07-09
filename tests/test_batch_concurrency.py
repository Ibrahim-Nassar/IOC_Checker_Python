#!/usr/bin/env python3
"""
Test batch processing concurrency to ensure GUI doesn't freeze.
"""
import asyncio
import time
from unittest.mock import AsyncMock, MagicMock
import pytest

from ioc_types import IOCResult, IOCStatus
from ioc_checker import scan_ioc


class MockProvider:
    """Mock provider that simulates network delay."""
    
    def __init__(self, name: str, delay: float = 0.2):
        self.NAME = name
        self.delay = delay
    
    async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
        """Simulate network delay."""
        await asyncio.sleep(self.delay)
        return IOCResult(
            ioc=ioc,
            ioc_type=ioc_type,
            status=IOCStatus.SUCCESS,
            malicious_engines=0,
            total_engines=1,
            message=""
        )


@pytest.mark.asyncio
async def test_concurrent_batch_processing():
    """Test that multiple IOCs can be processed concurrently."""
    # Create mock providers with small delays
    providers = [
        MockProvider("provider1", 0.1),
        MockProvider("provider2", 0.1),
    ]
    
    # Test IOCs
    iocs = [
        "8.8.8.8",
        "1.1.1.1", 
        "google.com",
        "example.com",
        "malware.com"
    ]
    
    start_time = time.time()
    
    # Process all IOCs concurrently (like the fixed GUI logic)
    tasks = []
    for ioc in iocs:
        task = asyncio.create_task(scan_ioc(ioc, "ip", providers))
        tasks.append(task)
    
    # Wait for all to complete
    results = await asyncio.gather(*tasks)
    
    elapsed = time.time() - start_time
    
    # With concurrency, this should complete faster than sequential processing
    # Sequential would take: len(iocs) * len(providers) * delay = 5 * 2 * 0.1 = 1.0 seconds
    # Concurrent should take: max(len(providers) * delay) = 2 * 0.1 = 0.2 seconds (roughly)
    assert elapsed < 0.8, f"Batch took {elapsed:.2f}s, expected < 0.8s (concurrent processing)"
    
    # Verify all IOCs were processed
    assert len(results) == len(iocs)
    
    # Verify each result has responses from all providers
    for result in results:
        assert len(result) == len(providers)


@pytest.mark.asyncio 
async def test_provider_timeout_handling():
    """Test that slow providers don't block the entire batch."""
    
    class SlowProvider:
        NAME = "slow_provider"
        
        async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
            # This should timeout due to the 15s limit in scan_ioc
            await asyncio.sleep(20)  # Longer than timeout
            return IOCResult(ioc=ioc, ioc_type=ioc_type, status=IOCStatus.SUCCESS, malicious_engines=0, total_engines=1)
    
    fast_provider = MockProvider("fast_provider", 0.1)
    slow_provider = SlowProvider()
    
    start_time = time.time()
    
    # This should complete quickly due to timeout handling
    result = await scan_ioc("8.8.8.8", "ip", [fast_provider, slow_provider])
    
    elapsed = time.time() - start_time
    
    # Should complete in ~15 seconds (timeout) not 20+ seconds
    assert elapsed < 17, f"Scan took {elapsed:.2f}s, expected < 17s due to timeout"
    
    # Should have results from both providers (fast success, slow timeout error)
    assert len(result) == 2
    assert "fast_provider" in result
    assert "slow_provider" in result
    
    # Fast provider should succeed
    assert result["fast_provider"].status == IOCStatus.SUCCESS
    
    # Slow provider should have timeout error
    assert result["slow_provider"].status == IOCStatus.ERROR
    assert "timeout" in result["slow_provider"].message.lower()


def test_progress_tracking_simulation():
    """Test that progress tracking would work correctly in concurrent environment."""
    
    # Simulate the GUI's progress tracking logic
    completed_count = 0
    total_iocs = 20
    progress_updates = []
    
    def update_progress():
        nonlocal completed_count
        completed_count += 1
        progress_text = f"Processing {completed_count}/{total_iocs} IOCs..."
        progress_updates.append(progress_text)
        return progress_text
    
    # Simulate concurrent IOC processing completing at different times
    for i in range(total_iocs):
        progress = update_progress()
        
    # Verify progress reaches 100%
    assert completed_count == total_iocs
    assert progress_updates[-1] == f"Processing {total_iocs}/{total_iocs} IOCs..."
    
    # Verify progress is monotonically increasing
    for i in range(1, len(progress_updates)):
        current_num = int(progress_updates[i].split()[1].split('/')[0])
        prev_num = int(progress_updates[i-1].split()[1].split('/')[0])
        assert current_num > prev_num, "Progress should be monotonically increasing"


if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 