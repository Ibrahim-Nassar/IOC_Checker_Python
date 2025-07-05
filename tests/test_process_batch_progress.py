"""
Tests for IOCProcessingService batch processing progress tracking.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock

from services import IOCProcessingService
from ioc_types import IOCStatus, IOCResult


class TestBatchProcessingProgress:
    """Test progress tracking in batch processing."""
    
    @pytest.fixture
    def processing_service(self):
        """Create a fresh IOCProcessingService instance."""
        return IOCProcessingService()
    
    @pytest.fixture
    def mock_providers(self):
        """Create mock providers for testing."""
        provider = MagicMock()
        provider.NAME = "test_provider"
        provider.query_ioc = AsyncMock(return_value=IOCResult(
            ioc="test",
            ioc_type="ip",
            status=IOCStatus.SUCCESS,
            malicious_engines=0,
            total_engines=1,
            message="Clean"
        ))
        return [provider]
    
    @pytest.mark.asyncio
    async def test_progress_skips_duplicates(self, processing_service, mock_providers):
        """Test that progress callback is not called for duplicate IOCs."""
        progress_calls = []
        
        def progress_callback(processed, total):
            progress_calls.append((processed, total))
        
        # Test data with duplicates
        iocs = [
            {"value": "192.168.1.1"},
            {"value": "192.168.1.2"},
            {"value": "192.168.1.1"},  # Duplicate
            {"value": "192.168.1.3"},
            {"value": "192.168.1.2"},  # Duplicate
        ]
        
        results, valid_count, invalid_count, duplicate_count = await processing_service.process_batch(
            iocs, mock_providers, progress_callback
        )
        
        # Should have processed 3 unique IOCs, found 2 duplicates
        assert valid_count == 3
        assert duplicate_count == 2
        assert len(progress_calls) == 3, f"Expected 3 progress calls, got {len(progress_calls)}"
        
        # Progress should never exceed the number of processed IOCs
        for processed, total in progress_calls:
            assert processed <= 3, f"Progress {processed} should not exceed processed count 3"
            assert total == 5, f"Total should be 5, got {total}"
        
        # Progress should be sequential: 1, 2, 3
        expected_progress = [(1, 5), (2, 5), (3, 5)]
        assert progress_calls == expected_progress, f"Expected {expected_progress}, got {progress_calls}"
    
    @pytest.mark.asyncio
    async def test_progress_with_invalid_iocs(self, processing_service, mock_providers):
        """Test progress tracking with invalid IOCs."""
        progress_calls = []
        
        def progress_callback(processed, total):
            progress_calls.append((processed, total))
        
        # Test data with invalid IOCs
        iocs = [
            {"value": "192.168.1.1"},       # Valid
            {"value": "invalid_ioc"},       # Invalid
            {"value": "192.168.1.2"},       # Valid
            {"value": ""},                  # Invalid (empty)
            {"value": "192.168.1.3"},       # Valid
        ]
        
        results, valid_count, invalid_count, duplicate_count = await processing_service.process_batch(
            iocs, mock_providers, progress_callback
        )
        
        # Should have processed all 5 IOCs (3 valid, 2 invalid)
        assert valid_count == 3
        assert invalid_count == 2
        assert duplicate_count == 0
        assert len(progress_calls) == 5, f"Expected 5 progress calls, got {len(progress_calls)}"
        
        # Progress should be sequential: 1, 2, 3, 4, 5
        expected_progress = [(1, 5), (2, 5), (3, 5), (4, 5), (5, 5)]
        assert progress_calls == expected_progress, f"Expected {expected_progress}, got {progress_calls}"
    
    @pytest.mark.asyncio
    async def test_progress_with_mixed_scenarios(self, processing_service, mock_providers):
        """Test progress tracking with mixed valid, invalid, and duplicate IOCs."""
        progress_calls = []
        
        def progress_callback(processed, total):
            progress_calls.append((processed, total))
        
        # Complex test data
        iocs = [
            {"value": "192.168.1.1"},       # Valid
            {"value": "192.168.1.1"},       # Duplicate
            {"value": "invalid_ioc"},       # Invalid
            {"value": "192.168.1.2"},       # Valid
            {"value": ""},                  # Invalid (empty)
            {"value": "192.168.1.2"},       # Duplicate
            {"value": "192.168.1.3"},       # Valid
        ]
        
        results, valid_count, invalid_count, duplicate_count = await processing_service.process_batch(
            iocs, mock_providers, progress_callback
        )
        
        # Should have processed 4 unique IOCs (3 valid, 1 invalid), found 2 duplicates  
        assert valid_count == 3
        assert invalid_count == 1
        assert duplicate_count == 2
        assert len(progress_calls) == 4, f"Expected 4 progress calls, got {len(progress_calls)}"
        
        # Progress should never exceed processed count
        for processed, total in progress_calls:
            assert processed <= 4, f"Progress {processed} should not exceed processed count 4"
            assert total == 7, f"Total should be 7, got {total}"
        
        # Progress should be sequential: 1, 2, 3, 4
        expected_progress = [(1, 7), (2, 7), (3, 7), (4, 7)]
        assert progress_calls == expected_progress, f"Expected {expected_progress}, got {progress_calls}"
    
    @pytest.mark.asyncio
    async def test_progress_percentage_never_exceeds_100(self, processing_service, mock_providers):
        """Test that progress percentage never exceeds 100%."""
        progress_calls = []
        
        def progress_callback(processed, total):
            progress_calls.append((processed, total))
            percentage = (processed / total) * 100
            assert percentage <= 100.0, f"Progress percentage {percentage}% should not exceed 100%"
        
        # Test data with many duplicates
        iocs = [
            {"value": "192.168.1.1"},       # Valid
            {"value": "192.168.1.1"},       # Duplicate
            {"value": "192.168.1.1"},       # Duplicate
            {"value": "192.168.1.1"},       # Duplicate
            {"value": "192.168.1.1"},       # Duplicate
        ]
        
        results, valid_count, invalid_count, duplicate_count = await processing_service.process_batch(
            iocs, mock_providers, progress_callback
        )
        
        # Should have processed only 1 unique IOC, found 4 duplicates
        assert valid_count == 1
        assert duplicate_count == 4
        assert len(progress_calls) == 1, f"Expected 1 progress call, got {len(progress_calls)}"
        
        # Progress should be (1, 5) = 20%
        assert progress_calls == [(1, 5)]
    
    @pytest.mark.asyncio
    async def test_no_progress_callback(self, processing_service, mock_providers):
        """Test that batch processing works without progress callback."""
        # Test data
        iocs = [
            {"value": "192.168.1.1"},
            {"value": "192.168.1.2"},
        ]
        
        # Should not raise any errors
        results, valid_count, invalid_count, duplicate_count = await processing_service.process_batch(
            iocs, mock_providers, None
        )
        
        assert valid_count == 2
        assert invalid_count == 0
        assert duplicate_count == 0


if __name__ == "__main__":
    pytest.main([__file__]) 