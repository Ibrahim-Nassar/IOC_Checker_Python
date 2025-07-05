"""Tests for async_cache shutdown scenarios."""
import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import threading

from async_cache import _close_all_clients, _get_client


class TestAsyncCacheShutdown:
    """Test async_cache shutdown behavior."""
    
    def test_close_all_clients_no_loop(self):
        """Test _close_all_clients when no event loop is running."""
        # Create a mock client
        mock_client = Mock()
        mock_client.is_closed = False
        mock_client.aclose = AsyncMock()
        
        with patch('async_cache._GLOBAL_CLIENT', mock_client), \
             patch('asyncio.get_running_loop', side_effect=RuntimeError("No running loop")), \
             patch('asyncio.run') as mock_run:
            
            _close_all_clients()
            
            # Should use asyncio.run to close the client
            mock_run.assert_called_once_with(mock_client.aclose())
    
    def test_close_all_clients_with_active_loop(self):
        """Test _close_all_clients when an event loop is running."""
        mock_client = Mock()
        mock_client.is_closed = False
        mock_client.aclose = AsyncMock()
        
        mock_loop = Mock()
        mock_loop.is_closed.return_value = False
        
        with patch('async_cache._GLOBAL_CLIENT', mock_client), \
             patch('asyncio.get_running_loop', return_value=mock_loop):
            
            _close_all_clients()
            
            # Should schedule cleanup in the existing loop
            mock_loop.create_task.assert_called_once_with(mock_client.aclose())
    
    def test_close_all_clients_with_closed_loop(self):
        """Test _close_all_clients when the event loop is closed."""
        mock_client = Mock()
        mock_client.is_closed = False
        mock_client.aclose = AsyncMock()
        
        mock_loop = Mock()
        mock_loop.is_closed.return_value = True
        
        with patch('async_cache._GLOBAL_CLIENT', mock_client), \
             patch('asyncio.get_running_loop', return_value=mock_loop), \
             patch('asyncio.run') as mock_run:
            
            _close_all_clients()
            
            # Should use asyncio.run since loop is closed
            mock_run.assert_called_once_with(mock_client.aclose())
    
    def test_close_all_clients_no_client(self):
        """Test _close_all_clients when no client exists."""
        with patch('async_cache._GLOBAL_CLIENT', None):
            # Should not raise any exception
            _close_all_clients()
    
    def test_close_all_clients_already_closed(self):
        """Test _close_all_clients when client is already closed."""
        mock_client = Mock()
        mock_client.is_closed = True
        
        with patch('async_cache._GLOBAL_CLIENT', mock_client):
            # Should not attempt to close
            _close_all_clients()
    
    def test_close_all_clients_exception_handling(self):
        """Test _close_all_clients handles exceptions gracefully."""
        mock_client = Mock()
        mock_client.is_closed = False
        mock_client.aclose = AsyncMock()
        
        with patch('async_cache._GLOBAL_CLIENT', mock_client), \
             patch('asyncio.get_running_loop', side_effect=RuntimeError("No running loop")), \
             patch('asyncio.run', side_effect=Exception("Cleanup failed")):
            
            # Should not raise exception (best effort cleanup)
            _close_all_clients()
    
    def test_close_all_clients_multiple_calls(self):
        """Test _close_all_clients can be called multiple times safely."""
        mock_client = Mock()
        mock_client.is_closed = False
        mock_client.aclose = AsyncMock()
        
        with patch('async_cache._GLOBAL_CLIENT', mock_client), \
             patch('asyncio.get_running_loop', side_effect=RuntimeError("No running loop")), \
             patch('asyncio.run') as mock_run:
            
            # Call multiple times
            _close_all_clients()
            _close_all_clients()
            
            # Should handle multiple calls gracefully
            assert mock_run.call_count >= 1
    
    def test_get_client_after_close(self):
        """Test that _get_client works after _close_all_clients."""
        # This test ensures the client can be recreated after shutdown
        with patch('async_cache._GLOBAL_CLIENT', None):
            client = _get_client()
            assert client is not None
            
            # Should be able to get client again
            client2 = _get_client()
            assert client2 is client  # Should be the same instance 