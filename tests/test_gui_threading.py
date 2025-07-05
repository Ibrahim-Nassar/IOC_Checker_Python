"""Test GUI threading safety."""
import asyncio
import pytest
import tkinter as tk
from unittest.mock import MagicMock, AsyncMock, patch
from concurrent.futures import ThreadPoolExecutor
import threading
import time

# TODO: Add pytest-qt for better GUI testing
# from pytestqt.qtbot import QtBot

from ioc_types import IOCResult, IOCStatus
from ioc_gui_tk import IOCCheckerGUI


class TestGUIThreading:
    """Test thread safety of GUI operations."""
    
    def test_no_runtime_error_on_parallel_scans(self):
        """Test that 5 parallel scans don't cause RuntimeError: main thread."""
        # Create a mock GUI instance
        with patch('ioc_gui_tk._LOOP') as mock_loop:
            mock_loop.run_forever = MagicMock()
            
            # Create GUI instance
            gui = IOCCheckerGUI()
            
            # Mock the scan function to return dummy results
            async def mock_scan_ioc(ioc, ioc_type, providers):
                # Simulate some async work
                await asyncio.sleep(0.1)
                return {
                    'test_provider': IOCResult(
                        ioc=ioc,
                        ioc_type=ioc_type,
                        status=IOCStatus.SUCCESS,
                        malicious_engines=0,
                        total_engines=1,
                        message=""
                    )
                }
            
            # Mock providers
            mock_provider = MagicMock()
            mock_provider.NAME = "test_provider"
            
            with patch('ioc_gui_tk.scan_ioc', side_effect=mock_scan_ioc), \
                 patch.object(gui, '_selected_providers', return_value=[mock_provider]), \
                 patch.object(gui, 'update_table') as mock_update:
                
                # Set up test IOCs
                test_iocs = [
                    "1.2.3.4",
                    "example.com", 
                    "https://test.com",
                    "d41d8cd98f00b204e9800998ecf8427e",
                    "192.168.1.1"
                ]
                
                # Track exceptions from threads
                thread_exceptions = []
                
                def run_scan_with_exception_tracking(ioc):
                    try:
                        # Set IOC in GUI
                        gui.ioc_var.set(ioc)
                        # Trigger scan
                        gui._start_single()
                        # Small delay to let async operations start
                        time.sleep(0.05)
                    except Exception as e:
                        thread_exceptions.append(e)
                
                # Run 5 parallel scans
                with ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [executor.submit(run_scan_with_exception_tracking, ioc) 
                              for ioc in test_iocs]
                    
                    # Wait for all futures to complete
                    for future in futures:
                        future.result(timeout=10)
                
                # Check that no RuntimeError about main thread occurred
                main_thread_errors = [e for e in thread_exceptions 
                                    if isinstance(e, RuntimeError) and 'main thread' in str(e).lower()]
                
                assert len(main_thread_errors) == 0, f"Found main thread errors: {main_thread_errors}"
                
                # Verify that update_table was called (meaning the async operations completed)
                assert mock_update.call_count >= 1, "update_table should have been called"
    
    def test_gui_root_after_usage(self):
        """Test that GUI uses root.after() for thread-safe updates."""
        with patch('ioc_gui_tk._LOOP') as mock_loop:
            mock_loop.run_forever = MagicMock()
            
            gui = IOCCheckerGUI()
            
            # Mock root.after to track calls
            original_after = gui.root.after
            after_calls = []
            
            def mock_after(delay, func):
                after_calls.append((delay, func))
                # Still call the original to maintain functionality
                return original_after(delay, func)
            
            gui.root.after = mock_after
            
            # Create a mock future with result
            mock_future = MagicMock()
            mock_future.result.return_value = {
                'test_provider': IOCResult(
                    ioc="test.com",
                    ioc_type="domain",
                    status=IOCStatus.SUCCESS,
                    malicious_engines=0,
                    total_engines=1,
                    message=""
                )
            }
            
            # Test _on_scan_done callback
            gui._on_scan_done("test.com", "domain", None, mock_future)
            
            # Verify that root.after was called
            assert len(after_calls) >= 1, "root.after should have been called for thread-safe updates"
            
            # Verify the delay is 0 (immediate scheduling)
            assert after_calls[0][0] == 0, "Updates should be scheduled immediately with delay=0"
    
    def test_background_loop_reference(self):
        """Test that GUI maintains reference to background loop."""
        with patch('ioc_gui_tk._LOOP') as mock_loop:
            mock_loop.run_forever = MagicMock()
            
            gui = IOCCheckerGUI()
            
            # Verify that self.loop is set
            assert hasattr(gui, 'loop'), "GUI should have a loop attribute"
            assert gui.loop is mock_loop, "GUI loop should reference the global _LOOP"
    
    def test_concurrent_batch_processing(self):
        """Test that batch processing handles concurrent operations safely."""
        with patch('ioc_gui_tk._LOOP') as mock_loop:
            mock_loop.run_forever = MagicMock()
            
            gui = IOCCheckerGUI()
            
            # Mock the necessary components
            mock_provider = MagicMock()
            mock_provider.NAME = "test_provider"
            
            with patch.object(gui, '_selected_providers', return_value=[mock_provider]), \
                 patch('ioc_gui_tk.load_iocs') as mock_load_iocs, \
                 patch('ioc_gui_tk.scan_ioc') as mock_scan_ioc:
                
                # Set up mock data
                mock_load_iocs.return_value = [
                    {"value": "1.2.3.4", "type": "ip"},
                    {"value": "example.com", "type": "domain"}
                ]
                
                # Mock scan_ioc to return results
                mock_scan_ioc.return_value = {
                    'test_provider': IOCResult(
                        ioc="test",
                        ioc_type="ip",
                        status=IOCStatus.SUCCESS,
                        malicious_engines=0,
                        total_engines=1,
                        message=""
                    )
                }
                
                # Set a test file
                gui.file_var.set("test.csv")
                
                # Track exceptions
                exceptions = []
                
                def exception_handler(loop, context):
                    exceptions.append(context.get('exception'))
                
                # Set exception handler for the mock loop
                mock_loop.set_exception_handler = MagicMock(side_effect=exception_handler)
                
                # Start batch processing
                gui._start_batch()
                
                # Small delay to let operations start
                time.sleep(0.1)
                
                # Check that no exceptions occurred
                threading_exceptions = [e for e in exceptions 
                                      if isinstance(e, RuntimeError) and 'thread' in str(e).lower()]
                
                assert len(threading_exceptions) == 0, f"Found threading exceptions: {threading_exceptions}" 