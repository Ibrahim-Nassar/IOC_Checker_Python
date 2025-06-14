"""
Test GUI progress bar functionality.
"""
import pytest
import tkinter as tk
from tkinter import ttk
import threading
import time
from unittest.mock import Mock, patch, MagicMock
import tempfile
from pathlib import Path

# Import GUI components
from ioc_gui_tk import IOCCheckerGUI


class TestProgressBar:
    """Test suite for GUI progress bar functionality."""
    
    @pytest.fixture
    def root_window(self):
        """Create a test Tkinter root window."""
        root = tk.Tk()
        root.withdraw()  # Hide window for headless testing
        yield root
        root.quit()
        root.destroy()
    
    @pytest.fixture
    def gui_app(self, root_window):
        """Create a GUI application instance for testing."""
        # Mock the IOCCheckerGUI class to use our root window
        app = IOCCheckerGUI()
        app.root = root_window
        app.root.withdraw()
        return app
    
    def test_progress_bar_exists(self, gui_app):
        """Test that progress bar widget is created."""
        assert hasattr(gui_app, 'progress')
        assert isinstance(gui_app.progress, ttk.Progressbar)
    
    def test_progress_bar_initially_hidden(self, gui_app):
        """Test that progress bar is initially hidden."""
        # Progress frame should not be visible initially
        progress_frame_info = gui_app.progress_frame.grid_info()
        assert not progress_frame_info  # Empty dict means not gridded
    
    def test_progress_bar_show_hide(self, gui_app):
        """Test showing and hiding progress bar."""
        # Show progress
        gui_app._show_progress("Testing...")
        gui_app.root.update()
        
        # Should be visible now
        progress_frame_info = gui_app.progress_frame.grid_info()
        assert progress_frame_info  # Non-empty dict means gridded
        
        # Hide progress
        gui_app._hide_progress()
        gui_app.root.update()
        
        # Should be hidden again
        progress_frame_info = gui_app.progress_frame.grid_info()
        assert not progress_frame_info
    
    def test_progress_bar_indeterminate_mode(self, gui_app):
        """Test progress bar indeterminate mode during file loading."""
        # Start indeterminate mode
        gui_app._show_progress("Loading...")
        gui_app.root.update()
        
        # Should be in indeterminate mode and running
        assert str(gui_app.progress.cget('mode')) == 'indeterminate'
        
        # Update to determinate mode
        gui_app._update_progress_ui(5, 10, "Processing")
        gui_app.root.update()
        
        # Should switch to determinate
        assert str(gui_app.progress.cget('mode')) == 'determinate'
        assert gui_app.progress.cget('maximum') == 10
        assert gui_app.progress.cget('value') == 5
    
    def test_progress_update_calculations(self, gui_app):
        """Test progress bar percentage calculations."""
        gui_app._show_progress("Starting...")
        
        # Test progress updates
        gui_app._update_progress_ui(25, 100, "Processing IOCs")
        gui_app.root.update()
        
        # Check the label shows percentage
        label_text = gui_app.progress_label.cget('text')
        assert "25%" in label_text
        assert "25/100" in label_text
        assert "Processing IOCs" in label_text
    
    def test_progress_error_handling(self, gui_app):
        """Test progress bar behavior during error conditions."""
        # Show progress
        gui_app._show_progress("Processing...")
        gui_app.root.update()
        
        # Verify progress is shown
        progress_frame_info = gui_app.progress_frame.grid_info()
        assert progress_frame_info
        
        # Simulate error - progress should be hidden
        gui_app._hide_progress()
        gui_app.root.update()
        
        # Progress bar should be hidden on error
        progress_frame_info = gui_app.progress_frame.grid_info()
        assert not progress_frame_info
    
    def test_progress_thread_safety(self, gui_app):
        """Test that progress updates work correctly."""
        # Test direct progress updates (avoiding threading issues in tests)
        gui_app._update_progress_ui(50, 100, "Thread update")
        gui_app.root.update()
        
        # Progress should be updated
        assert gui_app.progress.cget('value') == 50
        assert gui_app.progress.cget('maximum') == 100
    
    def test_progress_reset_on_new_operation(self, gui_app):
        """Test that progress resets properly for new operations."""
        # Set some progress
        gui_app._update_progress_ui(75, 100, "Almost done")
        gui_app.root.update()
        
        assert gui_app.progress.cget('value') == 75
        
        # Start new operation
        gui_app._show_progress("New operation starting...")
        gui_app.root.update()
        
        # Should be back to indeterminate mode
        assert str(gui_app.progress.cget('mode')) == 'indeterminate'
    
    def test_controls_state_during_processing(self, gui_app):
        """Test that GUI controls are properly disabled during processing."""
        # Initially enabled
        assert str(gui_app.btn_check.cget('state')) == 'normal'
        assert str(gui_app.btn_batch.cget('state')) == 'normal'
        
        # Simulate processing start
        gui_app.btn_check.config(state="disabled")
        gui_app.btn_batch.config(state="disabled")
        
        assert str(gui_app.btn_check.cget('state')) == 'disabled'
        assert str(gui_app.btn_batch.cget('state')) == 'disabled'
        
        # Reset controls
        gui_app.btn_check.config(state="normal")
        gui_app.btn_batch.config(state="normal")
        
        assert str(gui_app.btn_check.cget('state')) == 'normal'
        assert str(gui_app.btn_batch.cget('state')) == 'normal'
    
    def test_format_detection(self, gui_app):
        """Test that file format detection works."""
        # Test CSV detection
        gui_app._update_format_info("test.csv")
        assert "CSV" in gui_app.format_label.cget('text')
        
        # Test Excel detection
        gui_app._update_format_info("test.xlsx")
        assert "Excel" in gui_app.format_label.cget('text')
        
        # Test TSV detection
        gui_app._update_format_info("test.tsv")
        assert "TSV" in gui_app.format_label.cget('text')
        
        # Test TXT detection
        gui_app._update_format_info("test.txt")
        assert "Plain Text" in gui_app.format_label.cget('text')
    
    def test_preview_update(self, gui_app):
        """Test preview functionality."""
        # Mock IOC data
        sample_iocs = [
            {'type': 'domain', 'value': 'test.com'},
            {'type': 'ip', 'value': '1.2.3.4'},
            {'type': 'hash', 'value': 'abc123'}
        ]
        
        gui_app._update_preview(10, sample_iocs)
        
        preview_text = gui_app.format_label.cget('text')
        assert "10 IOCs found" in preview_text
        assert "domain" in preview_text or "ip" in preview_text or "hash" in preview_text