"""
Test CSV processing flow in GUI - ensures CSV input shows output.
"""
import pytest
import tempfile
import os
from unittest.mock import patch, Mock


def test_csv_command_construction():
    """Test that CSV processing constructs correct command."""
    # Import after setting up patches to avoid Tkinter issues
    with patch('ioc_gui_tk.tk.Tk', Mock):
        with patch('ioc_gui_tk.theme', Mock):
            with patch('ioc_gui_tk.subprocess.Popen') as mock_popen:
                mock_popen.return_value = Mock()
                
                # Import and create app manually
                import ioc_gui_tk
                app = object.__new__(ioc_gui_tk.App)
                app.cfg = {"virustotal": False, "greynoise": False, "pulsedive": False, "shodan": False}
                app.proc = None
                app.path = Mock()
                app.out = Mock()
                app.auto_clear = Mock()
                app.auto_clear.get.return_value = False
                
                # Create test CSV
                with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                    f.write("ioc\n8.8.8.8\n")
                    csv_path = f.name
                
                try:
                    app.path.get.return_value = csv_path
                    
                    # Test batch method
                    app.batch()
                    
                    # Verify command construction
                    mock_popen.assert_called_once()
                    args = mock_popen.call_args[0][0]
                    assert "--csv" in args
                    assert csv_path in args
                    assert "-o" in args
                    
                    # Verify output messages
                    app.out.insert.assert_called()
                    
                finally:
                    os.unlink(csv_path)


def test_csv_with_providers():
    """Test CSV command with provider selection."""
    with patch('ioc_gui_tk.tk.Tk', Mock):
        with patch('ioc_gui_tk.theme', Mock):
            with patch('ioc_gui_tk.subprocess.Popen') as mock_popen:
                mock_popen.return_value = Mock()
                
                import ioc_gui_tk
                app = object.__new__(ioc_gui_tk.App)
                app.cfg = {"virustotal": True, "greynoise": False, "pulsedive": True, "shodan": False}
                app.proc = None
                app.path = Mock()
                app.out = Mock()
                app.auto_clear = Mock()
                app.auto_clear.get.return_value = False
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                    f.write("ioc\n8.8.8.8\n")
                    csv_path = f.name
                
                try:
                    app.path.get.return_value = csv_path
                    app.batch()
                    
                    args = mock_popen.call_args[0][0]
                    assert "--virustotal" in args
                    assert "--pulsedive" in args
                    assert "--rate" in args
                    
                finally:
                    os.unlink(csv_path)


def test_csv_status_messages():
    """Test that CSV processing shows status messages."""
    with patch('ioc_gui_tk.tk.Tk', Mock):
        with patch('ioc_gui_tk.theme', Mock):
            with patch('ioc_gui_tk.subprocess.Popen', Mock):
                import ioc_gui_tk
                app = object.__new__(ioc_gui_tk.App)
                app.cfg = {}
                app.proc = None
                app.path = Mock()
                app.out = Mock()
                app.auto_clear = Mock()
                app.auto_clear.get.return_value = False
                
                with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
                    f.write("ioc\n8.8.8.8\n")
                    csv_path = f.name
                
                try:
                    app.path.get.return_value = csv_path
                    app.batch()
                    
                    # Verify status messages were added
                    insert_calls = app.out.insert.call_args_list
                    messages = [call[0][1] for call in insert_calls]
                    
                    assert any("Starting CSV processing" in msg for msg in messages)
                    assert any("Output will be saved to" in msg for msg in messages)
                    
                finally:
                    os.unlink(csv_path)


if __name__ == "__main__":
    pytest.main([__file__])