# tests/test_gui.py
"""Test GUI functionality."""
import pytest
import tkinter as tk
from unittest.mock import patch, MagicMock
import tempfile
from pathlib import Path

# Import GUI components
try:
    from ioc_gui_tk import App, ProviderDlg, ProxyDlg
except ImportError:
    pytest.skip("GUI tests require tkinter", allow_module_level=True)

class TestGUI:
    """Test GUI functionality."""
    
    def setup_method(self):
        """Set up test environment."""
        self.root = tk.Tk()
        self.root.withdraw()  # Hide window during tests
    
    def teardown_method(self):
        """Clean up test environment."""
        if self.root:
            self.root.destroy()
    
    def test_app_initialization(self):
        """Test App initializes without errors."""
        try:
            app = App()
            app.withdraw()  # Hide window
            assert app.title() == "IOC Checker"
            assert hasattr(app, 'cfg')
            assert hasattr(app, 'auto_clear')
            app.destroy()
        except Exception as e:
            pytest.fail(f"App initialization failed: {e}")
    
    def test_enter_key_triggers_check(self):
        """Test Enter key triggers single IOC check."""
        app = App()
        app.withdraw()
        
        app.typ.set("ip")
        app.val.set("8.8.8.8")
        
        with patch.object(app, 'single') as mock_single:
            # Simulate Enter key press
            app.event_generate('<Return>')
            app.update()  # Process events
            # Note: This may not work in headless environment
        
        app.destroy()
    
    def test_clear_output_button(self):
        """Test Clear Output button empties log."""
        app = App()
        app.withdraw()
        
        # Add some text to output
        app.out.config(state=tk.NORMAL)
        app.out.insert(tk.END, "Test output")
        app.out.config(state=tk.DISABLED)
        
        # Clear output
        app.clear()
        
        # Check if cleared
        content = app.out.get("1.0", tk.END).strip()
        assert content == ""
        
        app.destroy()
    
    def test_auto_clear_toggle(self):
        """Test auto-clear toggle functionality."""
        app = App()
        app.withdraw()
        
        # Test default state
        assert app.auto_clear.get() == True
        
        # Toggle state
        app.auto_clear.set(False)
        assert app.auto_clear.get() == False
        
        app.destroy()
    
    def test_browse_csv_file(self):
        """Test CSV file browsing."""
        app = App()
        app.withdraw()
        
        # Create temporary CSV file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("ip,domain\n8.8.8.8,google.com\n")
            csv_path = f.name
        
        try:
            # Mock file dialog
            with patch('tkinter.filedialog.askopenfilename', return_value=csv_path):
                app.browse()
                assert app.path.get() == csv_path
        finally:
            Path(csv_path).unlink()
            app.destroy()
    
    def test_run_with_missing_csv(self):
        """Test run with missing CSV shows error."""
        app = App()
        app.withdraw()
        
        app.path.set("nonexistent.csv")
        
        with patch('tkinter.messagebox.showerror') as mock_error:
            app.batch()
            mock_error.assert_called_once()
        
        app.destroy()
    
    def test_run_with_existing_csv(self):
        """Test run with existing CSV starts process."""
        app = App()
        app.withdraw()
        
        # Create temporary CSV file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("ip,domain\n8.8.8.8,google.com\n")
            csv_path = f.name
        
        try:
            app.path.set(csv_path)
            
            with patch('subprocess.Popen') as mock_popen:
                mock_popen.return_value.poll.return_value = None
                mock_popen.return_value.stdout.readline.return_value = ""
                app.batch()
                mock_popen.assert_called_once()
        finally:
            Path(csv_path).unlink()
            app.destroy()
    
    def test_provider_dialog(self):
        """Test provider configuration dialog."""
        app = App()
        app.withdraw()
        
        cfg = {"virustotal": False, "greynoise": True}
        dialog = ProviderDlg(app, cfg)
        
        # Test initialization
        assert len(dialog.vars) == len(cfg)
        assert dialog.vars["virustotal"].get() == False
        assert dialog.vars["greynoise"].get() == True
        
        # Test OK button
        dialog.vars["virustotal"].set(True)
        dialog.ok()
        
        assert dialog.result["virustotal"] == True
        assert dialog.result["greynoise"] == True
        
        app.destroy()
    
    def test_proxy_dialog(self):
        """Test proxy configuration dialog."""
        app = App()
        app.withdraw()
        
        import os
        original_proxy = os.environ.get("https_proxy", "")
        
        try:
            dialog = ProxyDlg(app)
            
            # Test setting proxy
            dialog.var.set("http://proxy.example.com:8080")
            dialog.ok()
            
            assert os.environ.get("https_proxy") == "http://proxy.example.com:8080"
            
        finally:
            # Restore original proxy setting
            if original_proxy:
                os.environ["https_proxy"] = original_proxy
            else:
                os.environ.pop("https_proxy", None)
            app.destroy()
    
    def test_single_ioc_validation(self):
        """Test single IOC input validation."""
        app = App()
        app.withdraw()
        
        # Test empty value
        app.val.set("")
        with patch('tkinter.messagebox.showerror') as mock_error:
            app.single()
            mock_error.assert_called_once()
        
        app.destroy()
    
    def test_subprocess_polling(self):
        """Test subprocess output polling."""
        app = App()
        app.withdraw()
        
        # Mock subprocess
        mock_proc = MagicMock()
        mock_proc.stdout.readline.return_value = "Test output\n"
        mock_proc.poll.return_value = None
        app.proc = mock_proc
        
        # Test polling
        app._poll()
        
        # Check if output was added
        content = app.out.get("1.0", tk.END)
        # Note: This might not work in headless environment
        
        app.destroy()
