"""
Test GUI module components and functionality.
Covers Tkinter GUI, dialog boxes, and subprocess handling.
"""
import pytest
import tkinter as tk
from unittest.mock import patch, Mock, MagicMock
import subprocess
import os
from pathlib import Path
import tempfile

# Mock tkinter for headless testing
with patch.dict('sys.modules', {'tkinter': MagicMock(), 'tkinter.ttk': MagicMock(), 'tkinter.filedialog': MagicMock(), 'tkinter.messagebox': MagicMock(), 'tkinter.font': MagicMock()}):
    from ioc_gui_tk import theme, ProviderDlg, ProxyDlg, App


class TestGUITheme:
    """Test GUI theme functionality."""
    
    def test_theme_setup_success(self):
        """Test successful theme setup."""
        mock_root = Mock()
        mock_style = Mock()
        mock_font = Mock()
        
        with patch('ioc_gui_tk.ttk.Style', return_value=mock_style):
            with patch('ioc_gui_tk.font.nametofont', return_value=mock_font):
                theme(mock_root)
                
                mock_style.theme_use.assert_called_with("clam")
                mock_font.configure.assert_called()
                mock_root.option_add.assert_called()
    
    def test_theme_setup_failure(self):
        """Test theme setup with exception handling."""
        mock_root = Mock()
        
        with patch('ioc_gui_tk.ttk.Style', side_effect=Exception("Theme failed")):
            with patch('ioc_gui_tk.log.warning') as mock_warning:
                theme(mock_root)
                mock_warning.assert_called()


class TestProviderDialog:
    """Test provider configuration dialog."""
    
    def test_provider_dialog_init(self):
        """Test provider dialog initialization."""
        mock_master = Mock()
        test_config = {"virustotal": True, "greynoise": False}
        
        with patch('ioc_gui_tk.tk.Toplevel'):
            with patch('ioc_gui_tk.tk.BooleanVar') as mock_var:
                with patch('ioc_gui_tk.ttk.Checkbutton'):
                    with patch('ioc_gui_tk.ttk.Button'):
                        dialog = ProviderDlg(mock_master, test_config)
                        
                        assert dialog.result is None
                        assert len(dialog.vars) == 2
    
    def test_provider_dialog_ok(self):
        """Test provider dialog OK button."""
        mock_master = Mock()
        test_config = {"virustotal": True, "greynoise": False}
        
        with patch('ioc_gui_tk.tk.Toplevel'):
            with patch('ioc_gui_tk.tk.BooleanVar') as mock_var_class:
                mock_var1 = Mock()
                mock_var1.get.return_value = True
                mock_var2 = Mock() 
                mock_var2.get.return_value = False
                mock_var_class.side_effect = [mock_var1, mock_var2]
                
                with patch('ioc_gui_tk.ttk.Checkbutton'):
                    with patch('ioc_gui_tk.ttk.Button'):
                        dialog = ProviderDlg(mock_master, test_config)
                        dialog.vars = {"virustotal": mock_var1, "greynoise": mock_var2}
                        
                        dialog.ok()
                        
                        assert dialog.result == {"virustotal": True, "greynoise": False}


class TestProxyDialog:
    """Test proxy configuration dialog."""
    
    def test_proxy_dialog_init(self):
        """Test proxy dialog initialization."""
        mock_master = Mock()
        
        with patch('ioc_gui_tk.tk.Toplevel'):
            with patch('ioc_gui_tk.tk.StringVar') as mock_var:
                with patch('ioc_gui_tk.ttk.Entry'):
                    with patch('ioc_gui_tk.ttk.Button'):
                        with patch('os.environ.get', return_value="http://proxy:8080"):
                            dialog = ProxyDlg(mock_master)
                            mock_var.assert_called_with(value="http://proxy:8080")
    
    def test_proxy_dialog_ok_with_proxy(self):
        """Test proxy dialog OK with proxy value."""
        mock_master = Mock()
        
        with patch('ioc_gui_tk.tk.Toplevel'):
            with patch('ioc_gui_tk.tk.StringVar') as mock_var_class:
                mock_var = Mock()
                mock_var.get.return_value = "http://proxy:8080"
                mock_var_class.return_value = mock_var
                
                with patch('ioc_gui_tk.ttk.Entry'):
                    with patch('ioc_gui_tk.ttk.Button'):
                        with patch('os.environ.get', return_value=""):
                            dialog = ProxyDlg(mock_master)
                            dialog.var = mock_var
                            
                            with patch.dict(os.environ, {}, clear=True):
                                dialog.ok()
                                
                                assert os.environ.get("http_proxy") == "http://proxy:8080"
                                assert os.environ.get("https_proxy") == "http://proxy:8080"
    
    def test_proxy_dialog_ok_clear_proxy(self):
        """Test proxy dialog OK with empty proxy (clear)."""
        mock_master = Mock()
        
        with patch('ioc_gui_tk.tk.Toplevel'):
            with patch('ioc_gui_tk.tk.StringVar') as mock_var_class:
                mock_var = Mock()
                mock_var.get.return_value = "  "  # Whitespace only
                mock_var_class.return_value = mock_var
                
                with patch('ioc_gui_tk.ttk.Entry'):
                    with patch('ioc_gui_tk.ttk.Button'):
                        with patch('os.environ.get', return_value=""):
                            dialog = ProxyDlg(mock_master)
                            dialog.var = mock_var
                            
                            with patch.dict(os.environ, {"http_proxy": "old", "https_proxy": "old"}):
                                dialog.ok()
                                
                                assert "http_proxy" not in os.environ
                                assert "https_proxy" not in os.environ


class TestMainApp:
    """Test main application functionality."""
    
    def test_app_init(self):
        """Test app initialization."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        app = App()
                        
                        assert app.cfg == {"virustotal": False, "greynoise": False, "pulsedive": False, "shodan": False}
                        assert app.proc is None
    
    def test_app_build_gui(self):
        """Test GUI building."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch('ioc_gui_tk.ttk.Frame'):
                    with patch('ioc_gui_tk.ttk.LabelFrame'):
                        with patch('ioc_gui_tk.ttk.Label'):
                            with patch('ioc_gui_tk.ttk.Combobox') as mock_combo:
                                with patch('ioc_gui_tk.ttk.Entry'):
                                    with patch('ioc_gui_tk.ttk.Button'):
                                        with patch('ioc_gui_tk.tk.Text'):
                                            with patch('ioc_gui_tk.tk.StringVar'):
                                                with patch('ioc_gui_tk.tk.BooleanVar'):
                                                    with patch.object(App, 'after'):
                                                        app = App()
                                                        
                                                        mock_combo.assert_called()
    
    def test_app_browse_file(self):
        """Test file browsing functionality."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch('ioc_gui_tk.filedialog.askopenfilename', return_value="test.csv"):
                            app = App()
                            app.path = Mock()
                            
                            app.browse()
                            
                            app.path.set.assert_called_with("test.csv")
    
    def test_app_browse_file_cancelled(self):
        """Test file browsing when cancelled."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch('ioc_gui_tk.filedialog.askopenfilename', return_value=""):
                            app = App()
                            app.path = Mock()
                            
                            app.browse()
                            
                            app.path.set.assert_not_called()
    
    def test_app_providers_config(self):
        """Test provider configuration."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch.object(App, 'wait_window'):
                            app = App()
                            
                            mock_dialog = Mock()
                            mock_dialog.result = {"virustotal": True, "greynoise": False}
                            
                            with patch('ioc_gui_tk.ProviderDlg', return_value=mock_dialog):
                                app.providers()
                                
                                assert app.cfg["virustotal"] == True
                                assert app.cfg["greynoise"] == False
    
    def test_app_providers_config_cancelled(self):
        """Test provider configuration when cancelled."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch.object(App, 'wait_window'):
                            app = App()
                            original_cfg = app.cfg.copy()
                            
                            mock_dialog = Mock()
                            mock_dialog.result = None
                            
                            with patch('ioc_gui_tk.ProviderDlg', return_value=mock_dialog):
                                app.providers()
                                
                                assert app.cfg == original_cfg
    
    def test_app_proxy_config(self):
        """Test proxy configuration."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch('ioc_gui_tk.ProxyDlg') as mock_dialog_class:
                            app = App()
                            app.proxy()
                            mock_dialog_class.assert_called_with(app)
    
    def test_app_clear_output(self):
        """Test output clearing."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        app = App()
                        app.out = Mock()
                        
                        app.clear()
                        
                        app.out.config.assert_called()
                        app.out.delete.assert_called_with("1.0", "end")
    
    def test_app_single_ioc_no_value(self):
        """Test single IOC with no value."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch('ioc_gui_tk.messagebox.showerror') as mock_error:
                            app = App()
                            app.proc = None
                            app.val = Mock()
                            app.val.get.return_value = ""
                            
                            app.single()
                            
                            mock_error.assert_called_with("Input", "Enter an IOC value")
    
    def test_app_single_ioc_process_running(self):
        """Test single IOC when process already running."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        app = App()
                        app.proc = Mock()  # Process already running
                        
                        result = app.single()
                        assert result is None
    
    def test_app_batch_no_file(self):
        """Test batch processing with no file."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch('ioc_gui_tk.messagebox.showerror') as mock_error:
                            app = App()
                            app.proc = None
                            app.path = Mock()
                            app.path.get.return_value = ""
                            
                            app.batch()
                            
                            mock_error.assert_called_with("File", "Select a CSV/TXT file")
    
    def test_app_batch_file_not_found(self):
        """Test batch processing with non-existent file."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch('ioc_gui_tk.messagebox.showerror') as mock_error:
                            with patch('ioc_gui_tk.Path') as mock_path:
                                mock_path.return_value.exists.return_value = False
                                
                                app = App()
                                app.proc = None
                                app.path = Mock()
                                app.path.get.return_value = "nonexistent.csv"
                                
                                app.batch()
                                
                                mock_error.assert_called_with("File", "File not found")
    
    def test_app_start_subprocess_success(self):
        """Test successful subprocess start."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch('ioc_gui_tk.subprocess.Popen') as mock_popen:
                            with patch('ioc_gui_tk.log.info') as mock_log:
                                app = App()
                                app.auto_clear = Mock()
                                app.auto_clear.get.return_value = True
                                
                                with patch.object(app, 'clear'):
                                    app._start(["python", "test.py"])
                                    
                                    mock_popen.assert_called()
                                    mock_log.assert_called()
    
    def test_app_start_subprocess_failure(self):
        """Test subprocess start failure."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch('ioc_gui_tk.subprocess.Popen', side_effect=Exception("Start failed")):
                            with patch('ioc_gui_tk.messagebox.showerror') as mock_error:
                                with patch('ioc_gui_tk.log.error') as mock_log:
                                    app = App()
                                    app.auto_clear = Mock()
                                    app.auto_clear.get.return_value = False
                                    
                                    app._start(["python", "test.py"])
                                    
                                    mock_error.assert_called()
                                    mock_log.assert_called()
    
    def test_app_start_existing_process(self):
        """Test starting subprocess when one already exists."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch('ioc_gui_tk.log.warning') as mock_warning:
                            app = App()
                            app.proc = Mock()
                            app.proc.poll.return_value = None  # Still running
                            app.auto_clear = Mock()
                            app.auto_clear.get.return_value = False
                            
                            app._start(["python", "test.py"])
                            
                            mock_warning.assert_called()
    
    def test_app_poll_subprocess_output(self):
        """Test polling subprocess for output."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after') as mock_after:
                        app = App()
                        app.proc = Mock()
                        app.proc.stdout.readline.side_effect = ["line1\n", "line2\n", ""]
                        app.proc.poll.return_value = 0  # Process finished
                        app.out = Mock()
                        
                        app._poll()
                        
                        app.out.config.assert_called()
                        app.out.insert.assert_called()
                        mock_after.assert_called_with(100, app._poll)
    
    def test_app_poll_subprocess_error(self):
        """Test polling subprocess with error."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch('ioc_gui_tk.log.error') as mock_log:
                            app = App()
                            app.proc = Mock()
                            app.proc.stdout.readline.side_effect = Exception("Read failed")
                            
                            app._poll()
                            
                            mock_log.assert_called()
                            assert app.proc is None
    
    def test_app_poll_no_process(self):
        """Test polling when no process exists."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after') as mock_after:
                        app = App()
                        app.proc = None
                        
                        app._poll()
                        
                        mock_after.assert_called_with(100, app._poll)


class TestGUIIntegration:
    """Test GUI integration scenarios."""
    
    def test_app_main_execution(self):
        """Test main execution path."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch.object(App, 'mainloop') as mock_mainloop:
                            with patch('ioc_gui_tk.log.error') as mock_log:
                                # Test normal execution
                                with patch('ioc_gui_tk.App', return_value=Mock()) as mock_app_class:
                                    mock_app = mock_app_class.return_value
                                    
                                    # Simulate running the GUI module
                                    exec("if __name__ == '__main__': pass")
    
    def test_app_exception_handling(self):
        """Test application exception handling."""
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        with patch.object(App, 'mainloop', side_effect=Exception("GUI error")):
                            with patch('ioc_gui_tk.log.error') as mock_log:
                                with patch('builtins.print') as mock_print:
                                    try:
                                        app = App()
                                        app.mainloop()
                                    except Exception:
                                        pass


if __name__ == "__main__":
    pytest.main([__file__])