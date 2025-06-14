"""
Simplified GUI tests that actually work with mocked Tkinter.
Focus on covering the GUI logic without complex UI interactions.
"""
import pytest
import os
from unittest.mock import Mock, patch, MagicMock
import tempfile


def test_gui_module_import():
    """Test that GUI module can be imported."""
    with patch.dict('sys.modules', {
        'tkinter': MagicMock(), 
        'tkinter.ttk': MagicMock(), 
        'tkinter.filedialog': MagicMock(), 
        'tkinter.messagebox': MagicMock(), 
        'tkinter.font': MagicMock()
    }):
        import ioc_gui_tk
        assert hasattr(ioc_gui_tk, 'App')
        assert hasattr(ioc_gui_tk, 'theme')
        assert hasattr(ioc_gui_tk, 'ProviderDlg')
        assert hasattr(ioc_gui_tk, 'ProxyDlg')


def test_theme_function():
    """Test theme setup function."""
    with patch.dict('sys.modules', {
        'tkinter': MagicMock(), 
        'tkinter.ttk': MagicMock(), 
        'tkinter.font': MagicMock()
    }):
        from ioc_gui_tk import theme
        
        mock_root = Mock()
        mock_style = Mock()
        mock_font = Mock()
        
        with patch('ioc_gui_tk.ttk.Style', return_value=mock_style):
            with patch('ioc_gui_tk.font.nametofont', return_value=mock_font):
                # Test successful theme setup
                theme(mock_root)
                mock_style.theme_use.assert_called()
                mock_font.configure.assert_called()


def test_theme_function_exception():
    """Test theme setup with exception."""
    with patch.dict('sys.modules', {
        'tkinter': MagicMock(), 
        'tkinter.ttk': MagicMock(), 
        'tkinter.font': MagicMock()
    }):
        from ioc_gui_tk import theme
        
        mock_root = Mock()
        
        with patch('ioc_gui_tk.ttk.Style', side_effect=Exception("Theme error")):
            with patch('ioc_gui_tk.log.warning') as mock_warning:
                theme(mock_root)
                mock_warning.assert_called()


def test_provider_dialog_basic():
    """Test basic ProviderDlg functionality."""
    with patch.dict('sys.modules', {
        'tkinter': MagicMock(), 
        'tkinter.ttk': MagicMock()
    }):
        from ioc_gui_tk import ProviderDlg
        
        master = Mock()
        config = {"virustotal": True, "greynoise": False}
        
        with patch('ioc_gui_tk.tk.Toplevel'):
            with patch('ioc_gui_tk.tk.BooleanVar') as mock_var:
                with patch('ioc_gui_tk.ttk.Checkbutton'):
                    with patch('ioc_gui_tk.ttk.Button'):
                        dialog = ProviderDlg(master, config)
                        
                        # Test OK method
                        mock_var1 = Mock()
                        mock_var1.get.return_value = True
                        mock_var2 = Mock()
                        mock_var2.get.return_value = False
                        dialog.vars = {"virustotal": mock_var1, "greynoise": mock_var2}
                        
                        dialog.ok()
                        assert dialog.result == {"virustotal": True, "greynoise": False}


def test_proxy_dialog_basic():
    """Test basic ProxyDlg functionality."""
    with patch.dict('sys.modules', {
        'tkinter': MagicMock(), 
        'tkinter.ttk': MagicMock()
    }):
        from ioc_gui_tk import ProxyDlg
        
        master = Mock()
        
        with patch('ioc_gui_tk.tk.Toplevel'):
            with patch('ioc_gui_tk.tk.StringVar') as mock_var_class:
                with patch('ioc_gui_tk.ttk.Entry'):
                    with patch('ioc_gui_tk.ttk.Button'):
                        with patch('os.environ.get', return_value=""):
                            mock_var = Mock()
                            mock_var.get.return_value = "http://proxy:8080"
                            mock_var_class.return_value = mock_var
                            
                            dialog = ProxyDlg(master)
                            dialog.var = mock_var
                            
                            # Test setting proxy
                            with patch.dict(os.environ, {}, clear=True):
                                dialog.ok()
                                assert os.environ.get("http_proxy") == "http://proxy:8080"
                                assert os.environ.get("https_proxy") == "http://proxy:8080"


def test_proxy_dialog_clear():
    """Test ProxyDlg clearing proxy settings."""
    with patch.dict('sys.modules', {
        'tkinter': MagicMock(), 
        'tkinter.ttk': MagicMock()
    }):
        from ioc_gui_tk import ProxyDlg
        
        master = Mock()
        
        with patch('ioc_gui_tk.tk.Toplevel'):
            with patch('ioc_gui_tk.tk.StringVar') as mock_var_class:
                with patch('ioc_gui_tk.ttk.Entry'):
                    with patch('ioc_gui_tk.ttk.Button'):
                        with patch('os.environ.get', return_value=""):
                            mock_var = Mock()
                            mock_var.get.return_value = "  "  # Empty/whitespace
                            mock_var_class.return_value = mock_var
                            
                            dialog = ProxyDlg(master)
                            dialog.var = mock_var
                            
                            # Test clearing proxy
                            with patch.dict(os.environ, {"http_proxy": "old", "https_proxy": "old"}):
                                dialog.ok()
                                assert "http_proxy" not in os.environ
                                assert "https_proxy" not in os.environ


def test_app_basic_methods():
    """Test basic App class methods that don't require full GUI."""
    with patch.dict('sys.modules', {
        'tkinter': MagicMock(), 
        'tkinter.ttk': MagicMock(), 
        'tkinter.filedialog': MagicMock(),
        'tkinter.messagebox': MagicMock()
    }):
        from ioc_gui_tk import App
        
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        app = App()
                        
                        # Test configuration
                        assert isinstance(app.cfg, dict)
                        assert "virustotal" in app.cfg
                        
                        # Test file browsing
                        app.path = Mock()
                        with patch('ioc_gui_tk.filedialog.askopenfilename', return_value="test.csv"):
                            app.browse()
                            app.path.set.assert_called_with("test.csv")
                        
                        # Test file browsing cancelled
                        app.path.reset_mock()
                        with patch('ioc_gui_tk.filedialog.askopenfilename', return_value=""):
                            app.browse()
                            app.path.set.assert_not_called()
                        
                        # Test clear method
                        app.out = Mock()
                        app.clear()
                        app.out.config.assert_called()
                        app.out.delete.assert_called()


def test_app_single_ioc_validation():
    """Test single IOC validation logic."""
    with patch.dict('sys.modules', {
        'tkinter': MagicMock(), 
        'tkinter.ttk': MagicMock(), 
        'tkinter.messagebox': MagicMock()
    }):
        from ioc_gui_tk import App
        
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        app = App()
                        app.proc = None
                        app.val = Mock()
                        app.typ = Mock()
                        app.typ.get.return_value = "ip"
                        
                        # Test empty value
                        app.val.get.return_value = ""
                        with patch('ioc_gui_tk.messagebox.showerror') as mock_error:
                            app.single()
                            mock_error.assert_called_with("Input", "Enter an IOC value")
                        
                        # Test process already running
                        app.proc = Mock()
                        result = app.single()
                        assert result is None


def test_app_batch_validation():
    """Test batch processing validation."""
    with patch.dict('sys.modules', {
        'tkinter': MagicMock(), 
        'tkinter.messagebox': MagicMock()
    }):
        from ioc_gui_tk import App
        
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        app = App()
                        app.proc = None
                        app.path = Mock()
                        
                        # Test no file selected
                        app.path.get.return_value = ""
                        with patch('ioc_gui_tk.messagebox.showerror') as mock_error:
                            app.batch()
                            mock_error.assert_called_with("File", "Select a CSV/TXT file")
                        
                        # Test file not found
                        app.path.get.return_value = "nonexistent.csv"
                        with patch('ioc_gui_tk.Path') as mock_path:
                            mock_path.return_value.exists.return_value = False
                            with patch('ioc_gui_tk.messagebox.showerror') as mock_error:
                                app.batch()
                                mock_error.assert_called_with("File", "File not found")


def test_app_subprocess_start():
    """Test subprocess starting logic."""
    with patch.dict('sys.modules', {
        'tkinter': MagicMock(), 
        'tkinter.messagebox': MagicMock()
    }):
        from ioc_gui_tk import App
        
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after'):
                        app = App()
                        app.auto_clear = Mock()
                        app.auto_clear.get.return_value = True
                        
                        # Test successful start
                        with patch('ioc_gui_tk.subprocess.Popen') as mock_popen:
                            with patch.object(app, 'clear'):
                                app._start(["python", "test.py"])
                                mock_popen.assert_called()
                        
                        # Test start failure
                        app.auto_clear.get.return_value = False
                        with patch('ioc_gui_tk.subprocess.Popen', side_effect=Exception("Start failed")):
                            with patch('ioc_gui_tk.messagebox.showerror') as mock_error:
                                app._start(["python", "test.py"])
                                mock_error.assert_called()


def test_app_polling():
    """Test subprocess polling logic."""
    with patch.dict('sys.modules', {'tkinter': MagicMock()}):
        from ioc_gui_tk import App
        
        with patch('ioc_gui_tk.tk.Tk'):
            with patch('ioc_gui_tk.theme'):
                with patch.object(App, '_build'):
                    with patch.object(App, 'after') as mock_after:
                        app = App()
                        
                        # Test no process
                        app.proc = None
                        app._poll()
                        mock_after.assert_called()
                        
                        # Test process with output
                        app.proc = Mock()
                        app.proc.stdout.readline.side_effect = ["line1\n", ""]
                        app.proc.poll.return_value = 0
                        app.out = Mock()
                        
                        app._poll()
                        app.out.config.assert_called()
                        app.out.insert.assert_called()
                        
                        # Test polling error
                        app.proc = Mock()
                        app.proc.stdout.readline.side_effect = Exception("Read error")
                        
                        with patch('ioc_gui_tk.log.error') as mock_log:
                            app._poll()
                            mock_log.assert_called()
                            assert app.proc is None


if __name__ == "__main__":
    pytest.main([__file__])