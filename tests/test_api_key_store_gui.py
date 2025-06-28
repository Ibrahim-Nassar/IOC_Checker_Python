import os, importlib, types
import pytest
from unittest.mock import patch, MagicMock
from api_key_store import save as save_key, load as load_key

@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    for var in ("VIRUSTOTAL_API_KEY", "OTX_API_KEY",
                "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
        save_key(var, "")
    yield

def test_save_and_reload():
    save_key("VIRUSTOTAL_API_KEY", "dummy123")
    os.environ.pop("VIRUSTOTAL_API_KEY", None)

    # Import GUI class and create instance with comprehensive mocking
    with patch('IOC_Checker_Python.ioc_gui_tk.tk.Tk') as mock_tk, \
         patch('IOC_Checker_Python.ioc_gui_tk.threading.Thread') as mock_thread, \
         patch('IOC_Checker_Python.ioc_gui_tk.asyncio.new_event_loop') as mock_loop:
        
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        mock_loop.return_value = MagicMock()
        
        gui_mod = importlib.import_module("IOC_Checker_Python.ioc_gui_tk")
        cls = getattr(gui_mod, "IOCCheckerGUI")
        
        # Mock the methods that come after API key loading to prevent full initialization
        with patch.object(cls, '_create_menu'), \
             patch.object(cls, '_build_ui'), \
             patch.object(cls, '_poll_queue'):
            
            # Create an instance to trigger __init__ and API key loading
            instance = cls()
        
    assert os.environ["VIRUSTOTAL_API_KEY"] == "dummy123"
    assert load_key("VIRUSTOTAL_API_KEY") == "dummy123" 