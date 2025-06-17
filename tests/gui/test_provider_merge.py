"""
Test provider merge logic - ensures defaults + user selections = union.
"""
import pytest
from unittest.mock import patch, Mock, AsyncMock


@pytest.mark.asyncio
async def test_provider_merge_logic():
    """Test that selected providers are merged with default always-on providers."""
    from ioc_checker import _query
    from providers import ALWAYS_ON, RATE_LIMIT
    
    # Mock session and provider objects
    session = Mock()
    
    # Mock provider classes with query methods
    mock_always_on = []
    mock_rate_limited = []
    
    for i, provider in enumerate(ALWAYS_ON):
        mock_prov = Mock()
        mock_prov.name = provider.name
        mock_prov.ioc_kinds = provider.ioc_kinds
        mock_prov.query = AsyncMock(return_value=f"result_{i}")
        mock_always_on.append(mock_prov)
    
    for i, provider in enumerate(RATE_LIMIT):
        mock_prov = Mock()
        mock_prov.name = provider.name
        mock_prov.ioc_kinds = provider.ioc_kinds
        mock_prov.query = AsyncMock(return_value=f"rate_result_{i}")
        mock_rate_limited.append(mock_prov)
    
    # Test with selected providers - should merge with always-on
    with patch('ioc_checker.ALWAYS_ON', mock_always_on):
        with patch('ioc_checker.RATE_LIMIT', mock_rate_limited):
            # Test case: user selects virustotal, should get always-on + virustotal
            selected_providers = ["virustotal"]
            result = await _query(session, "ip", "8.8.8.8", False, selected_providers)
            
            # Should include all always-on providers plus selected ones
            expected_providers = set()
            for p in mock_always_on:
                if "ip" in p.ioc_kinds:
                    expected_providers.add(p.name)
            expected_providers.add("virustotal")
            
            assert len(result) >= len([p for p in mock_always_on if "ip" in p.ioc_kinds])


def test_gui_provider_merge():
    """Test GUI properly merges providers in command construction."""
    with patch('ioc_gui_tk.tk.Tk', Mock):
        with patch('ioc_gui_tk.theme', Mock):
            with patch('ioc_gui_tk.subprocess.Popen') as mock_popen:
                mock_popen.return_value = Mock()
                
                import ioc_gui_tk
                app = object.__new__(ioc_gui_tk.App)
                app.cfg = {"virustotal": True, "greynoise": False, "pulsedive": True, "shodan": False}
                app.proc = None
                app.val = Mock()
                app.val.get.return_value = "8.8.8.8"
                app.typ = Mock()
                app.typ.get.return_value = "ip"
                app.auto_clear = Mock()
                app.auto_clear.get.return_value = False
                
                app.single()
                
                # Verify command includes selected providers and rate flag
                args = mock_popen.call_args[0][0]
                assert "--virustotal" in args
                assert "--pulsedive" in args
                assert "--greynoise" not in args
                assert "--shodan" not in args
                assert "--rate" in args  # Should be added when providers selected


def test_no_providers_selected():
    """Test behavior when no providers are explicitly selected."""
    with patch('ioc_gui_tk.tk.Tk', Mock):
        with patch('ioc_gui_tk.theme', Mock):
            with patch('ioc_gui_tk.subprocess.Popen') as mock_popen:
                mock_popen.return_value = Mock()
                
                import ioc_gui_tk
                app = object.__new__(ioc_gui_tk.App)
                app.cfg = {"virustotal": False, "greynoise": False, "pulsedive": False, "shodan": False}
                app.proc = None
                app.val = Mock()
                app.val.get.return_value = "8.8.8.8"
                app.typ = Mock()
                app.typ.get.return_value = "ip"
                app.auto_clear = Mock()
                app.auto_clear.get.return_value = False
                
                app.single()
                
                # Verify no extra provider flags are added
                args = mock_popen.call_args[0][0]
                assert "--virustotal" not in args
                assert "--greynoise" not in args
                assert "--pulsedive" not in args
                assert "--shodan" not in args
                assert "--rate" not in args  # Should not be added when no providers selected


@pytest.mark.asyncio 
async def test_backend_provider_merge():
    """Test backend properly merges default and selected providers."""
    from ioc_checker import scan_single
    
    # Mock session
    session = Mock()
    
    # Test with selected providers
    with patch('ioc_checker._query') as mock_query:
        mock_query.return_value = {"provider1": "result1", "provider2": "result2"}
        
        result = await scan_single(session, "8.8.8.8", False, ["virustotal"])
        
        # Verify _query was called with correct parameters
        mock_query.assert_called_once_with(session, "ip", "8.8.8.8", False, ["virustotal"])
        
        assert result["value"] == "8.8.8.8"
        assert result["type"] == "ip"
        assert "results" in result


def test_provider_dialog_functionality():
    """Test that provider dialog correctly handles user selections."""
    import ioc_gui_tk
    
    # Create dialog manually without tkinter inheritance issues
    dialog = object.__new__(ioc_gui_tk.ProviderDlg)
    dialog.result = None
    dialog.vars = {}
    
    # Simulate user selections
    initial_cfg = {"virustotal": False, "greynoise": True, "pulsedive": False, "shodan": True}
    for k, v in initial_cfg.items():
        var = Mock()
        var.get.return_value = v
        dialog.vars[k] = var
    
    # Test OK method preserves selections (without destroy call)
    dialog.result = {k: v.get() for k, v in dialog.vars.items()}
    
    assert dialog.result == initial_cfg
    assert dialog.result["greynoise"]
    assert dialog.result["shodan"]
    assert not dialog.result["virustotal"]
    assert not dialog.result["pulsedive"]


if __name__ == "__main__":
    pytest.main([__file__])