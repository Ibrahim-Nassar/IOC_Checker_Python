#!/usr/bin/env python3
"""
Test script to verify all dialog enhancements and provider configurations.
"""
import sys
import os
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

try:
    from ioc_gui_tk import IOCCheckerGUI
    from dialog_templates import (
        ConfigurationDialog, 
        APIKeyConfigDialog, 
        ProviderSelectionDialog,
        create_api_key_dialog,
        create_provider_selection_dialog,
        STANDARD_API_KEY_CONFIGS
    )
    print("✅ Successfully imported all dialog components")
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)


def test_basic_configuration_dialog():
    """Test the basic ConfigurationDialog template."""
    print("\n🧪 Testing basic ConfigurationDialog...")
    
    root = tk.Tk()
    root.withdraw()  # Hide main window
    
    class TestDialog(ConfigurationDialog):
        def __init__(self, parent):
            super().__init__(parent, "Test Configuration", 400, 300)
            
            # Add some test content
            test_label = ttk.Label(self.content_frame, text="This is a test configuration dialog.")
            test_label.pack(pady=20)
            
            test_entry = ttk.Entry(self.content_frame, width=30)
            test_entry.pack(pady=10)
            test_entry.insert(0, "Test value")
            
            # Set up callbacks
            self.set_save_callback(lambda: messagebox.showinfo("Test", "Save callback works!"))
            self.set_test_callback(lambda: messagebox.showinfo("Test", "Test callback works!"))
    
    try:
        dialog = TestDialog(root)
        print("✅ Basic ConfigurationDialog created successfully")
        
        # Test that all required buttons exist
        assert dialog.save_button is not None, "Save button missing"
        assert dialog.test_button is not None, "Test button missing"
        assert dialog.cancel_button is not None, "Cancel button missing"
        print("✅ All required buttons present")
        
        # Test button hiding/showing
        dialog.hide_test_button()
        dialog.show_test_button()
        print("✅ Button visibility controls work")
        
        dialog.dialog.destroy()
        
    except Exception as e:
        print(f"❌ Basic ConfigurationDialog test failed: {e}")
        return False
    finally:
        root.destroy()
    
    return True


def test_api_key_dialog():
    """Test the API key configuration dialog."""
    print("\n🧪 Testing API Key Configuration Dialog...")
    
    root = tk.Tk()
    root.withdraw()
    
    try:
        current_keys = {
            "virustotal": "test_vt_key",
            "abuseipdb": "",
            "otx": "test_otx_key"
        }
        
        test_configs = [
            ("virustotal", "VirusTotal", "Test VT description"),
            ("abuseipdb", "AbuseIPDB", "Test AbuseIPDB description"),
            ("otx", "AlienVault OTX", "Test OTX description")
        ]
        
        dialog = APIKeyConfigDialog(root, test_configs, current_keys)
        print("✅ API Key dialog created successfully")
        
        # Test that all API key vars are created
        assert len(dialog.api_key_vars) == 3, f"Expected 3 API key vars, got {len(dialog.api_key_vars)}"
        print("✅ API key variables created correctly")
        
        # Test getting keys
        keys = dialog.get_api_keys()
        assert "virustotal" in keys, "VirusTotal key missing"
        assert keys["virustotal"] == "test_vt_key", "VirusTotal key value incorrect"
        print("✅ API key retrieval works")
        
        dialog.dialog.destroy()
        
    except Exception as e:
        print(f"❌ API Key dialog test failed: {e}")
        return False
    finally:
        root.destroy()
    
    return True


def test_provider_selection_dialog():
    """Test the provider selection dialog."""
    print("\n🧪 Testing Provider Selection Dialog...")
    
    root = tk.Tk()
    root.withdraw()
    
    try:
        providers_info = [
            ("virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", "Universal threat intelligence", ["ip", "domain", "url", "hash"]),
            ("abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", "IP reputation service", ["ip"]),
            ("urlhaus", "URLHaus", None, "Free URL database", ["url"])
        ]
        
        current_selection = {
            "virustotal": True,
            "abuseipdb": False,
            "urlhaus": True
        }
        
        dialog = ProviderSelectionDialog(root, providers_info, current_selection)
        print("✅ Provider selection dialog created successfully")
        
        # Test that provider vars are created
        assert len(dialog.provider_vars) == 3, f"Expected 3 provider vars, got {len(dialog.provider_vars)}"
        print("✅ Provider variables created correctly")
        
        # Test getting selection
        selection = dialog.get_selected_providers()
        assert "virustotal" in selection, "VirusTotal selection missing"
        assert selection["virustotal"] == True, "VirusTotal selection incorrect"
        print("✅ Provider selection retrieval works")
        
        dialog.dialog.destroy()
        
    except Exception as e:
        print(f"❌ Provider selection dialog test failed: {e}")
        return False
    finally:
        root.destroy()
    
    return True


def test_dialog_creation_functions():
    """Test the convenience functions for creating dialogs."""
    print("\n🧪 Testing dialog creation functions...")
    
    root = tk.Tk()
    root.withdraw()
    
    try:
        # Test API key dialog creation
        current_keys = {"virustotal": "test_key"}
        
        def dummy_save():
            print("Save callback called")
        
        api_dialog = create_api_key_dialog(root, STANDARD_API_KEY_CONFIGS, current_keys, dummy_save)
        assert api_dialog is not None, "API key dialog creation failed"
        assert api_dialog.save_callback is not None, "Save callback not set"
        print("✅ API key dialog creation function works")
        api_dialog.dialog.destroy()
        
        # Test provider selection dialog creation
        providers_info = [
            ("virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", "Test", ["ip"]),
        ]
        current_selection = {"virustotal": True}
        
        provider_dialog = create_provider_selection_dialog(root, providers_info, current_selection, dummy_save)
        assert provider_dialog is not None, "Provider dialog creation failed"
        assert provider_dialog.save_callback is not None, "Save callback not set"
        print("✅ Provider selection dialog creation function works")
        provider_dialog.dialog.destroy()
        
    except Exception as e:
        print(f"❌ Dialog creation functions test failed: {e}")
        return False
    finally:
        root.destroy()
    
    return True


def test_main_gui_integration():
    """Test that the main GUI still works with all enhancements."""
    print("\n🧪 Testing main GUI integration...")
    
    try:
        # Create GUI instance (don't show it)
        root = tk.Tk()
        root.withdraw()
        
        gui = IOCCheckerGUI()
        gui.root.withdraw()  # Hide the GUI window
        
        print("✅ Main GUI created successfully")
        
        # Test that all required attributes exist
        assert hasattr(gui, 'api_keys'), "API keys attribute missing"
        assert hasattr(gui, 'provider_config'), "Provider config attribute missing"
        assert hasattr(gui, 'providers_info'), "Providers info attribute missing"
        print("✅ All required GUI attributes present")
        
        # Test that provider info is properly configured
        provider_names = [p[0] for p in gui.providers_info]
        expected_providers = ["virustotal", "abuseipdb", "otx", "threatfox", "urlhaus", "malwarebazaar", "greynoise", "pulsedive", "shodan"]
        
        for provider in expected_providers:
            assert provider in provider_names, f"Provider {provider} missing from GUI"
        
        print("✅ All expected providers present in GUI")
        
        # Test API key configuration
        assert len(gui.api_keys) >= 7, f"Expected at least 7 API keys, got {len(gui.api_keys)}"
        print("✅ API keys properly configured")
        
        gui.root.destroy()
        root.destroy()
        
    except Exception as e:
        print(f"❌ Main GUI integration test failed: {e}")
        return False
    
    return True


def run_all_tests():
    """Run all tests and report results."""
    print("🚀 Starting comprehensive dialog enhancement tests...\n")
    
    tests = [
        ("Basic Configuration Dialog", test_basic_configuration_dialog),
        ("API Key Dialog", test_api_key_dialog),
        ("Provider Selection Dialog", test_provider_selection_dialog),
        ("Dialog Creation Functions", test_dialog_creation_functions),
        ("Main GUI Integration", test_main_gui_integration),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n📋 Running: {test_name}")
        print("-" * 50)
        
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name}: PASSED")
            else:
                print(f"❌ {test_name}: FAILED")
        except Exception as e:
            print(f"❌ {test_name}: FAILED with exception: {e}")
    
    print("\n" + "="*60)
    print(f"📊 TEST RESULTS: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! Dialog enhancements are working correctly.")
        return True
    else:
        print("⚠️  Some tests failed. Please check the output above.")
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
