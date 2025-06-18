#!/usr/bin/env python3
"""
Test script for dark mode toggle functionality
"""

import tkinter as tk
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

try:
    import sv_ttk
    SV_TTK_AVAILABLE = True
except ImportError:
    SV_TTK_AVAILABLE = False
    print("Warning: sv-ttk not available for testing")

def test_dark_mode_toggle():
    """Test the dark mode toggle functionality."""
    print("Testing dark mode toggle functionality...")
    
    if not SV_TTK_AVAILABLE:
        print("❌ sv-ttk not available - dark mode test skipped")
        return False
    
    try:
        # Create a test root window
        root = tk.Tk()
        root.withdraw()  # Hide the window
        
        # Test initial theme (should be light/vista)
        current_theme = sv_ttk.get_theme()
        print(f"Initial theme: {current_theme}")
        assert current_theme in ("light", "vista"), f"Initial theme should be light/vista, got {current_theme}"
        
        # Test setting dark theme
        sv_ttk.set_theme("dark")
        current_theme = sv_ttk.get_theme()
        print(f"After setting dark: {current_theme}")
        assert current_theme == "dark", f"Theme should be dark after setting, got {current_theme}"
        
        # Test setting light theme
        sv_ttk.set_theme("light")
        current_theme = sv_ttk.get_theme()
        print(f"After setting light: {current_theme}")
        assert current_theme == "light", f"Theme should be light after setting, got {current_theme}"
        
        # Clean up
        root.destroy()
        
        print("✅ Dark mode toggle test passed")
        return True
        
    except Exception as e:
        print(f"❌ Dark mode toggle test failed: {e}")
        return False

def test_gui_dark_mode_integration():
    """Test the GUI integration with dark mode."""
    print("\nTesting GUI dark mode integration...")
    
    try:
        from ioc_gui_tk import IOCCheckerGUI
        
        # Create GUI instance
        gui = IOCCheckerGUI()
        
        # Check if dark mode variable exists when sv-ttk is available
        if SV_TTK_AVAILABLE:
            assert hasattr(gui, 'dark_mode'), "GUI should have dark_mode variable when sv-ttk is available"
            assert hasattr(gui, 'toggle_theme'), "GUI should have toggle_theme method"
            
            # Test toggle method exists and is callable
            assert callable(gui.toggle_theme), "toggle_theme should be callable"
            
            # Test initial state
            assert gui.dark_mode.get() == False, "Dark mode should be initially disabled"
            
            print("✅ GUI dark mode integration test passed")
        else:
            print("⚠️ sv-ttk not available - GUI integration test limited")
            
        # Clean up
        gui.root.destroy()
        return True
        
    except Exception as e:
        print(f"❌ GUI dark mode integration test failed: {e}")
        return False

def test_manual_toggle():
    """Test manual dark mode toggle (requires sv-ttk)."""
    print("\nTesting manual dark mode toggle...")
    
    if not SV_TTK_AVAILABLE:
        print("⚠️ sv-ttk not available - manual toggle test skipped")
        return True
    
    try:
        from ioc_gui_tk import IOCCheckerGUI
        
        # Create GUI instance
        gui = IOCCheckerGUI()
        
        # Test manual toggle
        initial_theme = sv_ttk.get_theme()
        print(f"Initial theme: {initial_theme}")
        
        # Enable dark mode
        gui.dark_mode.set(True)
        gui.toggle_theme()
        current_theme = sv_ttk.get_theme()
        print(f"After enabling dark mode: {current_theme}")
        assert current_theme == "dark", f"Theme should be dark, got {current_theme}"
        
        # Disable dark mode
        gui.dark_mode.set(False)
        gui.toggle_theme()
        current_theme = sv_ttk.get_theme()
        print(f"After disabling dark mode: {current_theme}")
        assert current_theme == "light", f"Theme should be light, got {current_theme}"
        
        # Clean up
        gui.root.destroy()
        
        print("✅ Manual dark mode toggle test passed")
        return True
        
    except Exception as e:
        print(f"❌ Manual dark mode toggle test failed: {e}")
        return False

if __name__ == "__main__":
    print("=== Dark Mode Functionality Tests ===\n")
    
    # Run all tests
    results = []
    results.append(test_dark_mode_toggle())
    results.append(test_gui_dark_mode_integration())
    results.append(test_manual_toggle())
    
    # Summary
    passed = sum(results)
    total = len(results)
    
    print(f"\n=== Test Summary ===")
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("🎉 All dark mode tests passed!")
    else:
        print("⚠️ Some tests failed or were skipped")
    
    if SV_TTK_AVAILABLE:
        print("\n✅ sv-ttk is available - dark mode is fully functional")
    else:
        print("\n❌ sv-ttk is not available - please install with: pip install sv-ttk")