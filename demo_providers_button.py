#!/usr/bin/env python3
"""
Demonstration script for the Providers button functionality.
This script shows how the new Providers button allows users to select which 
threat intelligence providers to use for IOC checking.
"""
import os
import tkinter as tk
from ioc_gui_tk import IOCCheckerGUI

def demo_providers_button():
    """Demonstrate the Providers button functionality."""
    
    print("IOC Checker GUI - Provider Selection Demo")
    print("=" * 45)
    print()
    print("Setting up demo environment with sample API keys...")
    
    # Set up some demo environment variables
    demo_env = {
        'VIRUSTOTAL_API_KEY': 'demo_virustotal_key_12345',
        'ABUSEIPDB_API_KEY': 'demo_abuseipdb_key_67890',
        'SHODAN_API_KEY': 'demo_shodan_key_abcdef'
        # Note: GREYNOISE_API_KEY and others are not set to demonstrate "Not Set" status
    }
    
    # Apply demo environment
    for key, value in demo_env.items():
        os.environ[key] = value
        print(f"Set {key}: {value[:20]}...")
    
    print()
    print("Starting IOC Checker GUI...")
    print("=" * 45)
    print("USAGE INSTRUCTIONS:")
    print("1. Look for the 'Providers' button in the bottom-right area")
    print("2. Click it to open the provider selection dialog")
    print("3. Select/deselect providers you want to use")
    print("4. Providers with ✓ have API keys configured")
    print("5. Providers with ✗ need API keys to be fully functional")
    print("6. Use 'Select All' or 'Clear All' for quick selection")
    print("7. Click 'Save' to apply your selection")
    print("8. Test IOC checking with your selected providers")
    print()
    print("The selection dialog shows:")
    print("- All supported threat intelligence providers")
    print("- API key status (Available/Missing) for each provider")
    print("- Description of each provider's capabilities")
    print("- Checkboxes to enable/disable each provider")
    print("- Selected providers will be used for IOC checking")
    
    try:
        # Create and run the GUI
        gui = IOCCheckerGUI()
        
        # Add a custom message to the GUI window title
        gui.root.title("IOC Checker - Provider Selection Demo")
        
        print()
        print("GUI is now running. Try the following:")
        print("- Click 'Providers' button to select providers")
        print("- Enter an IOC and click 'Check' to test with selected providers")
        print("- Close the window to exit.")
        gui.run()
        
    except Exception as e:
        print(f"Error running GUI: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    demo_providers_button()
