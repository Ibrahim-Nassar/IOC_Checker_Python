#!/usr/bin/env python3
"""
Demo script to showcase the enhanced API Key Configuration and Provider Selection dialogs.
"""
import sys
import os
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from dialog_templates import create_api_key_dialog, create_provider_selection_dialog, STANDARD_API_KEY_CONFIGS


def demo_api_key_dialog():
    """Demonstrate the enhanced API Key Configuration dialog."""
    print("Opening API Key Configuration dialog...")
    
    # Sample current API keys (mix of set and unset)
    current_keys = {
        "virustotal": "vt_demo_key_12345",
        "abuseipdb": "",
        "otx": "otx_demo_key_67890",
        "threatfox": "",
        "greynoise": "gn_demo_key_abcde",
        "pulsedive": "",
        "shodan": ""
    }
    
    def save_api_keys():
        """Save callback for API keys."""
        keys = dialog.get_api_keys()
        print("\n🔑 API Keys to save:")
        for key_id, value in keys.items():
            if value.strip():
                print(f"  {key_id}: {value[:10]}..." if len(value) > 10 else f"  {key_id}: {value}")
            else:
                print(f"  {key_id}: (not set)")
        
        messagebox.showinfo("API Keys Saved", 
            f"Successfully saved {len([k for k in keys.values() if k.strip()])} API keys!\n\n"
            "In a real application, these would be saved to:\n"
            "• Environment variables for current session\n"
            "• .env file for persistence")
        dialog.dialog.destroy()
    
    dialog = create_api_key_dialog(root, STANDARD_API_KEY_CONFIGS, current_keys, save_api_keys)
    dialog.show()


def demo_provider_selection_dialog():
    """Demonstrate the enhanced Provider Selection dialog."""
    print("Opening Provider Selection dialog...")
    
    # Provider information (matches what's in the actual app)
    providers_info = [
        ("virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", "Universal threat intelligence platform", ["ip", "domain", "url", "hash"]),
        ("abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", "IP reputation and abuse reports", ["ip"]),
        ("otx", "AlienVault OTX", "OTX_API_KEY", "Open threat exchange platform", ["ip", "domain", "url", "hash"]),
        ("threatfox", "ThreatFox", "THREATFOX_API_KEY", "Malware IOCs from abuse.ch", ["ip", "domain", "url", "hash"]),
        ("urlhaus", "URLHaus", None, "Malicious URL database (abuse.ch)", ["url"]),
        ("malwarebazaar", "MalwareBazaar", None, "Malware sample database (abuse.ch)", ["hash"]),
        ("greynoise", "GreyNoise", "GREYNOISE_API_KEY", "Internet background noise analysis", ["ip"]),
        ("pulsedive", "Pulsedive", "PULSEDIVE_API_KEY", "Threat intelligence platform", ["ip", "domain", "url"]),
        ("shodan", "Shodan", "SHODAN_API_KEY", "Internet-connected devices search", ["ip"]),
    ]
    
    # Sample current selection (some providers enabled)
    current_selection = {
        "virustotal": True,
        "abuseipdb": True,
        "otx": False,
        "threatfox": True,
        "urlhaus": True,
        "malwarebazaar": False,
        "greynoise": False,
        "pulsedive": False,
        "shodan": False
    }
    
    def save_provider_selection():
        """Save callback for provider selection."""
        selection = dialog.get_selected_providers()
        selected = [provider for provider, enabled in selection.items() if enabled]
        
        print("\n🔍 Selected providers:")
        for provider in selected:
            print(f"  ✅ {provider}")
        
        if not selected:
            print("  (No providers selected)")
        
        messagebox.showinfo("Provider Selection Saved", 
            f"Selected {len(selected)} providers:\n\n" + 
            "\n".join([f"• {p}" for p in selected[:5]]) +
            (f"\n• ... and {len(selected)-5} more" if len(selected) > 5 else "") +
            "\n\nIn a real application, these selections would be saved and used for IOC checking.")
        dialog.dialog.destroy()
    
    dialog = create_provider_selection_dialog(root, providers_info, current_selection, save_provider_selection)
    dialog.show()


def create_demo_menu():
    """Create a demo menu to showcase both dialogs."""
    # Create main demo window
    demo_frame = ttk.Frame(root, padding=20)
    demo_frame.pack(fill="both", expand=True)
    
    # Title
    title_label = ttk.Label(demo_frame, text="IOC Checker - Enhanced Dialogs Demo", 
                           font=("TkDefaultFont", 14, "bold"))
    title_label.pack(pady=(0, 30))
    
    # Description
    desc_text = """This demo showcases the enhanced configuration dialogs with:

✅ Consistent Save buttons across all configuration dialogs
✅ Complete provider coverage (all 9 supported providers)
✅ Improved API Key Configuration with show/hide functionality
✅ Provider Selection with IOC type filtering
✅ Professional UI/UX with proper error handling
✅ Template system for future configuration dialogs"""
    
    desc_label = ttk.Label(demo_frame, text=desc_text, justify="left")
    desc_label.pack(pady=(0, 30))
    
    # Buttons
    button_frame = ttk.Frame(demo_frame)
    button_frame.pack(pady=20)
    
    api_button = ttk.Button(button_frame, text="🔑 API Key Configuration", 
                           command=demo_api_key_dialog, width=25)
    api_button.pack(pady=10)
    
    provider_button = ttk.Button(button_frame, text="🔍 Provider Selection", 
                                command=demo_provider_selection_dialog, width=25)
    provider_button.pack(pady=10)
    
    # Info
    info_text = """Both dialogs include:
• Proper Save/Cancel button layout
• Input validation and error handling  
• Consistent styling and behavior
• Template-based design for future dialogs"""
    
    info_label = ttk.Label(demo_frame, text=info_text, justify="left", 
                          font=("TkDefaultFont", 8), foreground="gray")
    info_label.pack(pady=(20, 0))


if __name__ == "__main__":
    print("🚀 Starting Enhanced Dialogs Demo...")
    
    # Create main window
    root = tk.Tk()
    root.title("IOC Checker - Enhanced Dialogs Demo")
    root.geometry("500x450")
    
    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (500 // 2)
    y = (root.winfo_screenheight() // 2) - (450 // 2)
    root.geometry(f"+{x}+{y}")
    
    try:
        create_demo_menu()
        print("✅ Demo window created successfully")
        print("👆 Use the buttons in the demo window to test the enhanced dialogs")
        root.mainloop()
    except Exception as e:
        print(f"❌ Demo failed: {e}")
        messagebox.showerror("Demo Error", f"Failed to run demo: {e}")
    
    print("Demo completed.")
