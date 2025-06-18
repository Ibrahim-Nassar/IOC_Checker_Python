#!/usr/bin/env python3
"""
Dialog templates for consistent UI/UX across the IOC Checker application.

This module provides templates and utilities for creating configuration dialogs
with consistent layout, save functionality, and user experience.
"""
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox
from typing import Callable, Dict, Any, Optional, List, Tuple
import os


class ConfigurationDialog:
    """Base class for configuration dialogs with consistent layout and behavior."""
    
    def __init__(self, parent: tk.Tk, title: str, width: int = 600, height: int = 500):
        """Initialize the configuration dialog."""
        self.parent = parent
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry(f"{width}x{height}")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self._center_dialog()
        
        # Main frame with consistent padding
        self.main_frame = ttk.Frame(self.dialog, padding=20)
        self.main_frame.pack(fill="both", expand=True)
        
        # Title label
        self.title_label = ttk.Label(
            self.main_frame, 
            text=title, 
            font=("TkDefaultFont", 12, "bold")
        )
        self.title_label.pack(pady=(0, 20))
        
        # Content frame (to be populated by subclasses)
        self.content_frame = ttk.Frame(self.main_frame)
        self.content_frame.pack(fill="both", expand=True, pady=(0, 20))
        
        # Buttons frame
        self.buttons_frame = ttk.Frame(self.main_frame)
        self.buttons_frame.pack(fill="x")
        
        # Store callbacks
        self.save_callback: Optional[Callable] = None
        self.test_callback: Optional[Callable] = None
        self.cancel_callback: Optional[Callable] = None
        
        self._setup_default_buttons()
    
    def _center_dialog(self):
        """Center the dialog on the parent window."""
        self.dialog.geometry("+%d+%d" % (
            self.parent.winfo_rootx() + 50,
            self.parent.winfo_rooty() + 50
        ))
    
    def _setup_default_buttons(self):
        """Setup default Save, Test, and Cancel buttons."""
        # Save button (always present)
        self.save_button = ttk.Button(
            self.buttons_frame, 
            text="Save", 
            command=self._handle_save
        )
        self.save_button.pack(side="left", padx=(0, 10))
        
        # Test button (optional, can be hidden)
        self.test_button = ttk.Button(
            self.buttons_frame, 
            text="Test", 
            command=self._handle_test
        )
        self.test_button.pack(side="left", padx=(0, 10))
        
        # Cancel button
        self.cancel_button = ttk.Button(
            self.buttons_frame, 
            text="Cancel", 
            command=self._handle_cancel
        )
        self.cancel_button.pack(side="right")
    
    def _handle_save(self):
        """Handle save button click."""
        if self.save_callback:
            try:
                self.save_callback()
            except Exception as e:
                messagebox.showerror("Save Error", f"Failed to save configuration:\n{e}")
        else:
            messagebox.showinfo("Save", "Save functionality not implemented.")
    
    def _handle_test(self):
        """Handle test button click."""
        if self.test_callback:
            try:
                self.test_callback()
            except Exception as e:
                messagebox.showerror("Test Error", f"Test failed:\n{e}")
        else:
            messagebox.showinfo("Test", "Test functionality not implemented.")
    
    def _handle_cancel(self):
        """Handle cancel button click."""
        if self.cancel_callback:
            self.cancel_callback()
        else:
            self.dialog.destroy()
    
    def set_save_callback(self, callback: Callable):
        """Set the save callback function."""
        self.save_callback = callback
    
    def set_test_callback(self, callback: Callable):
        """Set the test callback function."""
        self.test_callback = callback
    
    def set_cancel_callback(self, callback: Callable):
        """Set the cancel callback function."""
        self.cancel_callback = callback
    
    def hide_test_button(self):
        """Hide the test button if not needed."""
        self.test_button.pack_forget()
    
    def show_test_button(self):
        """Show the test button if needed."""
        self.test_button.pack(side="left", padx=(0, 10))
    
    def add_description(self, text: str, wrap_length: int = 550):
        """Add a description text below the title."""
        desc_label = ttk.Label(
            self.main_frame, 
            text=text, 
            justify="left",
            wraplength=wrap_length
        )
        desc_label.pack(pady=(0, 20), anchor="w")
    
    def show(self):
        """Show the dialog and wait for it to close."""
        self.dialog.wait_window()


class APIKeyConfigDialog(ConfigurationDialog):
    """Specialized dialog for API key configuration."""
    
    def __init__(self, parent: tk.Tk, api_configs: List[Tuple[str, str, str]], 
                 current_keys: Dict[str, str]):
        """
        Initialize API key configuration dialog.
        
        Args:
            parent: Parent window
            api_configs: List of (key_id, display_name, description) tuples
            current_keys: Current API key values
        """
        super().__init__(parent, "API Key Configuration", 600, 500)
        
        self.api_configs = api_configs
        self.current_keys = current_keys
        self.api_key_vars = {}
        
        self._setup_api_key_content()
    
    def _setup_api_key_content(self):
        """Setup API key entry fields."""
        # Description
        desc_text = """Enter your API keys below. Get free API keys from:
• VirusTotal: https://www.virustotal.com/gui/my-apikey
• AbuseIPDB: https://www.abuseipdb.com/register
• Others are optional for enhanced analysis"""
        
        desc_label = ttk.Label(self.content_frame, text=desc_text, justify="left")
        desc_label.pack(pady=(0, 20), anchor="w")
        
        # Entries frame with scrolling support
        entries_frame = ttk.Frame(self.content_frame)
        entries_frame.pack(fill="both", expand=True, pady=(0, 20))
        
        # Note about free services
        note_text = "Note: URLHaus and MalwareBazaar (abuse.ch) are free services that don't require API keys."
        note_label = ttk.Label(
            entries_frame, 
            text=note_text, 
            font=("TkDefaultFont", 8), 
            foreground="blue", 
            wraplength=550
        )
        note_label.pack(anchor="w", pady=(0, 10))
        
        # API key entry fields
        for key_id, name, desc in self.api_configs:
            frame = ttk.LabelFrame(entries_frame, text=f"{name} API Key", padding=10)
            frame.pack(fill="x", pady=5)
            
            # Description
            desc_label = ttk.Label(frame, text=desc, font=("TkDefaultFont", 8))
            desc_label.pack(anchor="w")
            
            # Entry field
            self.api_key_vars[key_id] = tk.StringVar(value=self.current_keys.get(key_id, ''))
            entry = ttk.Entry(
                frame, 
                textvariable=self.api_key_vars[key_id], 
                width=60, 
                show="*" if self.api_key_vars[key_id].get() else ""
            )
            entry.pack(fill="x", pady=(5, 0))
            
            # Show/Hide button
            def toggle_visibility(entry_widget, key_id=key_id):
                current_show = entry_widget.cget("show")
                entry_widget.config(show="" if current_show == "*" else "*")
            
            show_btn = ttk.Button(
                frame, 
                text="Show/Hide", 
                command=lambda e=entry: toggle_visibility(e)
            )
            show_btn.pack(anchor="e", pady=(2, 0))
    
    def get_api_keys(self) -> Dict[str, str]:
        """Get the current API key values from the dialog."""
        return {key: var.get().strip() for key, var in self.api_key_vars.items()}


class ProviderSelectionDialog(ConfigurationDialog):
    """Specialized dialog for provider selection with filtering."""
    
    def __init__(self, parent: tk.Tk, providers_info: List[Tuple], 
                 current_selection: Dict[str, bool]):
        """
        Initialize provider selection dialog.
        
        Args:
            parent: Parent window
            providers_info: List of provider information tuples
            current_selection: Current provider selection state
        """
        super().__init__(parent, "Provider Selection", 700, 600)
        
        self.providers_info = providers_info
        self.current_selection = current_selection
        self.provider_vars = {}
        
        self._setup_provider_content()
        self.hide_test_button()  # Not needed for provider selection
    
    def _setup_provider_content(self):
        """Setup provider selection content."""
        # Description
        desc_text = """Select which threat intelligence providers to use for IOC checking.
Each provider supports different types of IOCs (IP, Domain, URL, Hash)."""
        
        desc_label = ttk.Label(self.content_frame, text=desc_text, justify="left")
        desc_label.pack(pady=(0, 20), anchor="w")
        
        # Filter frame
        filter_frame = ttk.LabelFrame(self.content_frame, text="Filter by IOC Type", padding=10)
        filter_frame.pack(fill="x", pady=(0, 20))
        
        # IOC type filter checkboxes
        self.filter_vars = {}
        filter_inner = ttk.Frame(filter_frame)
        filter_inner.pack(fill="x")
        
        for ioc_type in ["ip", "domain", "url", "hash"]:
            self.filter_vars[ioc_type] = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(
                filter_inner, 
                text=ioc_type.upper(), 
                variable=self.filter_vars[ioc_type],
                command=self._apply_filter
            )
            cb.pack(side="left", padx=(0, 20))
        
        # Providers frame with scrolling
        providers_container = ttk.Frame(self.content_frame)
        providers_container.pack(fill="both", expand=True)
        
        canvas = tk.Canvas(providers_container)
        scrollbar = ttk.Scrollbar(providers_container, orient="vertical", command=canvas.yview)
        self.providers_frame = ttk.Frame(canvas)
        
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.create_window((0, 0), window=self.providers_frame, anchor="nw")
        
        def configure_scroll_region(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
        
        self.providers_frame.bind("<Configure>", configure_scroll_region)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.provider_canvas = canvas
        self._create_provider_checkboxes()
    
    def _create_provider_checkboxes(self):
        """Create provider checkboxes."""
        for provider_id, name, env_var, description, supported_types in self.providers_info:
            frame = ttk.LabelFrame(self.providers_frame, text=name, padding=10)
            frame.pack(fill="x", pady=5, padx=10)
            
            # Checkbox and description
            self.provider_vars[provider_id] = tk.BooleanVar(
                value=self.current_selection.get(provider_id, False)
            )
            
            cb = ttk.Checkbutton(
                frame, 
                text=f"Enable {name}", 
                variable=self.provider_vars[provider_id]
            )
            cb.pack(anchor="w")
            
            # Description and supported types
            desc_text = f"{description}\nSupported IOC types: {', '.join(supported_types).upper()}"
            desc_label = ttk.Label(frame, text=desc_text, font=("TkDefaultFont", 8))
            desc_label.pack(anchor="w", pady=(5, 0))
            
            # API key status
            if env_var:
                api_key = os.getenv(env_var, "").strip()
                status = "✅ API key configured" if api_key else "❌ No API key"
                status_label = ttk.Label(frame, text=status, font=("TkDefaultFont", 8))
                status_label.pack(anchor="w")
    
    def _apply_filter(self):
        """Apply IOC type filter to provider list."""
        selected_types = [ioc_type for ioc_type, var in self.filter_vars.items() if var.get()]
        
        for child in self.providers_frame.winfo_children():
            child.pack_forget()
        
        for provider_id, name, env_var, description, supported_types in self.providers_info:
            # Show provider if it supports any of the selected IOC types
            if not selected_types or any(ioc_type in supported_types for ioc_type in selected_types):
                self._show_provider(provider_id, name, env_var, description, supported_types)
    
    def _show_provider(self, provider_id, name, env_var, description, supported_types):
        """Show a single provider checkbox."""
        frame = ttk.LabelFrame(self.providers_frame, text=name, padding=10)
        frame.pack(fill="x", pady=5, padx=10)
        
        if provider_id not in self.provider_vars:
            self.provider_vars[provider_id] = tk.BooleanVar(
                value=self.current_selection.get(provider_id, False)
            )
        
        cb = ttk.Checkbutton(
            frame, 
            text=f"Enable {name}", 
            variable=self.provider_vars[provider_id]
        )
        cb.pack(anchor="w")
        
        desc_text = f"{description}\nSupported IOC types: {', '.join(supported_types).upper()}"
        desc_label = ttk.Label(frame, text=desc_text, font=("TkDefaultFont", 8))
        desc_label.pack(anchor="w", pady=(5, 0))
        
        if env_var:
            api_key = os.getenv(env_var, "").strip()
            status = "✅ API key configured" if api_key else "❌ No API key"
            status_label = ttk.Label(frame, text=status, font=("TkDefaultFont", 8))
            status_label.pack(anchor="w")
    
    def get_selected_providers(self) -> Dict[str, bool]:
        """Get the current provider selection state."""
        return {provider_id: var.get() for provider_id, var in self.provider_vars.items()}


# Utility functions for creating standard dialogs
def create_api_key_dialog(parent: tk.Tk, api_configs: List[Tuple[str, str, str]], 
                         current_keys: Dict[str, str], save_callback: Callable) -> APIKeyConfigDialog:
    """Create a standard API key configuration dialog."""
    dialog = APIKeyConfigDialog(parent, api_configs, current_keys)
    dialog.set_save_callback(save_callback)
    return dialog


def create_provider_selection_dialog(parent: tk.Tk, providers_info: List[Tuple], 
                                   current_selection: Dict[str, bool], 
                                   save_callback: Callable) -> ProviderSelectionDialog:
    """Create a standard provider selection dialog."""
    dialog = ProviderSelectionDialog(parent, providers_info, current_selection)
    dialog.set_save_callback(save_callback)
    return dialog


# Standard dialog configurations
STANDARD_API_KEY_CONFIGS = [
    ("virustotal", "VirusTotal", "Required for malware/URL analysis"),
    ("abuseipdb", "AbuseIPDB", "Required for IP reputation"),
    ("otx", "AlienVault OTX", "Optional - Open threat exchange"),
    ("threatfox", "ThreatFox", "Optional - Malware IOCs from abuse.ch"),
    ("greynoise", "GreyNoise", "Optional - Advanced IP analysis"),
    ("pulsedive", "Pulsedive", "Optional - Threat intelligence platform"),
    ("shodan", "Shodan", "Optional - Infrastructure analysis"),
]
