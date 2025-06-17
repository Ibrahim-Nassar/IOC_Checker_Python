#!/usr/bin/env python3
"""
Tkinter GUI for IOC checking with format-agnostic input, live progress bar, and provider selection.
• Drag & Drop • Format detection • Real-time progress • Provider selection dialog • Subprocess integration
• Menu-based settings • Dark/Light theme toggle • Enhanced visual hierarchy
"""
import tkinter as tk
import ttkbootstrap as tb
from ttkbootstrap.constants import *
from tkinter import filedialog, messagebox
import subprocess
import sys
import queue
import os
import re
import logging
from loader import load_iocs

# ttkbootstrap is now the primary theming system
TTKBOOTSTRAP_AVAILABLE = True

log = logging.getLogger("gui")

SCRIPT = "ioc_checker.py"
PYTHON = sys.executable
IOC_TYPES = ("ip", "domain", "url", "hash")
COLORS = {
    'threat': '#FF4444',
    'clean':  '#00AA00',
    'warning':'#FF8800',
    'error':  '#CC0000',
    'info':   '#0066CC',
    'default':'#000000'
}

# Dark mode color scheme
DARK_COLORS = {
    'threat': '#FF6666',
    'clean':  '#44DD44', 
    'warning':'#FFB347',
    'error':  '#FF4444',
    'info':   '#66B3FF',
    'default':'#FFFFFF'
}

# Theme configurations
THEMES = {
    'light': {
        'bg': '#FFFFFF',
        'fg': '#000000',
        'select_bg': '#0078D4',
        'select_fg': '#FFFFFF',
        'entry_bg': '#FFFFFF',
        'entry_fg': '#000000',
        'button_bg': '#F0F0F0',
        'colors': COLORS
    },
    'dark': {
        'bg': '#2B2B2B',
        'fg': '#FFFFFF', 
        'select_bg': '#404040',
        'select_fg': '#FFFFFF',
        'entry_bg': '#404040',
        'entry_fg': '#FFFFFF',
        'button_bg': '#404040',
        'colors': DARK_COLORS
    }
}

# Enhanced color schemes
ENHANCED_THEMES = {
    'light': {
        'bg': '#FFFFFF',
        'fg': '#000000',
        'select_bg': '#0078D4',
        'select_fg': '#FFFFFF',
        'entry_bg': '#FFFFFF',
        'entry_fg': '#000000',
        'button_bg': '#F0F0F0',
        'primary_button': '#0078D4',
        'danger_button': '#D13438',
        'colors': {
            'threat': '#D13438',
            'clean': '#107C10',
            'warning': '#FF8C00',
            'error': '#D13438',
            'info': '#0078D4',
            'default': '#000000'
        }
    },
    'dark': {
        'bg': '#2B2B2B',
        'fg': '#FFFFFF',
        'select_bg': '#404040',
        'select_fg': '#FFFFFF',
        'entry_bg': '#404040',
        'entry_fg': '#FFFFFF',
        'button_bg': '#404040',
        'primary_button': '#0078D4',
        'danger_button': '#FF6B6B',
        'colors': {
            'threat': '#FF6B6B',
            'clean': '#51CF66',
            'warning': '#FFD43B',
            'error': '#FF6B6B',
            'info': '#74C0FC',
            'default': '#FFFFFF'
        }
    }
}

# Provider configuration
AVAILABLE_PROVIDERS = {
    'abuseipdb': 'AbuseIPDB (IP reputation)',
    'otx': 'AlienVault OTX (Multi-IOC)',
    'threatfox': 'ThreatFox (IOC database)',
    'urlhaus': 'URLhaus (Malicious URLs)',
    'malwarebazaar': 'MalwareBazaar (Hash database)',
    'virustotal': 'VirusTotal (Multi-engine)',
    'greynoise': 'GreyNoise (IP intelligence)',
    'pulsedive': 'Pulsedive (Threat intel)',
    'shodan': 'Shodan (Device search)'
}

# Default always-on providers (can be customized by user)
DEFAULT_ALWAYS_ON = ['abuseipdb', 'otx']

def _classify(line: str) -> str:
    # Enhanced classification for better output handling
    if ("🚨" in line or 
        re.search(r"(Malicious|Suspicious):[1-9]", line) or 
        "Found in" in line or
        "MALICIOUS" in line.upper()):
        return "threat"
    if any(t in line for t in ("✅", "Clean", "Not found", "Whitelisted", "completed")):
        return "clean"
    if any(t in line for t in ("⚠️", "Suspicious", "Medium", "WARNING")):
        return "warning"
    if ("❌" in line or "ERROR" in line or 
        line.startswith("Processing IOC: ERROR") or
        line.startswith("Result: ERROR") or
        "Process error:" in line or
        "Failed to process" in line):
        return "error"
    if (any(t in line for t in ("ℹ️", "INFO", "🔢", "🔍", "💻", "📁", "🚀", "📂", "🎯")) or
        line.startswith("===") or
        "Command:" in line or
        "Output will be saved" in line or
        "Processing limit set" in line or
        "Active providers:" in line):
        return "info"
    # Handle IOC processing messages
    if line.startswith("Processing IOC:") and "ERROR" not in line:
        return "info"
    if line.startswith("Result:") and "ERROR" not in line:
        return "clean"
    return "default"

def _should_show(line: str, only: bool) -> bool:
    """Return True if the line should appear given the 'only threats' setting."""
    if not only:
        return True

    # Always keep high-level progress / errors
    if any(k in line.lower() for k in ("starting", "completed", "error")):
        return True

    # Explicit threat markers
    if ("🚨" in line or 
        "⚠️" in line or 
        "Found in" in line):
        return True

    # Malicious / Suspicious counts > 0
    if re.search(r"(Malicious|Suspicious):[1-9]", line):
        return True

    return False

class ProviderDlg:
    """Provider selection dialog with checkboxes for each provider."""
    
    def __init__(self, parent, config=None, theme='light'):
        self.parent = parent
        self.result = None
        self.vars = {}
        self.theme = theme
          # Default configuration
        default_config = {provider: False for provider in AVAILABLE_PROVIDERS.keys()}
        default_config.update({'abuseipdb': True, 'otx': True})  # Default always-on providers
        
        if config:
            default_config.update(config)
        
        self._build_dialog(default_config)
    
    def _build_dialog(self, config):
        """Build the provider selection dialog."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Select Threat Intelligence Providers")
        self.dialog.geometry("600x600")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Apply theme to dialog
        theme = THEMES[self.theme]
        self.dialog.configure(bg=theme['bg'])
        
        # Handle window close button (X) to cancel
        self.dialog.protocol("WM_DELETE_WINDOW", self._cancel)
          # Center the dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (600 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (600 // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        main_frame = tb.Frame(self.dialog, padding=20)
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = tb.Label(main_frame, text="Select Threat Intelligence Providers", 
                               font=('Arial', 14, 'bold'))
        title_label.pack(anchor='w', pady=(0, 15))
        
        # Instructions
        instructions = tb.Label(main_frame, 
                                text="Choose which threat intelligence providers to query.\n"
                                     "Check 'Always On' to make a provider permanently enabled.",
                                foreground='gray')
        instructions.pack(anchor='w', pady=(0, 10))
        
        # Filter section
        filter_frame = tb.Frame(main_frame)
        filter_frame.pack(fill='x', pady=(0, 15))
        
        tb.Label(filter_frame, text="Filter by IOC type:").pack(side='left')
        self.filter_var = tk.StringVar(value="all")
        filter_combo = tb.Combobox(filter_frame, textvariable=self.filter_var, 
                                   values=["all", "ip", "domain", "url", "hash"], 
                                   state="readonly", width=10)
        filter_combo.pack(side='left', padx=(10, 0))
        filter_combo.bind('<<ComboboxSelected>>', self._on_filter_change)
        
        # Create a simple frame for the provider list (remove problematic scrolling)
        list_container = tb.Frame(main_frame)
        list_container.pack(fill='both', expand=True, pady=(0, 15))
          # Add a canvas with scrollbar for the provider list
        canvas = tk.Canvas(list_container, height=250, bg=theme['bg'], highlightthickness=0)
        scrollbar = tb.Scrollbar(list_container, orient="vertical", command=canvas.yview)
        self.list_frame = tb.Frame(canvas)
        
        self.list_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar properly
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Build provider widgets
        self._build_provider_widgets(config)
        
        # Buttons frame - ensure it's separate from the scrollable area
        button_frame = tb.Frame(main_frame)
        button_frame.pack(fill='x', pady=(15, 0))
        
        # Left side buttons
        left_buttons = tb.Frame(button_frame)
        left_buttons.pack(side='left')
        
        tb.Button(left_buttons, text="Select All", command=self._select_all).pack(side='left')
        tb.Button(left_buttons, text="Select None", command=self._select_none).pack(side='left', padx=(10, 0))
        tb.Button(left_buttons, text="Defaults", command=self._select_defaults).pack(side='left', padx=(10, 0))
          # Right side buttons
        right_buttons = tb.Frame(button_frame)
        right_buttons.pack(side='right')
        
        tb.Button(right_buttons, text="Cancel", command=self._cancel).pack(side='right', padx=(10, 0))
        save_button = tb.Button(right_buttons, text="Save", command=self.ok)
        save_button.pack(side='right')
        
        # Bind Enter and Escape
        self.dialog.bind('<Return>', lambda e: self.ok())
        self.dialog.bind('<Escape>', lambda e: self._cancel())
        
        # Focus on Save button
        save_button.focus_set()
    
    def _build_provider_widgets(self, config):
        """Build the provider widgets."""
        # Clear existing widgets
        for widget in self.list_frame.winfo_children():
            widget.destroy()
        
        # Get provider compatibility info with fallback
        try:
            from providers import ALWAYS_ON, RATE_LIMIT
            all_providers = list(ALWAYS_ON) + list(RATE_LIMIT)
            provider_capabilities = {p.name: p.ioc_kinds for p in all_providers}
        except ImportError:
            # Fallback if providers module not available
            provider_capabilities = {
                'abuseipdb': ('ip',),
                'otx': ('ip', 'domain', 'url', 'hash'),
                'threatfox': ('ip', 'domain', 'url', 'hash'),
                'urlhaus': ('url', 'domain'),
                'malwarebazaar': ('hash',),
                'virustotal': ('ip', 'domain', 'url', 'hash'),
                'greynoise': ('ip',),
                'pulsedive': ('ip', 'domain', 'url', 'hash'),
                'shodan': ('ip',)
            }
        
        # Filter providers based on selected IOC type
        selected_ioc_type = self.filter_var.get()
        
        for i, (provider, description) in enumerate(AVAILABLE_PROVIDERS.items()):
            # Check if provider should be shown based on filter
            if selected_ioc_type != "all":
                provider_ioc_kinds = provider_capabilities.get(provider, ())
                if selected_ioc_type not in provider_ioc_kinds:
                    continue
            
            # Create or get existing variable - preserve existing state
            if provider not in self.vars:
                var = tk.BooleanVar(value=config.get(provider, False))
                self.vars[provider] = var
            else:
                # Update value but keep existing variable to preserve state
                self.vars[provider].set(config.get(provider, self.vars[provider].get()))
            
            var = self.vars[provider]
              # Main provider frame
            provider_frame = tb.Frame(self.list_frame)
            provider_frame.pack(fill='x', pady=2)
            provider_frame.columnconfigure(1, weight=1)  # Make description column expandable
            
            # Checkbox
            checkbox = tb.Checkbutton(provider_frame, text=provider.upper(), 
                                     variable=var, width=15)
            checkbox.grid(row=0, column=0, sticky='w', padx=(0, 10))
            
            # Description with IOC types
            ioc_types = provider_capabilities.get(provider, ())
            desc_with_types = f"{description} - Supports: {', '.join(ioc_types)}"
            desc_label = tb.Label(provider_frame, text=desc_with_types, 
                                 foreground='gray')
            desc_label.grid(row=0, column=1, sticky='w', padx=(0, 10))
            
            # Always On checkbox
            always_on_attr = f"{provider}_always_on"
            if not hasattr(self, always_on_attr):
                always_on_var = tk.BooleanVar(value=provider in DEFAULT_ALWAYS_ON)
                setattr(self, always_on_attr, always_on_var)
            else:
                always_on_var = getattr(self, always_on_attr)
            
            always_on_cb = tb.Checkbutton(provider_frame, text="Always On", 
                                         variable=always_on_var)
            always_on_cb.grid(row=0, column=2, sticky='e', padx=(10, 0))
    
    def _on_filter_change(self, event=None):
        """Handle filter dropdown change."""
        # Preserve current selections when filtering
        config = {provider: var.get() for provider, var in self.vars.items()}
        self._build_provider_widgets(config)
    
    def _select_all(self):
        """Select all providers."""
        for var in self.vars.values():
            var.set(True)
    
    def _select_none(self):
        """Deselect all providers."""
        for var in self.vars.values():
            var.set(False)
    
    def _select_defaults(self):
        """Set providers to default configuration."""
        defaults = ['abuseipdb', 'otx']
        for provider, var in self.vars.items():
            var.set(provider in defaults)
    
    def ok(self):
        """Accept the provider selection and update always-on list."""
        # Update the provider selection
        self.result = {provider: var.get() for provider, var in self.vars.items()}
        
        # Update always-on providers based on user selection
        global DEFAULT_ALWAYS_ON
        new_always_on = []
        for provider in AVAILABLE_PROVIDERS.keys():
            always_on_var = getattr(self, f"{provider}_always_on", None)
            if always_on_var and always_on_var.get():
                new_always_on.append(provider)
        
        DEFAULT_ALWAYS_ON = new_always_on
        self.dialog.destroy()
    
    def _cancel(self):
        """Cancel the provider selection."""
        self.result = None
        self.dialog.destroy()

class ProxyDlg:
    """Proxy configuration dialog."""
    
    def __init__(self, parent):
        self.parent = parent
        self.result = None
        
        self._build_dialog()
    
    def _build_dialog(self):
        """Build the proxy configuration dialog."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Proxy Configuration")
        self.dialog.geometry("400x200")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (400 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (200 // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        main_frame = tb.Frame(self.dialog, padding=20)
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = tb.Label(main_frame, text="HTTP Proxy Configuration", 
                               font=('Arial', 12, 'bold'))
        title_label.pack(anchor='w', pady=(0, 10))
        
        # Proxy input
        tb.Label(main_frame, text="Proxy URL (e.g., http://proxy:8080):").pack(anchor='w')
        
        self.var = tk.StringVar(value=os.environ.get("http_proxy", ""))
        self.entry = tb.Entry(main_frame, textvariable=self.var, width=50)
        self.entry.pack(fill='x', pady=(5, 15))
        
        # Instructions
        instructions = tb.Label(main_frame, 
                                text="Leave empty to disable proxy. Changes apply to current session only.",
                                foreground='gray')
        instructions.pack(anchor='w', pady=(0, 15))
        
        # Buttons
        button_frame = tb.Frame(main_frame)
        button_frame.pack(fill='x')
        
        tb.Button(button_frame, text="Cancel", command=self._cancel).pack(side='right')
        tb.Button(button_frame, text="OK", command=self.ok).pack(side='right', padx=(0, 10))
        
        # Bind Enter and Escape
        self.dialog.bind('<Return>', lambda e: self.ok())
        self.dialog.bind('<Escape>', lambda e: self._cancel())
        
        # Focus on entry
        self.entry.focus_set()
    
    def ok(self):
        """Accept the proxy configuration."""
        proxy = self.var.get().strip()
        if proxy:
            os.environ["http_proxy"] = proxy
            os.environ["https_proxy"] = proxy
            self.result = proxy
        else:
            # Clear proxy
            os.environ.pop("http_proxy", None)
            os.environ.pop("https_proxy", None)
            self.result = ""
        self.dialog.destroy()
    
    def _cancel(self):
        """Cancel the proxy configuration."""
        self.result = None
        self.dialog.destroy()

class DarkModeManager:
    """Manages dark/light theme detection and application."""
    
    def __init__(self):
        self.current_theme = self._detect_system_theme()
    
    def _detect_system_theme(self):
        """Detect system dark mode preference."""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                               r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            winreg.CloseKey(key)
            return 'dark' if value == 0 else 'light'
        except:
            return 'light'  # Fallback to light theme
    
    def toggle_theme(self):
        """Toggle between light and dark themes."""
        self.current_theme = "dark" if self.current_theme == "light" else "light"
        return self.current_theme

class TooltipManager:
    """Simple tooltip implementation for widgets."""
    
    @staticmethod
    def add_tooltip(widget, text):
        """Add tooltip to widget."""
        def on_enter(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            label = tk.Label(tooltip, text=text, background="lightyellow", 
                           relief="solid", borderwidth=1, font=("Arial", 8))
            label.pack()
            widget.tooltip = tooltip
        
        def on_leave(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
                del widget.tooltip
        
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

class IOCCheckerGUI:
    """Enhanced IOC Checker GUI with menu system and modern styling."""
    
    def __init__(self):
        self.dark_mode_mgr = DarkModeManager()
        self.current_theme = self.dark_mode_mgr.current_theme
        
        # Application state
        self.proc = None
        self.q = queue.Queue()
        self.stats = {'total': 0, 'threat': 0, 'clean': 0, 'error': 0}
        self.provider_config = {p: False for p in AVAILABLE_PROVIDERS.keys()}
        self.provider_config.update({'abuseipdb': True, 'otx': True})
        self.proxy_config = {}
        self.is_processing = False
        
        # UI state
        self.show_only = tk.BooleanVar(value=True)
        self.file_var = tk.StringVar()
        self.ioc_limit = tk.IntVar(value=0)
        self.total_iocs = 0
        self.processed_iocs = 0
        self.total_file_iocs = 0
        
        # Create main window
        self.root = tk.Tk()
        self.root.title("IOC Checker - Advanced")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Initialize styling
        self._setup_styles()
        
        # Create menu system
        self._create_menu()
        
        # Build main UI
        self._build_ui()
        
        # Setup drag and drop
        self._setup_drag_drop()
        
        # Apply initial theme
        self._apply_theme()        
        # Start queue polling
        self._poll_queue()
        
    def _setup_styles(self):
        """Setup enhanced ttkbootstrap styles."""
        # Initialize ttkbootstrap with darkly theme
        self.style = tb.Style(theme="darkly")
        
        # Configure custom styles for enhanced appearance
        self.style.configure('Primary.TButton', 
                           background='#0078D4', foreground='white',
                           borderwidth=1, focuscolor='none')
        self.style.map('Primary.TButton',
                      background=[('active', '#106EBE'), ('pressed', '#005A9E')])
        
        # Update Stop button style to danger-outline
        self.style.configure('Danger.TButton',
                           background='#D13438', foreground='white', 
                           borderwidth=1, focuscolor='none')
        self.style.map('Danger.TButton',
                      background=[('active', '#B71C1C'), ('pressed', '#8B0000')])
        
        # Progress bar with text
        self.style.layout('Text.Horizontal.TProgressbar',
                         [('Horizontal.Progressbar.trough',
                           {'children': [('Horizontal.Progressbar.pbar',
                                        {'side': 'left', 'sticky': 'ns'})],
                            'sticky': 'nswe'}),
                          ('Horizontal.Progressbar.label', {'sticky': ''})])
        self.style.configure('Text.Horizontal.TProgressbar', text='0%')
    
    def _create_menu(self):
        """Create enhanced menu system."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings ▾", menu=settings_menu)
        
        settings_menu.add_command(label="Providers...", command=self._configure_providers)
        settings_menu.add_command(label="Proxy...", command=self._configure_proxy)
        
        # View menu with Light/Dark theme toggle
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View ▸", menu=view_menu)
        view_menu.add_command(label="Light Theme", command=lambda: self._toggle_theme('light'))
        view_menu.add_command(label="Dark Theme", command=lambda: self._toggle_theme('dark'))
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)
    
    def _build_ui(self):
        """Build enhanced UI with visual hierarchy."""
        main = tb.Frame(self.root, padding=20)
        main.grid(sticky="nsew")
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        
        # Enhanced title section
        title_frame = tb.Frame(main)
        title_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        title_frame.columnconfigure(0, weight=1)
        
        title_label = tb.Label(title_frame, text="IOC Threat Intelligence Checker", 
                               font=('Arial', 18, 'bold'))
        title_label.grid(row=0, column=0, sticky="w")
        
        self.provider_status = tb.Label(title_frame, text="", foreground='gray')
        self.provider_status.grid(row=0, column=1, sticky="e")
        self._update_provider_status()
        
        # Single IOC input with enhanced styling
        inp = tb.LabelFrame(main, text="Single IOC Check", padding=15)
        inp.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        main.columnconfigure(0, weight=1)
        
        tb.Label(inp, text="Type:").grid(row=0, column=0, sticky="w")
        self.type_cb = tb.Combobox(inp, values=IOC_TYPES, state="readonly", width=12)
        self.type_cb.current(0)
        self.type_cb.grid(row=0, column=1, padx=(5, 15), sticky="w")
        
        tb.Label(inp, text="Value:").grid(row=0, column=2, sticky="w")
        self.val = tk.Entry(inp, width=50, font=('Consolas', 10))
        self.val.grid(row=0, column=3, sticky="ew", padx=(5, 15))
        inp.columnconfigure(3, weight=1)
        
        # Enhanced action buttons
        btn_frame = tb.Frame(inp)
        btn_frame.grid(row=0, column=4, sticky="e")
        
        self.btn_check = tb.Button(btn_frame, text="Check", style='Primary.TButton',
                                   command=self._start_single)
        self.btn_check.pack(side=tk.LEFT, padx=(0, 5))        
        self.btn_stop = tb.Button(btn_frame, text="Stop", bootstyle="danger-outline",
                                  command=self._stop_processing, state='disabled')
        self.btn_stop.pack(side=tk.LEFT, padx=(0, 5))
        
        tb.Button(btn_frame, text="Clear", command=self._clear).pack(side=tk.LEFT)
        
        # Batch processing with enhanced file input
        batch = tb.LabelFrame(main, text="Batch Processing", padding=15)
        batch.grid(row=2, column=0, sticky="ew", pady=(0, 15))
        
        tb.Label(batch, text="File:").grid(row=0, column=0, sticky="w")
        
        # Enhanced file entry with placeholder
        self.file_var = tk.StringVar()
        file_frame = tb.Frame(batch)
        file_frame.grid(row=0, column=1, sticky="ew", padx=(5, 15))
        file_frame.columnconfigure(0, weight=1)
        
        self.file_entry = tb.Entry(file_frame, textvariable=self.file_var, width=50)
        self.file_entry.grid(row=0, column=0, sticky="ew")
        self._set_placeholder(self.file_entry, "Select CSV / TXT / XLSX...")
        
        tb.Button(file_frame, text="Browse", command=self._browse).grid(row=0, column=1, padx=(5, 0))
        batch.columnconfigure(1, weight=1)
        
        # Enhanced batch buttons  
        batch_btn_frame = tb.Frame(batch)
        batch_btn_frame.grid(row=0, column=2, sticky="e", padx=(15, 0))
        
        self.btn_batch = tb.Button(batch_btn_frame, text="Start Processing", 
                                   style='Primary.TButton', command=self._start_batch)
        self.btn_batch.pack(side=tk.LEFT, padx=(0, 10))
        
        # Only Providers button (Proxy moved to menu)
        tb.Button(batch_btn_frame, text="Providers", 
                  command=self._configure_providers).pack(side=tk.LEFT)
        
        # IOC limit slider (enhanced)
        self.limit_frame = tb.LabelFrame(main, text="Processing Limit", padding=10)
        self.limit_frame.grid(row=3, column=0, sticky="ew", pady=(0, 15))
        self.limit_frame.columnconfigure(1, weight=1)
        
        tb.Label(self.limit_frame, text="IOCs to process:").grid(row=0, column=0, sticky="w")
        self.limit_scale = tb.Scale(self.limit_frame, from_=0, to=100, orient='horizontal',
                                    variable=self.ioc_limit, command=self._update_limit_label)
        self.limit_scale.grid(row=0, column=1, sticky="ew", padx=(10, 10))
        
        self.limit_label = tb.Label(self.limit_frame, text="All IOCs")
        self.limit_label.grid(row=0, column=2, sticky="e")
        
        # Hide limit frame initially
        self.limit_frame.grid_remove()
        
        # Enhanced progress section
        progress_frame = tb.LabelFrame(main, text="Progress", padding=10)
        progress_frame.grid(row=4, column=0, sticky="ew", pady=(0, 15))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress = tb.Progressbar(progress_frame, style='Text.Horizontal.TProgressbar')
        self.progress.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        
        # Stats with enhanced layout
        stats_frame = tb.Frame(progress_frame)
        stats_frame.grid(row=1, column=0, sticky="ew")
        stats_frame.columnconfigure(4, weight=1)        
        self.lab_stats = {}
        for i, stat in enumerate(['threat', 'clean', 'error', 'total']):
            self.lab_stats[stat] = tb.Label(stats_frame, text=f"{stat}: 0", 
                                           font=('TkDefaultFont', 9, 'bold'))
            self.lab_stats[stat].grid(row=0, column=i, padx=(0, 15), sticky="w")
        
        # Enhanced output area with tooltip
        output_frame = tb.LabelFrame(main, text="Results", padding=10)
        output_frame.grid(row=5, column=0, sticky="nsew", pady=(0, 10))
        main.rowconfigure(5, weight=1)
        
        # Replace ScrolledText with paginated Tableview
        tv_columns = ['Type', 'IOC', 'Status', 'Details']
        tv_data = []
        self.out = tb.Tableview(output_frame, 
                               coldata=tv_columns,
                               rowdata=tv_data,
                               paginated=True, 
                               bootstyle="info",
                               searchable=True,
                               height=15)
        self.out.pack(fill='both', expand=True)
        TooltipManager.add_tooltip(self.out, "Processing results will appear here")
        
        # Enhanced options
        options_frame = tb.Frame(main)
        options_frame.grid(row=6, column=0, sticky="ew")
        
        self.show_only = tk.BooleanVar(value=True)
        tb.Checkbutton(options_frame, text="Show only threats & errors", 
                       variable=self.show_only).pack(side='left')
          # Bind Enter key for single IOC check
        self.root.bind("<Return>", self._start_single)
        
        tb.Label(inp, text="Value").grid(row=0, column=2)
        self.val = tk.Entry(inp, width=40)
        self.val.grid(row=0, column=3, sticky="ew", padx=5)
        inp.columnconfigure(3, weight=1)
        
        # Single IOC buttons
        btnf = tb.Frame(inp)
        btnf.grid(row=0, column=4, padx=5)
        
        self.btn_check = tb.Button(btnf, text="Check", 
                                    command=self._start_single)
        self.btn_check.pack(side=tk.LEFT)
        self.btn_stop = tb.Button(btnf, text="Stop", bootstyle="danger-outline", 
                                  command=self._stop_processing, state='disabled')
        self.btn_stop.pack(side=tk.LEFT, padx=(5, 0))
        tb.Button(btnf, text="Clear", command=self._clear).pack(side=tk.LEFT, padx=(5, 0))
        
        # Batch processing
        batch = tb.Frame(main)
        batch.grid(row=2, column=0, sticky="ew", pady=5)
        self.file_var = tk.StringVar()
        
        tb.Label(batch, text="File:").grid(row=0, column=0)
        file_entry = tb.Entry(batch, textvariable=self.file_var, width=40)
        file_entry.grid(row=0, column=1, sticky="ew", padx=5)
        batch.columnconfigure(1, weight=1)
        
        tb.Button(batch, text="Browse", command=self._browse).grid(row=0, column=2, padx=(5, 0))
        
        self.btn_batch = tb.Button(batch, text="Start Processing", 
                                    command=self._start_batch)
        self.btn_batch.grid(row=0, column=3, padx=(5, 0))
        
        # Configuration buttons
        config_frame = tb.Frame(batch)
        config_frame.grid(row=0, column=4, padx=(10, 0))
        
        tb.Button(config_frame, text="Providers", style='Provider.TButton',
                  command=self._configure_providers).pack(side='left')
        tb.Button(config_frame, text="Proxy", style='Provider.TButton',
                  command=self._configure_proxy).pack(side='left', padx=(5, 0))
        self.theme_button = tb.Button(config_frame, text="🌙", style='Provider.TButton',
                  command=self._toggle_theme)
        self.theme_button.pack(side='left', padx=(5, 0))
          # Format info label
        self.format_label = tb.Label(batch, text="Supported: CSV, TSV, XLSX, TXT", foreground="gray")
        self.format_label.grid(row=1, column=0, columnspan=5, sticky="w", pady=(5,0))
        
        # IOC limit slider (initially hidden)
        self.limit_frame = tb.Frame(batch)
        self.limit_frame.grid(row=2, column=0, columnspan=5, sticky="ew", pady=(10,0))
        self.limit_frame.columnconfigure(1, weight=1)
        
        tb.Label(self.limit_frame, text="IOCs to process:").grid(row=0, column=0, sticky="w")
        
        self.limit_slider = tb.Scale(self.limit_frame, from_=1, to=100, orient="horizontal",
                                     variable=self.ioc_limit, command=self._on_limit_change)
        self.limit_slider.grid(row=0, column=1, sticky="ew", padx=(10,0))
        
        self.limit_label = tb.Label(self.limit_frame, text="All IOCs")
        self.limit_label.grid(row=0, column=2, sticky="w", padx=(10,0))
        
        # Initially hide the limit frame
        self.limit_frame.grid_remove()
        
        # Progress bar (initially hidden)
        self.progress_frame = tb.Frame(main)
        self.progress_frame.grid(row=3, column=0, sticky="ew", pady=(10,5))
        self.progress_frame.columnconfigure(0, weight=1)
        
        self.progress_label = tb.Label(self.progress_frame, text="")
        self.progress_label.grid(row=0, column=0, sticky="w")
        
        self.progress = tb.Progressbar(self.progress_frame, mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew", pady=(5,0))
        
        # Initially hide progress
        self.progress_frame.grid_remove()
          # Results with Tableview
        res = tb.LabelFrame(main, text="Results")
        res.grid(row=4, column=0, sticky="nsew")
        main.rowconfigure(4, weight=1)
        
        # Replace ScrolledText with paginated Tableview
        tv_columns2 = ['Type', 'IOC', 'Status', 'Details']
        tv_data2 = []
        self.out = tb.Tableview(res, 
                               coldata=tv_columns2,
                               rowdata=tv_data2,
                               paginated=True, 
                               bootstyle="info",
                               searchable=True,
                               height=12)
        self.out.pack(expand=True, fill='both')
        
        # Status bar
        st = tb.Frame(main)
        st.grid(row=5, column=0, sticky="ew")
        self.lab_stats = {k: tb.Label(st, text=f"{k}:0") for k in self.stats}
        for i, (k, label) in enumerate(self.lab_stats.items()):
            label.grid(row=0, column=i, padx=8, sticky="w")
        
        checkbox = tb.Checkbutton(st, text="Show only threats", variable=self.show_only)
        checkbox.grid(row=0, column=5, padx=20)
        
        self.root.bind("<Return>", self._start_single)
          # Setup drag and drop
        self._setup_drag_drop()
        
        # Apply initial theme
        self._apply_theme()
    
    def _apply_theme(self):
        """Apply the current enhanced theme to all widgets."""
        theme = ENHANCED_THEMES[self.current_theme]
        
        # Configure root window
        self.root.configure(bg=theme['bg'])
        
        # Update custom styles based on theme
        if self.current_theme == 'dark':
            self.style.configure('Primary.TButton', 
                               background=theme['primary_button'], foreground='white')
            self.style.configure('Danger.TButton',
                               background=theme['danger_button'], foreground='white')
        else:
            self.style.configure('Primary.TButton',
                               background=theme['primary_button'], foreground='white')
            self.style.configure('Danger.TButton', 
                               background=theme['danger_button'], foreground='white')
        
        # Configure output area colors
        self.out.configure(bg=theme['bg'], fg=theme['fg'],
                          selectbackground=theme['select_bg'],
                          selectforeground=theme['select_fg'],
                          insertbackground=theme['fg'])
        
        # Update text tags with theme colors
        for tag, color in theme['colors'].items():
            self.out.tag_configure(tag, foreground=color)
          # Configure ttk styles for dark mode
        style = tb.Style()
        if self.current_theme == 'dark':
            style.theme_use('clam')  # Use clam theme as base for dark mode
            
            # Configure dark theme styles
            style.configure('TFrame', background=theme['bg'], borderwidth=0)
            style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
            style.configure('TButton', background=theme['button_bg'], foreground=theme['fg'],
                          borderwidth=1, focuscolor='none')
            style.map('TButton', 
                     background=[('active', '#505050'), ('pressed', '#606060')])
            style.configure('TEntry', background=theme['entry_bg'], foreground=theme['entry_fg'], 
                          fieldbackground=theme['entry_bg'], insertcolor=theme['fg'],
                          borderwidth=1)
            style.configure('TCombobox', background=theme['entry_bg'], foreground=theme['entry_fg'],
                          fieldbackground=theme['entry_bg'], selectbackground=theme['select_bg'],
                          borderwidth=1, arrowcolor=theme['fg'])
            style.configure('TScale', background=theme['bg'], troughcolor=theme['entry_bg'],
                          borderwidth=0, sliderthickness=20)
            style.configure('TProgressbar', background=theme['select_bg'], 
                          troughcolor=theme['entry_bg'], borderwidth=1)
            style.configure('TCheckbutton', background=theme['bg'], foreground=theme['fg'],
                          focuscolor='none')
            style.map('TCheckbutton',
                     background=[('active', theme['bg'])])
            
            # Configure special button styles  
            style.configure('Provider.TButton', background=theme['button_bg'], foreground=theme['fg'],
                          borderwidth=1, focuscolor='none')
            style.map('Provider.TButton',
                     background=[('active', '#505050'), ('pressed', '#606060')])
            
        else:
            style.theme_use('clam')  # Use clam theme for light mode too for better control
            # Light mode button styling
            style.configure('Provider.TButton', background='#F0F0F0', foreground='black',
                          borderwidth=1, focuscolor='none', relief='raised')
            style.map('Provider.TButton',
                     background=[('active', '#E0E0E0'), ('pressed', '#D0D0D0')],
                     foreground=[('active', 'black'), ('pressed', 'black')])
            
            # Configure other light theme elements
            style.configure('TFrame', background=theme['bg'])
            style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
            style.configure('TButton', background=theme['button_bg'], foreground=theme['fg'])
            style.configure('TEntry', background=theme['entry_bg'], foreground=theme['entry_fg'], 
                          fieldbackground=theme['entry_bg'], insertcolor=theme['fg'])
            style.configure('TCombobox', background=theme['entry_bg'], foreground=theme['entry_fg'],
                          fieldbackground=theme['entry_bg'])
            style.configure('TCheckbutton', background=theme['bg'], foreground=theme['fg'])
        
        # Configure scrolled text widget
        self.out.configure(bg=theme['bg'], fg=theme['fg'], 
                          selectbackground=theme['select_bg'],
                          selectforeground=theme['select_fg'],
                          insertbackground=theme['fg'])
        
        # Update text tags with theme colors
        for t, c in theme['colors'].items():
            self.out.tag_configure(t, foreground=c)
              # Configure stats labels
        for label in self.lab_stats.values():
            # tb.Label doesn't support bg/fg directly - styling is handled by tb.Style above
            pass
            
        # Configure other labels (check if they're tk.Label or tb.Label)
        if hasattr(self, 'format_info'):
            if isinstance(self.format_info, tb.Label):
                pass  # Styled by tb.Style
            else:
                self.format_info.configure(bg=theme['bg'], fg=theme['fg'])
        if hasattr(self, 'provider_status'):
            if isinstance(self.provider_status, tb.Label):
                pass  # Styled by tb.Style  
            else:
                self.provider_status.configure(bg=theme['bg'], fg=theme['fg'])
        if hasattr(self, 'limit_label'):
            if isinstance(self.limit_label, tb.Label):
                pass  # Styled by tb.Style
            else:
                self.limit_label.configure(bg=theme['bg'], fg=theme['fg'])
        if hasattr(self, 'progress_label'):
            if isinstance(self.progress_label, tb.Label):
                pass  # Styled by tb.Style
            else:
                self.progress_label.configure(bg=theme['bg'], fg=theme['fg'])
              # Configure all frames to match theme
        for widget in self.root.winfo_children():
            self._configure_widget_theme(widget, theme)
    
    def _configure_widget_theme(self, widget, theme):
        """Recursively configure widget themes."""
        widget_class = widget.winfo_class()
        
        if widget_class == 'Frame':
            widget.configure(bg=theme['bg'])
        elif widget_class == 'Label':
            widget.configure(bg=theme['bg'], fg=theme['fg'])
        elif widget_class == 'Button':
            # Skip styled buttons
            if not hasattr(widget, 'cget') or widget.cget('style') == '':
                widget.configure(bg=theme['button_bg'], fg=theme['fg'])
        
        # Recursively apply to children
        for child in widget.winfo_children():
            self._configure_widget_theme(child, theme)
    
    def _toggle_theme(self, theme=None):
        """Toggle between light and dark themes using ttkbootstrap."""
        if theme:
            self.current_theme = theme
        else:
            self.current_theme = 'dark' if self.current_theme == 'light' else 'light'
        
        # Use ttkbootstrap's theme switching
        if self.current_theme == 'dark':
            self.style.theme_use('darkly')
        else:
            self.style.theme_use('litera')  # Light theme
        
        # Update theme button text if it exists
        if hasattr(self, 'theme_button'):
            self.theme_button.configure(text="☀️" if self.current_theme == 'dark' else "🌙")
        
        self._apply_theme()
        
        # Force refresh of all frames
        for widget in self.root.winfo_children():
            self._refresh_widget_theme(widget)
    
    def _refresh_widget_theme(self, widget):
        """Recursively refresh theme for widget and its children."""
        theme = THEMES[self.current_theme]
        
        try:
            # Apply theme to frame-like widgets
            if isinstance(widget, (tb.Frame, tk.Frame)):
                if isinstance(widget, tk.Frame):
                    widget.configure(bg=theme['bg'])
                
            # Recursively refresh children
            for child in widget.winfo_children():
                self._refresh_widget_theme(child)
                
        except tk.TclError:
            pass  # Ignore widgets that can't be configured

    def _on_limit_change(self, value):
        """Handle slider value change."""
        limit_value = int(float(value))
        if limit_value >= self.total_file_iocs or limit_value == 0:
            self.limit_label.config(text="All IOCs")
        else:
            self.limit_label.config(text=f"{limit_value} IOCs")
    
    def _update_provider_status(self):
        """Update the provider status display."""
        enabled_count = sum(1 for enabled in self.provider_config.values() if enabled)
        total_count = len(self.provider_config)
        self.provider_status.config(text=f"Providers: {enabled_count}/{total_count} enabled")

    def _configure_providers(self):
        """Open provider configuration dialog."""
        dialog = ProviderDlg(self.root, self.provider_config.copy(), self.current_theme)
        self.root.wait_window(dialog.dialog)
        
        if dialog.result is not None:
            self.provider_config.update(dialog.result)
            # Update always-on providers to ensure they remain enabled
            for provider in DEFAULT_ALWAYS_ON:
                if provider in self.provider_config:
                    self.provider_config[provider] = True
            self._update_provider_status()
            self._log("info", f"Provider configuration updated: {sum(self.provider_config.values())} providers enabled")

    def _configure_proxy(self):
        """Open proxy configuration dialog."""
        dialog = ProxyDlg(self.root)
        self.root.wait_window(dialog.dialog)
        
        if dialog.result is not None:
            if dialog.result:
                self._log("info", f"Proxy configured: {dialog.result}")
            else:
                self._log("info", "Proxy disabled")

    def _show_about(self):
        """Show About dialog."""
        about_text = """IOC Checker v1.0

A comprehensive tool for checking Indicators of Compromise (IOCs) 
against multiple threat intelligence providers.

Features:
• Single IOC lookups
• Batch CSV/TXT processing  
• Multiple provider support
• Modern GUI interface
• Export to CSV

Supported IOC Types:
IP addresses, Domains, URLs, File hashes, 
Email addresses, Registry keys, Crypto wallets, 
ASN numbers, ATT&CK techniques

© 2025 IOC Checker Project"""
        
        try:
            messagebox.showinfo("About IOC Checker", about_text)
        except Exception as e:
            self._log("error", f"Failed to show about dialog: {e}")

    def run(self):
        """Start the GUI application."""
        self.root.mainloop()
    
    def _browse(self):
        """Enhanced file browser with multiple format support."""
        filename = filedialog.askopenfilename(
            title="Select IOC file",
            filetypes=[
                ("All supported", "*.csv;*.txt;*.xlsx"),
                ("CSV files", "*.csv"),
                ("Text files", "*.txt"),
                ("Excel files", "*.xlsx"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.file_var.set(filename)
            self._check_file_and_setup_limit()
    
    def _check_file_and_setup_limit(self):
        """Check file and setup IOC limit controls."""
        filename = self.file_var.get()
        if filename and os.path.exists(filename):
            try:
                # Preview file to count IOCs
                iocs, detected_type = load_iocs(filename, max_rows=None)
                self.total_file_iocs = len(iocs)
                
                if self.total_file_iocs > 50:
                    self.limit_frame.grid()
                    self.limit_scale.configure(to=self.total_file_iocs)
                    self.ioc_limit.set(0)  # Default to all
                    self._update_limit_label()
                else:
                    self.limit_frame.grid_remove()
                    
                # Show file info
                info_text = f"Preview: {self.total_file_iocs} IOCs found (type: {detected_type})"
                if hasattr(self, 'format_label'):
                    self.format_label.configure(text=info_text)
                    
            except Exception as e:
                messagebox.showerror("File Error", f"Could not read file: {e}")
    
    def _update_limit_label(self, *args):
        """Update the limit label text."""
        limit = int(self.ioc_limit.get())
        if limit == 0:
            self.limit_label.configure(text="All IOCs")
        else:
            self.limit_label.configure(text=f"{limit} IOCs")
    
    def _add_tooltip(self, widget, text):
        """Add tooltip to widget using simple hover mechanism."""
        def on_enter(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")
            label = tk.Label(tooltip, text=text, background="lightyellow", 
                           relief="solid", borderwidth=1, font=("Arial", 8))
            label.pack()
            widget.tooltip = tooltip
            
        def on_leave(event):
            if hasattr(widget, 'tooltip'):
                widget.tooltip.destroy()
                del widget.tooltip
                
        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)
    
    def _add_placeholder(self, entry_widget, placeholder_text):
        """Add placeholder text to entry widget."""
        def on_focus_in(event):
            if entry_widget.get() == placeholder_text:
                entry_widget.delete(0, tk.END)
                entry_widget.configure(foreground='black')
                
        def on_focus_out(event):
            if not entry_widget.get():
                entry_widget.insert(0, placeholder_text)
                entry_widget.configure(foreground='grey')
                
        entry_widget.insert(0, placeholder_text)
        entry_widget.configure(foreground='grey')
        entry_widget.bind('<FocusIn>', on_focus_in)
        entry_widget.bind('<FocusOut>', on_focus_out)
    
    def _detect_system_theme(self):
        """Detect system dark mode preference."""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                               r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme")
            winreg.CloseKey(key)
            return 'dark' if value == 0 else 'light'
        except:
            return 'light'  # Fallback to light theme
    
    def _toggle_theme_menu(self):
        """Toggle theme via menu and update button text."""
        self._toggle_theme()
        # Update menu text
        current_text = "Theme: Dark" if self.current_theme == 'light' else "Theme: Light"
        self.theme_menu.entryconfig(2, label=current_text)
    
    def _update_progress_text(self, percentage):
        """Update progress bar with percentage text."""
        if hasattr(self, 'progress'):
            self.progress.configure(value=percentage)
            # Update the progress bar text if supported
            try:
                style = tb.Style()
                style.configure("text.Horizontal.TProgressbar", text=f"{percentage:.0f}%")
            except:
                pass  # Fallback if style doesn't support text
    
    def _disable_action_buttons(self):
        """Disable primary action buttons during processing."""
        self.btn_check.configure(state='disabled')
        self.btn_batch.configure(state='disabled')
        self.btn_stop.configure(state='normal')
    
    def _enable_action_buttons(self):
        """Re-enable primary action buttons after processing."""
        self.btn_check.configure(state='normal')
        self.btn_batch.configure(state='normal')
        self.btn_stop.configure(state='disabled')
    
    def _toggle_processing_state(self, is_processing):
        """Toggle processing state and update UI accordingly."""
        self.is_processing = is_processing
        
        if is_processing:
            self._disable_action_buttons()
            self.progress.grid()  # Show progress bar
            self._log("🚀 Starting processing...", "info")
        else:
            self._enable_action_buttons()
            self.progress.grid_remove()  # Hide progress bar
            self._log("✅ Processing complete.", "clean")

    def _start_single(self, *args):
        """Start single IOC lookup."""
        if self.is_processing:
            return
            
        ioc_value = self.val.get().strip()
        ioc_type = self.type_cb.get()
        
        if not ioc_value:
            messagebox.showerror("Input", "Enter an IOC value")
            return
            
        self._log("info", f"=== {ioc_type}: {ioc_value} ===")
        
        # Build command for single IOC lookup
        cmd = [PYTHON, SCRIPT, ioc_type, ioc_value]
        
        # Add provider flags based on configuration
        providers = [p for p, enabled in self.provider_config.items() if enabled]
        if providers:
            cmd.extend(["--providers", ",".join(providers)])
            
        self._toggle_processing_state(True)
        self._start_subprocess(cmd)

    def _stop_processing(self):
        """Stop current processing."""
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except:
                self.proc.kill()
            finally:
                self.proc = None
                self._toggle_processing_state(False)
                self._log("warning", "Processing stopped by user")

    def _clear(self):
        """Clear the output display."""
        if hasattr(self, 'out'):
            self.out.delete('1.0', 'end')
        
        # Reset statistics
        self.stats = {'total': 0, 'threat': 0, 'clean': 0, 'error': 0}
        if hasattr(self, 'lab_stats'):
            for k, v in self.stats.items():
                if k in self.lab_stats:
                    self.lab_stats[k].configure(text=f"{k}: {v}")

    def _start_batch(self):
        """Start batch file processing."""
        if self.is_processing:
            return
            
        file_path = self.file_var.get().strip()
        
        if not file_path:
            messagebox.showerror("File", "Select a CSV/TXT/XLSX file")
            return
            
        if not os.path.exists(file_path):
            messagebox.showerror("File", "File not found")
            return
            
        self._log("info", f"=== Batch processing: {file_path} ===")
        
        # Build command for batch processing
        cmd = [PYTHON, SCRIPT, "--file", file_path]
        
        # Add output file
        output_file = file_path.replace('.csv', '_results.csv').replace('.txt', '_results.csv').replace('.xlsx', '_results.csv')
        cmd.extend(["-o", output_file])
        
        # Add provider flags based on configuration
        providers = [p for p, enabled in self.provider_config.items() if enabled]
        if providers:
            cmd.extend(["--providers", ",".join(providers)])
            
        # Add IOC limit if set
        if self.ioc_limit.get() > 0:
            cmd.extend(["--limit", str(self.ioc_limit.get())])
            
        self._toggle_processing_state(True)
        self._start_subprocess(cmd)

    def _start_subprocess(self, cmd):
        """Start subprocess with the given command."""
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                universal_newlines=True
            )
            self._log("info", f"Command: {' '.join(cmd)}")
        except Exception as e:
            self._log("error", f"Failed to start subprocess: {e}")
            self._toggle_processing_state(False)

    def _poll_queue(self):
        """Poll subprocess output and update GUI."""
        try:
            if self.proc:
                # Read available output
                while True:
                    line = self.proc.stdout.readline()
                    if not line:
                        break
                    line = line.strip()
                    if line:
                        self._parse_and_log_output(line)
                
                # Check if process is done
                if self.proc.poll() is not None:
                    # Process finished
                    self.proc = None
                    self._toggle_processing_state(False)
                    
        except Exception as e:
            self._log("error", f"Polling error: {e}")
            if self.proc:
                self.proc = None
                self._toggle_processing_state(False)
        
        # Schedule next poll
        self.root.after(100, self._poll_queue)

    def _parse_and_log_output(self, line):
        """Parse subprocess output and log with appropriate formatting."""
        line = line.strip()
        if not line:
            return
            
        # Classify the output for proper styling
        if "error" in line.lower() or "failed" in line.lower():
            log_type = "error"
            self.stats['error'] += 1
        elif "malicious" in line.lower() or "threat" in line.lower():
            log_type = "threat"
            self.stats['threat'] += 1
        elif "clean" in line.lower() or "safe" in line.lower():
            log_type = "clean"
            self.stats['clean'] += 1
        else:
            log_type = "info"
            
        self.stats['total'] += 1
        self._log(line, log_type)
        
        # Update stats display
        if hasattr(self, 'lab_stats'):
            for k, v in self.stats.items():
                if k in self.lab_stats:
                    self.lab_stats[k].configure(text=f"{k}: {v}")

    def _log(self, message, msg_type="info"):
        """Log message to output with appropriate styling."""
        if hasattr(self, 'out'):
            if hasattr(self, 'show_only') and self.show_only.get():
                # Only show threats and errors
                if msg_type not in ['threat', 'error']:
                    return
                    
            # Add timestamp and format message
            timestamp = ""  # We can add timestamps if needed
            formatted_msg = f"{timestamp}{message}\n"
            
            # Insert with appropriate tag for styling
            self.out.insert('end', formatted_msg, msg_type)
            self.out.see('end')

    # ...existing code...



def main():
    """Main entry point for the IOC Checker GUI application."""
    try:
        # Create and run the GUI application
        app = IOCCheckerGUI()
        app.run()
    except Exception as e:
        # If GUI fails to start, show error message
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()  # Hide the main window
            messagebox.showerror("IOC Checker Error", f"Failed to start GUI application:\n{str(e)}")
        except:
            # If even basic tkinter fails, print to console
            print(f"Error starting IOC Checker GUI: {e}")
            print("Please check that all required dependencies are installed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
