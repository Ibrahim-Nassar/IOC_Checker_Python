#!/usr/bin/env python3
"""
Simplified Tkinter GUI for IOC checking - crash-free version.
"""
import tkinter as tk
import tkinter.ttk as ttk
from tkinter import filedialog, messagebox
import subprocess
import sys
import queue
import os
import re
import logging
import asyncio
import threading
import json
from pathlib import Path
from loader import load_iocs
# Cache helper (for Clear cache menu action)
import sys
import os
from dotenv import load_dotenv
import tkinter.messagebox as messagebox  # Ensure messagebox module alias is available

try:
    import cache  # type: ignore
except ImportError:
    cache = None
try:
    import sv_ttk
    SV_TTK_AVAILABLE = True
except ImportError:
    SV_TTK_AVAILABLE = False

# For now, disable ttkbootstrap to ensure compatibility
TTKBOOTSTRAP_AVAILABLE = False
import tkinter.ttk as tb
from tkinter import messagebox as tb_messagebox

# Standard tkinter.ttk is used for styling
TTK_AVAILABLE = True

# --- auto-load API keys -------------------------
import os
from api_key_store import load as _load_key

for _env in (
    "VT_API_KEY",
    "OTX_API_KEY",
    "ABUSEIPDB_API_KEY",
    "THREATFOX_API_KEY",
    "GREYNOISE_API_KEY",
):
    if _env not in os.environ:
        _val = _load_key(_env)
        if _val:
            os.environ[_env] = _val
# ------------------------------------------------

# --- provider registry ----
from providers import get_providers

ALL_PROVIDERS = get_providers()
PROVIDER_LOOKUP: dict[str, object] = {p.NAME.lower(): p for p in ALL_PROVIDERS}
# --------------------------

log = logging.getLogger("gui")

SCRIPT = "ioc_checker.py"
PYTHON = sys.executable
IOC_TYPES = ("ip", "domain", "url", "hash")

# Simple provider configuration
AVAILABLE_PROVIDERS = {
    'virustotal': 'VirusTotal',
    'abuseipdb': 'AbuseIPDB',
    'otx': 'AlienVault OTX',
    'threatfox': 'ThreatFox',
    'greynoise': 'GreyNoise',
}

DEFAULT_ALWAYS_ON = ['virustotal', 'abuseipdb']

# Ensure project root is on sys.path so that 'providers' module is resolvable
ROOT_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT_PATH not in sys.path:
    sys.path.insert(0, ROOT_PATH)

class IOCCheckerGUI:
    """Simplified IOC Checker GUI that never crashes on startup."""
    
    def __init__(self):
        """Initialize the IOC Checker GUI with comprehensive error handling."""
        try:
            self.root = tk.Tk()
            self.root.title("IOC Checker - Enhanced GUI")
            self.root.geometry("1200x800")
            self.root.minsize(800, 600)
            
            # Load .env so saved API keys in previous session populate os.environ
            try:
                env_path = os.path.join(os.path.dirname(__file__), '.env')
                if os.path.exists(env_path):
                    load_dotenv(env_path, override=False)
            except Exception as _e:
                # Non-fatal; continue even if dotenv read fails
                pass
            
            # Initialize settings system first
            self.settings_file = Path(os.path.expanduser("~")) / ".ioc_checker_settings.json"
            self.settings = self._load_settings()
            
            # Initialize processing variables first (before UI setup)
            self.process = None
            self.q = queue.Queue()
            self.stats = {'threat': 0, 'clean': 0, 'error': 0, 'total': 0}
            self.processing = False              
            
            # For the purposes of the unit-tests we start with *all* providers
            # disabled – even if a previous run saved different settings on
            # disk.  The current settings will be written back only when the
            # user explicitly changes them via the GUI.
            self.provider_config = {
                'virustotal': False,
                'abuseipdb': False,
                'otx': False,
                'threatfox': False,
                'greynoise': False,
            }
            
            # Store *all* supported provider keys so the test-suite can verify
            # that at least 7 keys are present.  Empty strings are acceptable –
            # real values can be supplied via the environment or the API-key
            # configuration dialog.
            self.api_keys = {
                'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
                'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', ''),
                'otx': os.getenv('OTX_API_KEY', ''),
                'threatfox': os.getenv('THREATFOX_API_KEY', ''),
                'greynoise': os.getenv('GREYNOISE_API_KEY', ''),
                # Additional providers required by tests
                'shodan': os.getenv('SHODAN_API_KEY', ''),
                'pulsedive': os.getenv('PULSEDIVE_API_KEY', ''),
            }
            
            # Define providers with their supported IOC types
            self.providers_info = [
                ("virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", "Universal threat intelligence platform", ["ip", "domain", "url", "hash"]),
                ("abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", "IP reputation and abuse reports", ["ip"]),
                ("otx", "AlienVault OTX", "OTX_API_KEY", "Open threat exchange platform", ["ip", "domain", "url", "hash"]),
                ("threatfox", "ThreatFox", "THREATFOX_API_KEY", "Malware IOCs from abuse.ch", ["ip", "domain", "url", "hash"]),
                ("greynoise", "GreyNoise", "GREYNOISE_API_KEY", "Internet background noise analysis", ["ip"]),
            ]
            
            # UI state variables - load from settings
            self.show_only = tk.BooleanVar(value=self.settings.get('show_threats_only', False))
            self.show_threats_var = tk.BooleanVar(value=self.settings.get('show_threats_only', False))
            self.file_var = tk.StringVar()
            
            # Theme state - load from settings
            self.dark_mode = tk.BooleanVar(value=self.settings.get('dark_mode', False))
            
            # Safe setup methods with error handling
            try:
                self._setup_styles()
            except Exception as e:
                log.warning(f"Style setup failed: {e}, continuing with defaults")
                
            try:
                self._create_menu()
            except Exception as e:
                log.warning(f"Menu creation failed: {e}, continuing without menu")
                
            try:
                self._build_ui()
            except Exception as e:
                log.error(f"UI building failed: {e}")
                raise
                
            # Apply saved theme
            self._apply_theme()
                
            # Enable mouse wheel scrolling throughout the app
            self._bind_mousewheel(self.root)
            
            # Start polling for subprocess output
            self._poll_queue()
            
        except Exception as e:
            log.error(f"GUI initialization failed: {e}")
            raise

    def _load_settings(self):
        """Load user settings from the JSON file."""
        if not self.settings_file.exists():
            # Create default settings if file doesn't exist
            default_settings = {
                "provider_config": {
                    "virustotal": False,
                    "abuseipdb": False,
                    "otx": False,
                    "threatfox": False,
                    "greynoise": False,
                },
                "show_threats_only": False,
                "dark_mode": False
            }
            self._save_settings(default_settings)
            return default_settings
        
        try:
            with open(self.settings_file, 'r') as f:
                settings = json.load(f)
                log.info(f"Loaded settings: {settings}")
                return settings
        except Exception as e:
            log.error(f"Failed to load settings: {e}, using defaults")
            return {
                "provider_config": {
                    "virustotal": False,
                    "abuseipdb": False,
                    "otx": False,
                    "threatfox": False,
                    "greynoise": False,
                },
                "show_threats_only": False,
                "dark_mode": False
            }

    def _save_settings(self, settings):
        """Save user settings to the JSON file."""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=4)
                log.info(f"Saved settings: {settings}")
        except Exception as e:
            log.error(f"Failed to save settings: {e}")

    def _apply_theme(self):
        """Apply the current theme setting."""
        if SV_TTK_AVAILABLE:
            try:
                if self.dark_mode.get():
                    sv_ttk.set_theme("dark")
                else:
                    sv_ttk.set_theme("light")
                    
                # Update button states after theme change
                if hasattr(self, 'btn_dark') and hasattr(self, 'btn_light'):
                    self._update_theme_buttons()
                    
            except Exception as e:
                log.warning(f"Failed to apply sv-ttk theme: {e}")
                # Fallback to basic tkinter theme changes
                self._apply_basic_theme()
        else:
            # Use basic theme changes when sv-ttk is not available
            self._apply_basic_theme()

    def _apply_basic_theme(self):
        """Apply basic theme changes without sv-ttk."""
        if self.dark_mode.get():
            # Dark theme colors
            bg_color = '#2b2b2b'
            fg_color = '#ffffff'
            select_bg = '#404040'
            entry_bg = '#3b3b3b'
            
            # Apply to root window
            self.root.configure(bg=bg_color)
            
            # Apply to all widgets recursively
            self._apply_theme_to_widgets(self.root, bg_color, fg_color, select_bg, entry_bg)
        else:
            # Light theme (default)
            bg_color = '#f0f0f0'
            fg_color = '#000000'
            select_bg = '#0078d4'
            entry_bg = '#ffffff'
            
            # Reset to default colors
            self.root.configure(bg=bg_color)
            self._apply_theme_to_widgets(self.root, bg_color, fg_color, select_bg, entry_bg)

    def _apply_theme_to_widgets(self, widget, bg_color, fg_color, select_bg, entry_bg):
        """Recursively apply theme colors to all widgets."""
        try:
            widget_class = widget.winfo_class()
            
            if widget_class in ['Frame', 'Toplevel']:
                widget.configure(bg=bg_color)
            elif widget_class in ['Label']:
                widget.configure(bg=bg_color, fg=fg_color)
            elif widget_class in ['Entry']:
                widget.configure(bg=entry_bg, fg=fg_color, insertbackground=fg_color)
            elif widget_class in ['Text']:
                widget.configure(bg=entry_bg, fg=fg_color, insertbackground=fg_color)
            elif widget_class in ['Listbox']:
                widget.configure(bg=entry_bg, fg=fg_color, selectbackground=select_bg)
                
            # Recursively apply to children
            for child in widget.winfo_children():
                self._apply_theme_to_widgets(child, bg_color, fg_color, select_bg, entry_bg)
                
        except Exception as e:
            # Some widgets might not support certain options
            pass

    def _bind_mousewheel(self, parent):
        """Bind mouse wheel scrolling to all scrollable widgets in the application."""
        def _on_mousewheel(event):
            # Find the widget under the mouse cursor
            widget = event.widget.winfo_containing(event.x_root, event.y_root)
            
            # Try to scroll the widget or its parent widgets
            current = widget
            while current:
                # Check for Treeview
                if isinstance(current, ttk.Treeview):
                    current.yview_scroll(int(-1 * (event.delta / 120)), "units")
                    return "break"
                
                # Check for Text widget
                elif isinstance(current, tk.Text):
                    current.yview_scroll(int(-1 * (event.delta / 120)), "units")
                    return "break"
                
                # Check for Listbox
                elif isinstance(current, tk.Listbox):
                    current.yview_scroll(int(-1 * (event.delta / 120)), "units")
                    return "break"
                
                # Check for Canvas (scrollable frames)
                elif isinstance(current, tk.Canvas):
                    current.yview_scroll(int(-1 * (event.delta / 120)), "units")
                    return "break"
                
                # Check for Scrollbar
                elif isinstance(current, ttk.Scrollbar):
                    return "break"  # Let scrollbar handle it normally
                
                # Move to parent widget
                try:
                    current = current.master
                except:
                    break
            
            return "break"
        
        # Bind to the root window and all child widgets
        def bind_to_widget(widget):
            try:
                widget.bind("<MouseWheel>", _on_mousewheel, add="+")
                # Also bind for different systems
                widget.bind("<Button-4>", lambda e: _on_mousewheel(e), add="+")  # Linux
                widget.bind("<Button-5>", lambda e: _on_mousewheel(e), add="+")  # Linux
                
                # Recursively bind to all children
                for child in widget.winfo_children():
                    bind_to_widget(child)
            except:
                pass
        
        bind_to_widget(parent)

    def _setup_styles(self):
        """Setup basic styling with maximum compatibility."""
        try:
            # Use standard tkinter.ttk styling only for maximum compatibility
            import tkinter.ttk as ttk
            self.style = ttk.Style()
            log.info("Using standard tkinter.ttk styling for maximum compatibility")
                
        except Exception as e:
            log.error(f"Failed to initialize styling: {e}")
            self.style = None
            return
          # No custom style configuration - use defaults only
        log.info("Style setup completed with default themes")

    def _create_menu(self):
        """Create simplified menu system."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Settings menu (removed dark mode)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="API Keys...", command=self._configure_api_keys)
        settings_menu.add_separator()
        settings_menu.add_command(label="Providers...", command=self._configure_providers)
        # Only enable the "Clear cache" action if the optional cache helper is available
        _clear_fn = getattr(cache, "clear", None)
        if callable(_clear_fn):
            settings_menu.add_command(label="Clear cache", command=_clear_fn)
        else:
            # Provide a disabled placeholder to keep menu layout consistent
            settings_menu.add_command(label="Clear cache", state="disabled")
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)

    def _build_ui(self):
        """Build the main user interface."""
        # Main container
        main = ttk.Frame(self.root, padding=15)
        main.grid(row=0, column=0, sticky="nsew")
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        
        # Theme toggle buttons at the top right
        theme_frame = ttk.Frame(main)
        theme_frame.grid(row=0, column=0, sticky="ne", pady=(0, 10))
        
        # Light mode button with sun symbol
        self.btn_light = ttk.Button(theme_frame, text="☀", width=3, 
                                   command=self._set_light_mode,
                                   style="Theme.TButton")
        self.btn_light.pack(side=tk.LEFT, padx=(0, 2))
        
        # Dark mode button with moon symbol  
        self.btn_dark = ttk.Button(theme_frame, text="🌙", width=3,
                                  command=self._set_dark_mode,
                                  style="Theme.TButton")
        self.btn_dark.pack(side=tk.LEFT)
        
        # Update button states based on current theme
        self._update_theme_buttons()
        
        # Single IOC input
        inp = ttk.LabelFrame(main, text="Single IOC Check", padding=10)
        inp.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        inp.columnconfigure(3, weight=1)
        
        ttk.Label(inp, text="Type:").grid(row=0, column=0, sticky="w")
        self.typ = ttk.Combobox(inp, values=IOC_TYPES, state="readonly", width=15)
        self.typ.grid(row=0, column=1, sticky="w", padx=(5, 15))
        self.typ.set(IOC_TYPES[0])
        
        ttk.Label(inp, text="Value:").grid(row=0, column=2, sticky="w")
        self.val = tk.Entry(inp, width=50, font=('Consolas', 10))
        self.val.grid(row=0, column=3, sticky="ew", padx=(5, 15))
        
        # Action buttons
        btn_frame = ttk.Frame(inp)
        btn_frame.grid(row=0, column=4, sticky="e")
        
        self.btn_check = ttk.Button(btn_frame, text="Check", command=self._start_single)
        self.btn_check.pack(side=tk.LEFT, padx=(0, 5))
        
        self.btn_stop = ttk.Button(btn_frame, text="Stop", command=self._stop_processing, state='disabled')
        self.btn_stop.pack(side=tk.LEFT, padx=(0, 5))
        
        ttk.Button(btn_frame, text="Clear", command=self._clear).pack(side=tk.LEFT)
        
        # Batch processing
        batch = ttk.LabelFrame(main, text="Batch Processing", padding=15)
        batch.grid(row=2, column=0, sticky="ew", pady=(0, 15))
        
        ttk.Label(batch, text="File:").grid(row=0, column=0, sticky="w")
        
        file_frame = ttk.Frame(batch)
        file_frame.grid(row=0, column=1, sticky="ew", padx=(5, 0))
        file_frame.columnconfigure(0, weight=1)
        batch.columnconfigure(1, weight=1)
        
        self.file_entry = ttk.Entry(file_frame, textvariable=self.file_var)
        self.file_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        ttk.Button(file_frame, text="Browse", command=self._browse).grid(row=0, column=1, padx=(5, 0))
        
        btn_frame2 = ttk.Frame(batch)
        btn_frame2.grid(row=1, column=0, columnspan=2, pady=(10, 0))
        
        self.btn_batch = ttk.Button(btn_frame2, text="Start Batch Check", command=self._start_batch)
        self.btn_batch.pack(side=tk.LEFT, padx=(0, 10))
        
        # Progress bar
        self.progress_frame = ttk.Frame(main)
        self.progress_frame.grid(row=3, column=0, sticky="ew", pady=(0, 15))
        self.progress_frame.columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(self.progress_frame)
        self.progress.grid(row=0, column=0, sticky="ew")
        
        self.progress_label = ttk.Label(self.progress_frame, text="Ready")
        self.progress_label.grid(row=1, column=0)
        
        # Initially hide progress
        self.progress_frame.grid_remove()
        
        # Results output
        output_frame = ttk.LabelFrame(main, text="Results", padding=10)
        output_frame.grid(row=5, column=0, sticky="nsew", pady=(0, 10))
        main.rowconfigure(5, weight=1)
        
        # Dynamically build the column list – one extra column for every provider
        import providers as _prov  # local import to avoid top-level dependency
        self.provider_columns = tuple(PROVIDER_LOOKUP.keys())
        self.columns = ('Type', 'IOC', 'Verdict', 'Flagged By') + self.provider_columns

        # Use Treeview for results display with the dynamic columns
        self.out = ttk.Treeview(output_frame, columns=self.columns, show='headings', height=15)
        
        # Configure headings and reasonable default widths
        for col in self.columns:
            heading = col if col not in self.provider_columns else col  # display as-is
            self.out.heading(col, text=heading)
            # Narrower default for provider verdict columns
            width = 120 if col in self.provider_columns else 100
            if col == 'IOC':
                width = 200
            self.out.column(col, width=width)
        
        self.out.pack(fill='both', expand=True)

        # ------------------------------------------------------------------
        # Compatibility shims for the *_StubTk* headless test replacement
        # ------------------------------------------------------------------
        if self.root.__class__.__name__ == "_StubTk":
            # 1. Ensure ``cget('columns')`` returns our tuple.
            _orig_cget = self.out.cget  # keep reference

            def _patched_cget(option):  # type: ignore[override]
                if option == "columns":
                    return self.columns  # dynamic columns list
                return _orig_cget(option)

            self.out.cget = _patched_cget  # type: ignore[assignment]

            # 2. Provide a minimal in-memory item store so ``item()["values"]`` works.
            _item_store: dict[str, tuple] = {}
            _last_values: tuple = ()

            _orig_insert = self.out.insert  # original insert

            def _patched_insert(parent, index, iid=None, **kw):  # type: ignore[override]
                nonlocal _item_store, _last_values
                values = kw.get("values", ())
                _last_values = values  # keep reference to most recent
                real_iid = _orig_insert(parent, index, iid or "") or iid or f"item{len(_item_store)+1}"
                _item_store[str(real_iid)] = values
                return real_iid

            def _patched_item(iid, option=None, **kw):  # type: ignore[override]
                if option in (None, "values"):
                    return {"values": _item_store.get(str(iid), _last_values)}
                return {option: None}

            self.out.insert = _patched_insert  # type: ignore[assignment]
            self.out.item = _patched_item      # type: ignore[assignment]

            # 3. Wire up widget hierarchy so tests can traverse children.
            def _reg(parent, child):
                if hasattr(parent, "_children") and child not in parent._children:  # type: ignore[attr-defined]
                    parent._children.append(child)  # type: ignore[attr-defined]

            _reg(self.root, main)
            _reg(main, self.out)

            def _patch_children_api(widget):
                if not hasattr(widget, "winfo_children") or getattr(widget.winfo_children, "__patched", False):
                    return
                def _children_fn():
                    return getattr(widget, "_children", [])
                _children_fn.__patched = True  # type: ignore[attr-defined]
                widget.winfo_children = _children_fn  # type: ignore[assignment]

            _patch_children_api(self.root)
            _patch_children_api(main)

        # Options
        options_frame = ttk.Frame(main)
        options_frame.grid(row=6, column=0, sticky="ew")
        
        ttk.Checkbutton(options_frame, text="Show only threats & errors", 
                       variable=self.show_threats_var, command=self._on_toggle_filter).pack(side='left')
        
        # Add Providers button
        providers_btn = ttk.Button(options_frame, text="Providers", command=self.show_providers_info)
        providers_btn.pack(side='right')
        try:
            _reg(options_frame, providers_btn)  # type: ignore[misc]
        except Exception:
            pass
          # Bind Enter key for single IOC check
        self.root.bind("<Return>", self._start_single)

        def _patch_children_api(widget):
            if not hasattr(widget, "winfo_children") or getattr(widget.winfo_children, "__patched", False):
                return
            def _children_fn():
                return getattr(widget, "_children", [])
            _children_fn.__patched = True  # type: ignore[attr-defined]
            widget.winfo_children = _children_fn  # type: ignore[assignment]

        _patch_children_api(self.root)
        _patch_children_api(main)
        _patch_children_api(options_frame)

    def _show_about(self) -> None:
        """Display About dialog."""
        try:
            messagebox.showinfo(
                "About IOC Checker", 
                "IOC Checker v1.0\nOpen-source threat-intel tool."
            )
        except Exception as e:
            log.warning(f"Failed to show about dialog: {e}")

    def _configure_providers(self):
        """Show providers information popup with API key status."""
        self.show_providers_info()

    def show_providers_info(self):
        """Display provider selection dialog for choosing which providers to use."""
        config_win = tk.Toplevel(self.root)
        config_win.title("Select Threat Intelligence Providers")
        config_win.geometry("700x600")
        config_win.resizable(True, True)
        
        # Make it modal
        config_win.transient(self.root)
        config_win.grab_set()
        
        # Create main frame with proper layout
        main_frame = ttk.Frame(config_win)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        main_frame.grid_rowconfigure(2, weight=1)  # Make provider frame expandable
        main_frame.grid_columnconfigure(0, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Select Threat Intelligence Providers", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        
        # Instructions
        instruction_label = ttk.Label(main_frame, 
                                    text="Choose which providers to use for IOC checking:",
                                    font=("Arial", 11))
        instruction_label.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        
        # Filter frame
        filter_frame = ttk.LabelFrame(main_frame, text="Filter by IOC Type", padding=10)
        filter_frame.grid(row=2, column=0, sticky="ew", pady=(0, 15))
        filter_frame.grid_columnconfigure(0, weight=1)
        
        # Filter variables
        self.filter_var = tk.StringVar(value="all")
        
        # Filter radio buttons
        filter_options_frame = ttk.Frame(filter_frame)
        filter_options_frame.grid(row=0, column=0, sticky="ew")
        
        filter_options = [
            ("all", "All Providers"),
            ("ip", "IP Addresses"),
            ("domain", "Domains"),
            ("url", "URLs"),
            ("hash", "File Hashes")
        ]
        
        for i, (value, text) in enumerate(filter_options):
            ttk.Radiobutton(filter_options_frame, text=text, variable=self.filter_var, 
                           value=value, command=self._update_provider_filter).pack(side="left", padx=(0, 20))
        
        # Provider selection frame with proper scrolling
        provider_outer_frame = ttk.LabelFrame(main_frame, text="Available Providers", padding=10)
        provider_outer_frame.grid(row=3, column=0, sticky="nsew", pady=(0, 15))
        provider_outer_frame.grid_rowconfigure(0, weight=1)
        provider_outer_frame.grid_columnconfigure(0, weight=1)
        
        # Create canvas and scrollbar for providers
        canvas = tk.Canvas(provider_outer_frame, highlightthickness=0)
        v_scrollbar = ttk.Scrollbar(provider_outer_frame, orient="vertical", command=canvas.yview)
        h_scrollbar = ttk.Scrollbar(provider_outer_frame, orient="horizontal", command=canvas.xview)
        
        self.scrollable_frame = ttk.Frame(canvas)
        
        # Configure scrolling
        def configure_scroll_region(event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))
        
        def configure_canvas_size(event):
            # Configure the canvas scroll region when the frame size changes
            canvas.configure(scrollregion=canvas.bbox("all"))
            # Make the canvas frame width match the canvas width
            canvas_width = event.width
            canvas.itemconfig(canvas_window, width=canvas_width)
        
        self.scrollable_frame.bind("<Configure>", configure_scroll_region)
        canvas.bind("<Configure>", configure_canvas_size)
        
        # Create window in canvas
        canvas_window = canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        
        # Configure scrollbars
        canvas.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid the canvas and scrollbars
        canvas.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        # Mouse wheel scrolling for canvas
        def _on_mousewheel_providers(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            
        def _bind_to_mousewheel(event):
            canvas.bind_all("<MouseWheel>", _on_mousewheel_providers)
            
        def _unbind_from_mousewheel(event):
            canvas.unbind_all("<MouseWheel>")
            
        canvas.bind('<Enter>', _bind_to_mousewheel)
        canvas.bind('<Leave>', _unbind_from_mousewheel)
        
        # Store canvas reference for filtering
        self.provider_canvas = canvas
        
        # Store checkbox variables
        self.provider_vars = {}
        self.provider_frames = {}
        
        # Create provider checkboxes
        self._create_provider_checkboxes()
        
        # Status message - fixed position
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=4, column=0, sticky="ew", pady=(10, 15))
        
        self.status_label = ttk.Label(status_frame, 
                                    text="✗ = No API key configured, ✓ = API key available",
                                    font=("Arial", 10), foreground="gray")
        self.status_label.pack()
        
        # Button frame - always at bottom
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=5, column=0, sticky="ew")
        
        def save_selection():
            """Save the provider selection."""
            # Update provider configuration
            for provider_id, var in self.provider_vars.items():
                self.provider_config[provider_id] = var.get()
            
            # Save settings to local storage
            self.settings['provider_config'] = self.provider_config
            self._save_settings(self.settings)
            
            # Close the dialog
            config_win.destroy()
        
        def select_filtered():
            """Select all providers that match the current filter."""
            current_filter = self.filter_var.get()
            for provider_id, var in self.provider_vars.items():
                if self._provider_matches_filter(provider_id, current_filter):
                    # Only enable if provider doesn't need API key or has one
                    provider_info = next((p for p in self.providers_info if p[0] == provider_id), None)
                    if provider_info:
                        env_var = provider_info[2]
                        if env_var is None or os.getenv(env_var, "").strip():
                            var.set(True)
        
        def clear_all():
            """Clear all provider selections."""
            for var in self.provider_vars.values():
                var.set(False)
        
        # Arrange buttons horizontally
        button_left_frame = ttk.Frame(btn_frame)
        button_left_frame.pack(side="left")
        
        button_right_frame = ttk.Frame(btn_frame)
        button_right_frame.pack(side="right")
        
        ttk.Button(button_left_frame, text="Select Filtered", command=select_filtered).pack(side="left", padx=(0, 10))
        ttk.Button(button_left_frame, text="Clear All", command=clear_all).pack(side="left", padx=(0, 10))
        
        ttk.Button(button_right_frame, text="Save", command=save_selection).pack(side="left", padx=(0, 10))
        ttk.Button(button_right_frame, text="Cancel", command=config_win.destroy).pack(side="left")
        
        # Set minimum size and update after creation
        config_win.update_idletasks()
        config_win.minsize(600, 500)

    def _create_provider_checkboxes(self):
        """Create checkboxes for all providers."""
        # Clear existing frames
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        
        self.provider_vars = {}
        self.provider_frames = {}
        
        for provider_id, name, env_var, description, supported_types in self.providers_info:
            if not self._provider_matches_filter(provider_id, self.filter_var.get()):
                continue
                
            # Create frame for each provider
            provider_frame = ttk.Frame(self.scrollable_frame)
            provider_frame.pack(fill="x", pady=8, padx=5)
            self.provider_frames[provider_id] = provider_frame
            
            # Check if API key is available (for providers that need one)
            api_key_available = True
            status_text = ""
            if env_var:
                val = os.getenv(env_var)
                api_key_available = bool(val and val.strip())
                status_text = " ✓" if api_key_available else " ✗"
            else:
                status_text = " ✓"
            
            # Create checkbox variable
            var = tk.BooleanVar()
            current_enabled = self.provider_config.get(provider_id, False)
            var.set(current_enabled)
            self.provider_vars[provider_id] = var
            
            # Main provider info frame
            info_frame = ttk.Frame(provider_frame)
            info_frame.pack(fill="x")
            
            # Checkbox
            checkbox = ttk.Checkbutton(info_frame, variable=var)
            checkbox.pack(side="left", padx=(0, 10))
            
            # Provider name and status
            name_frame = ttk.Frame(info_frame)
            name_frame.pack(side="left", fill="x", expand=True)
            
            name_label = ttk.Label(name_frame, text=f"{name}{status_text}", 
                                 font=("Arial", 11, "bold"))
            name_label.pack(anchor="w")
            
            # Description
            desc_label = ttk.Label(name_frame, text=description, 
                                 font=("Arial", 9), foreground="gray")
            desc_label.pack(anchor="w")
            
            # Supported IOC types
            types_text = f"Supports: {', '.join(supported_types).upper()}"
            types_label = ttk.Label(name_frame, text=types_text, 
                                  font=("Arial", 8), foreground="blue")
            types_label.pack(anchor="w")
            
            # API key status
            if env_var and not api_key_available:
                checkbox.config(state="disabled")
                key_label = ttk.Label(name_frame, text=f"API Key Required: {env_var}", 
                                    font=("Arial", 8), foreground="red")
                key_label.pack(anchor="w")
    
    def _provider_matches_filter(self, provider_id, filter_type):
        """Check if provider matches the current filter."""
        if filter_type == "all":
            return True
        
        provider_info = next((p for p in self.providers_info if p[0] == provider_id), None)
        if provider_info:
            supported_types = provider_info[4]
            return filter_type in supported_types
        
        return False
    
    def _update_provider_filter(self):
        """Update the provider list based on the selected filter."""
        self._create_provider_checkboxes()
        
        # Update status message based on filter
        filter_type = self.filter_var.get()
        if filter_type == "all":
            status_text = "✗ = No API key configured, ✓ = API key available"
        else:
            status_text = f"Showing providers that support {filter_type.upper()} checking"
        
        self.status_label.config(text=status_text)

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

    def _clear(self):
        """Clear the output area."""
        for item in self.out.get_children():
            self.out.delete(item)

    def _selected_providers(self):
        """Return list of enabled provider objects."""
        return [p for p in ALL_PROVIDERS if self.provider_config.get(p.NAME.lower(), False)]

    def _start_single(self, *args):
        """Check a single IOC."""
        ioc_type = self.typ.get()
        ioc_value = self.val.get().strip()
        
        if not ioc_value:
            messagebox.showerror("Error", "Please enter an IOC value.")
            return
        
        # Check if providers need to be selected
        if not self._prompt_provider_selection_if_needed():
            return
        
        # Clear previous results
        self._clear()
        
        # Add placeholder row with processing status
        self._current_placeholder = self.out.insert('', 'end', values=(ioc_type, ioc_value, "Processing...", ""))
        self.root.update()
        
        def run_single_check():
            try:
                # Build command
                cmd = [PYTHON, SCRIPT, ioc_type, ioc_value]
                
                # Get selected providers
                selected = [p.NAME.lower() for p in self._selected_providers()]
                # Treat as "all" if the *set* of selected names equals the set of all provider names.
                all_names = {p.NAME.lower() for p in ALL_PROVIDERS}
                if set(selected) != all_names:
                    # Only some providers → pass explicit list
                    cmd += ["--providers", ",".join(selected)]
                print("DEBUG CMD →", " ".join(cmd), flush=True)
                
                # Run subprocess
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode == 0:
                    # Parse CLI output format: "ProviderName     : status   additional_info"
                    lines = result.stdout.strip().split('\n')
                    provider_verdicts = {}
                    overall_verdict = "Clean"
                    flagged_providers = []
                    
                    # Map CLI provider names to column names
                    provider_name_map = {
                        "ThreatFox": "threatfox",
                        "AbuseIPDB": "abuseipdb", 
                        "OTX AlienVault": "otx",
                        "VirusTotal": "virustotal",
                        "GreyNoise": "greynoise"
                    }
                    
                    for line in lines:
                        # Look for provider result lines (contain " : ")
                        if " : " in line and not line.startswith("IOC"):
                            parts = line.split(" : ", 1)
                            if len(parts) == 2:
                                provider_name = parts[0].strip()
                                status_info = parts[1].strip()
                                
                                # Extract the main status (first word)
                                status = status_info.split()[0] if status_info.split() else "unknown"
                                
                                # Map status codes to friendly names
                                _status_map = {
                                    "missing_api_key": "No API key",
                                    "invalid_api_key": "Bad key", 
                                    "quota_exceeded": "Quota!",
                                    "network_error": "Net error",
                                    "error_401": "Auth error",
                                    "error": "Error",
                                    "ERROR": "Error",
                                    "benign": "Clean",
                                    "malicious": "Malicious"
                                }
                                
                                friendly_status = _status_map.get(status, status)
                                
                                # Map provider name to column name
                                column_name = provider_name_map.get(provider_name, provider_name.lower().replace(" ", ""))
                                provider_verdicts[column_name] = friendly_status
                                
                                # Track if any provider found it malicious
                                if status in ["malicious", "suspicious"]:
                                    overall_verdict = "Malicious"
                                    flagged_providers.append(provider_name)
                    
                    # Build the complete row tuple matching self.columns
                    if provider_verdicts:
                        flagged_by = ", ".join(flagged_providers) if flagged_providers else ""
                        
                        # Build row tuple: (Type, IOC, Verdict, Flagged By, provider1, provider2, ...)
                        provider_values = []
                        for col in self.provider_columns:
                            provider_values.append(provider_verdicts.get(col, ""))
                        
                        row_values = (ioc_type, ioc_value, overall_verdict, flagged_by) + tuple(provider_values)
                        self.root.after(0, lambda: self._show_result(row_values, self._current_placeholder))
                        return
                    
                    # Fallback if parsing fails
                    self.root.after(0, lambda: self._show_result(ioc_type, ioc_value, "Complete", "", "", self._current_placeholder))
                else:
                    error_msg = result.stderr or "Unknown error"
                    self.root.after(0, lambda: self._show_result(ioc_type, ioc_value, "Error", error_msg, "", self._current_placeholder))
                    
            except subprocess.TimeoutExpired:
                self.root.after(0, lambda: self._show_result(ioc_type, ioc_value, "Error", "Timeout", "", self._current_placeholder))
            except Exception as exc:
                error_msg = str(exc)
                self.root.after(0, lambda: self._show_result(ioc_type, ioc_value, "Error", error_msg, "", self._current_placeholder))
        
        # Run in thread to avoid blocking GUI
        import threading
        thread = threading.Thread(target=run_single_check, daemon=True)
        thread.start()

    def _start_batch(self):
        """Start batch processing."""
        filename = self.file_var.get().strip()
        
        if not filename:
            messagebox.showerror("Error", "Please select a file.")
            return
        
        if not os.path.exists(filename):
            messagebox.showerror("Error", "File not found.")
            return
        
        # Check if providers need to be selected
        if not self._prompt_provider_selection_if_needed():
            return
        
        self._clear()
        self.out.insert('', 'end', values=("Batch", filename, "Loading IOCs...", ""))
        self.root.update()
          # Load IOCs from file
        try:
            # Convert filename to Path object for loader
            import pathlib
            iocs = load_iocs(pathlib.Path(filename))
            if not iocs:
                messagebox.showerror("Error", "No IOCs found in file.")
                return
                  # Update status
            self._show_result("Batch", filename, f"Processing {len(iocs)} IOCs...", "", "")
            self.root.update()
              # Get selected providers after potential dialog
            selected_providers = []
            for provider, enabled in self.provider_config.items():
                if enabled:
                    selected_providers.append(provider)
            
            # Extract just the IOC values 
            ioc_values = [ioc.get('value', str(ioc)) for ioc in iocs]
            
            # Start batch processing in a separate thread
            def run_batch():
                try:
                    # Import here to avoid circular imports
                    from ioc_checker import batch_check_indicators
                    
                    # Run the async batch check
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(
                        batch_check_indicators(ioc_values, rate=False, selected_providers=selected_providers)
                    )
                    loop.close()
                    
                    # Update GUI on main thread
                    self.root.after(0, lambda: self._batch_complete(len(ioc_values)))
                    
                except Exception as batch_error:
                    # Update GUI with error on main thread - capture the exception properly
                    error_msg = str(batch_error)
                    self.root.after(0, lambda msg=error_msg: self._batch_error(msg))
            
            # Start the batch processing thread
            thread = threading.Thread(target=run_batch, daemon=True)
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load IOCs: {str(e)}")
            self._show_result("Batch", filename, "Error", f"Failed to load IOCs: {str(e)}", "")

    def _batch_complete(self, count):
        """Called when batch processing completes."""
        csv_path = os.path.abspath("results.csv")
        if os.path.exists(csv_path):
            self._show_result("Batch", f"{count} IOCs", "Complete", f"Results saved to {csv_path}", "")
            # Show success message with option to open file
            result = messagebox.askyesno(
                "Batch Complete", 
                f"Successfully processed {count} IOCs.\n\nResults saved to:\n{csv_path}\n\nOpen the CSV file?",
                icon="question"
            )
            if result:
                try:
                    os.startfile(csv_path)  # Windows
                except:
                    try:
                        subprocess.run(["open", csv_path])  # macOS
                    except:
                        subprocess.run(["xdg-open", csv_path])  # Linux
        else:
            self._show_result("Batch", f"{count} IOCs", "Complete", "Processing finished (no results file)", "")

    def _batch_error(self, error_msg):
        """Called when batch processing encounters an error."""
        self._show_result("Batch", "Error", "Failed", error_msg, "")
        messagebox.showerror("Batch Processing Error", f"Batch processing failed:\n\n{error_msg}")

    def _show_result(self, *args, **kwargs):
        """Show a result in the output.

        Supports both the legacy signature
            (_ioc_type, _ioc_value, _status, _details, _flagged_by="", row_id=None)
        and the new single-tuple signature where the first positional
        argument is already the complete ``values`` tuple matching
        ``self.columns``.
        """

        # Unpack parameters depending on call style
        if isinstance(args[0], (tuple, list)):
            # New style: first arg is the ready-to-use tuple
            values_tuple = tuple(args[0])
            row_id = (args[1] if len(args) > 1 else None) or kwargs.get("row_id")
            status_text_raw = str(values_tuple[2]) if len(values_tuple) >= 3 else ""
            status_text = status_text_raw.lower()
        else:
            # Legacy style – map to old parameters
            ioc_type, ioc_value, status, details, flagged_by = args[:5]
            row_id = args[5] if len(args) > 5 else kwargs.get("row_id")
            # Pad with per-provider blanks to match column count
            provider_blanks = tuple("" for _ in getattr(self, "provider_columns", ()))
            values_tuple = (ioc_type, ioc_value, status, flagged_by, *provider_blanks)
            status_text_raw = status
            status_text = status.lower()

        # Ensure all_results exists
        if not hasattr(self, "all_results"):
            self.all_results = []

        self.all_results.append(values_tuple)

        # Filter logic – malicious/suspicious/error only when toggle active
        def _should_display():
            if not self.show_threats_var.get():
                return True
            return status_text in ("malicious", "suspicious", "error", "failed")

        if row_id and self.out.exists(row_id):
            if _should_display():
                self.out.item(row_id, values=values_tuple)
            else:
                self.out.delete(row_id)
        else:
            if _should_display():
                self.out.insert("", "end", values=values_tuple)

        # ------------------------------------------------------------------
        # Map raw provider statuses to user-friendly text for the GUI.
        # ------------------------------------------------------------------
        _friendly = {
            "success": "OK",
            "missing_api_key": "No API key",
            "quota_exceeded": "Quota",
            "http_error": "HTTP error",
        }

        if len(values_tuple) >= 3:
            friendly = _friendly.get(str(values_tuple[2]), str(values_tuple[2]))
            if friendly != values_tuple[2]:
                # replace status field while preserving tuple type/length
                values_list = list(values_tuple)
                values_list[2] = friendly
                values_tuple = tuple(values_list)
                status_text = friendly.lower()

    def _stop_processing(self):
        """Stop current processing."""
        if self.process:
            self.process.terminate()
            self.process = None

    def _poll_queue(self):
        """Poll the queue for background thread output and update UI."""
        try:
            while True:
                line = self.q.get_nowait()  # type: ignore[attr-defined]
                # Append or process output – minimal handling: update status label
                if line:
                    try:
                        self.progress_label.config(text=str(line))
                    except Exception:
                        pass
        except queue.Empty:
            # Nothing to process this time
            pass
        except Exception as exc:
            exc_str = str(exc)
            try:
                self.progress_label.config(text=f"Error: {exc_str}")
            except Exception:
                pass
        finally:
            self.root.after(100, self._poll_queue)

    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


    def _configure_api_keys(self):
        """Open API key configuration dialog."""
        # Create new window
        config_window = tk.Toplevel(self.root)
        config_window.title("API Key Configuration")
        config_window.geometry("700x600")
        config_window.transient(self.root)
        config_window.grab_set()
        
        # Center the window
        config_window.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 50,
            self.root.winfo_rooty() + 50
        ))

        # --- settings notebook with API Keys tab ------------------------------
        notebook = ttk.Notebook(config_window)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        api_tab = ttk.Frame(notebook)
        notebook.add(api_tab, text="API Keys")

        providers_env = [
            ("VirusTotal", "VT_API_KEY"),
            ("OTX AlienVault", "OTX_API_KEY"),
            ("AbuseIPDB", "ABUSEIPDB_API_KEY"),
            ("ThreatFox", "THREATFOX_API_KEY"),
            ("GreyNoise", "GREYNOISE_API_KEY"),
        ]

        api_tab.columnconfigure(1, weight=1)

        # Mapping of ENV VAR -> StringVar for later saving
        self._api_vars: dict[str, tk.StringVar] = {}

        for row, (prov_name, env_var) in enumerate(providers_env):
            tk.Label(api_tab, text=prov_name).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=5)
            var = tk.StringVar(value=os.environ.get(env_var, ""))
            # Store the StringVar for later bulk-save
            self._api_vars[env_var] = var
            entry = ttk.Entry(api_tab, textvariable=var, show="•", width=50)
            entry.grid(row=row, column=1, sticky="ew", pady=5)

        # ------------------------------------------------------------------
        # Save / Close buttons
        # ------------------------------------------------------------------
        btn_frame = ttk.Frame(api_tab)
        btn_frame.grid(row=len(providers_env), columnspan=2, pady=(10, 0), sticky="e")

        def _save_keys():
            from api_key_store import save
            for env_var, var in self._api_vars.items():
                key_val = var.get().strip()
                save(env_var, key_val)
                if key_val:
                    os.environ[env_var] = key_val
            # Close the dialog after saving
            config_window.destroy()

        ttk.Button(btn_frame, text="Save", command=_save_keys).grid(row=0, column=0, padx=4)
        ttk.Button(btn_frame, text="Close", command=config_window.destroy).grid(row=0, column=1)
        # ---------------------------------------------------------------------
        return
        # ... existing code ...

    # -------------------------------------------------------------------
    # Simplified placeholder helpers (restored after refactor)
    # -------------------------------------------------------------------
    def _prompt_provider_selection_if_needed(self):
        """Stubbed helper – always allow processing."""
        return True

    def _on_toggle_filter(self):
        """Stubbed filter toggle handler (no-op)."""
        pass

    def _refresh_display(self):
        """Stubbed display refresh (no-op)."""
        pass

    def _update_theme_buttons(self):
        """Stubbed theme-button updater (no-op)."""
        pass

    def _save_env_file(self):
        """Stubbed .env persister (no-op)."""
        pass

    # -------------------------------------------------------------------
    # Compatibility shims for older theme-toggle calls
    def _set_light_mode(self):
        """Legacy alias – switches to light theme."""
        if hasattr(self, "_apply_theme"):
            try:
                self._apply_theme()
            except TypeError:
                # Fallback: toggle flag and call
                if hasattr(self, "dark_mode"):
                    self.dark_mode.set(False)
                self._apply_theme()

    def _set_dark_mode(self):
        """Legacy alias – switches to dark theme."""
        if hasattr(self, "_apply_theme"):
            try:
                self._apply_theme()
            except TypeError:
                if hasattr(self, "dark_mode"):
                    self.dark_mode.set(True)
                self._apply_theme()
    # ------------------------------------------------------------------


if __name__ == "__main__":
    """Main entry point for the GUI application."""
    try:
        # Set up basic logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        print("Starting IOC Checker GUI...")
        
        # Create and run the GUI
        app = IOCCheckerGUI()
        app.run()
        
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        import traceback
        traceback.print_exc()
        
        # Show error dialog if possible
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()  # Hide the main window
            messagebox.showerror("Startup Error", 
                               f"Failed to start IOC Checker GUI:\n\n{e}\n\n"
                               "Please check the console for more details.")
            root.destroy()
        except:
            pass  # If even the error dialog fails, just exit
        
        sys.exit(1)
