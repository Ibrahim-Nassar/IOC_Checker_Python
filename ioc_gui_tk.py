#!/usr/bin/env python3
"""
Simplified Tkinter GUI for IOC checking using the unified result format.
"""
from __future__ import annotations

# Enable pytest module aliasing
import sys
sys.modules['IOC_Checker_Python.ioc_gui_tk'] = sys.modules[__name__]

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import asyncio
import logging
import os
import sys
import threading
import queue
from pathlib import Path
import functools
import csv
from datetime import datetime
from ioc_types import IOCStatus, IOCResult, detect_ioc_type, validate_ioc
from providers import get_providers
from ioc_checker import aggregate_verdict, scan_ioc
from api_key_store import save as save_key, load as load_key
from loader import load_iocs as _load_iocs

_STATUS_MAP = {
    IOCStatus.SUCCESS: "✔ Clean",
    IOCStatus.MALICIOUS: "✖ Malicious", 
    IOCStatus.ERROR: "⚠ Error",
    IOCStatus.UNSUPPORTED: "— N/A",
    IOCStatus.NOT_FOUND: "◯ Not Found",
}

# Re-export for tests
load_iocs = _load_iocs

# Set UTF-8 encoding for console output when available
try:
    import locale
    locale.setlocale(locale.LC_ALL, '')
except (ImportError, locale.Error):
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("gui")

def _safe_task_id() -> str:
    """Return current asyncio task id or 'main-thread' if no loop."""
    try:
        t = asyncio.current_task()
        return str(id(t)) if t else "main-thread"
    except RuntimeError:
        return "main-thread"

def setup_verbose_logging():
    """Configure verbose logging for batch processing debugging."""
    # Create rotating file handler for debug logs
    debug_log_path = Path("ioc_gui_debug.log")
    
    # Simple logging: no rotating file handler
    if os.environ.get("IOC_GUI_DEBUG") == "1":
        root_logger = logging.getLogger()
        handler = logging.FileHandler(debug_log_path, encoding="utf-8")
        formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s")
        handler.setFormatter(formatter)
        root_logger.addHandler(handler)
        root_logger.setLevel(logging.DEBUG)
        log.info("Debug logging enabled via IOC_GUI_DEBUG=1")
    else:
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.INFO)
    
    log.info(f"Verbose logging configured, writing to {debug_log_path}")

AVAILABLE_PROVIDERS = {
    'virustotal': 'VirusTotal',
    'abuseipdb': 'AbuseIPDB', 
    'otx': 'AlienVault OTX',
}

# Module-level flag to prevent duplicate background loops
_GUI_LOOP_RUNNING = False
_GUI_LOOP = None
_GUI_LOOP_THREAD = None

# Simple tooltip class for better UX
class ToolTip:
    """Simple tooltip for tkinter widgets."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tooltip_window = None
        widget.bind("<Enter>", self.on_enter)
        widget.bind("<Leave>", self.on_leave)
    
    def on_enter(self, event=None):
        if self.tooltip_window:
            return
        x = self.widget.winfo_rootx() + 25
        y = self.widget.winfo_rooty() + 25
        self.tooltip_window = tk.Toplevel(self.widget)
        self.tooltip_window.wm_overrideredirect(True)
        self.tooltip_window.wm_geometry(f"+{x}+{y}")
        label = tk.Label(self.tooltip_window, text=self.text, 
                        background="lightyellow", relief="solid", borderwidth=1,
                        font=("Arial", 8, "normal"))
        label.pack()
    
    def on_leave(self, event=None):
        if self.tooltip_window:
            self.tooltip_window.destroy()
            self.tooltip_window = None

class IOCCheckerGUI:
    
    def __init__(self):
        # Set up verbose logging first
        setup_verbose_logging()
        
        self.root = tk.Tk()
        self.root.title("IOC Checker - Enhanced GUI")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        self.processing = False
        self.all_results = []
        self.q = queue.Queue()
        self.batch_task = None  # Track current batch task for cancellation
        self.processed_iocs = set()  # Track processed IOCs to prevent duplicates
        self._cached_providers = None  # Cache providers during batch processing
        
        self.provider_config = {
            'virustotal': False,
            'abuseipdb': False,
            'otx': False,
        }
        
        # Reference to the background loop
        self.loop = _GUI_LOOP
        
        self.providers_info = [
            ("virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", "Universal threat intelligence platform", ["ip", "domain", "url", "hash"]),
            ("abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", "IP reputation and abuse reports", ["ip"]),
            ("otx", "AlienVault OTX", "OTX_API_KEY", "Open threat exchange platform", ["ip", "domain", "url", "hash"]),
        ]
        
        self.show_threats_var = tk.BooleanVar(value=False)
        self.file_var = tk.StringVar()
        self.dark_mode = tk.BooleanVar(value=False)
        
        # Load saved API keys before any provider discovery
        _API_VARS = ("VIRUSTOTAL_API_KEY", "OTX_API_KEY",
                     "ABUSEIPDB_API_KEY")
        
        loaded_keys = []
        for var in _API_VARS:
            val = load_key(var)
            if val:
                os.environ[var] = val
                loaded_keys.append(var)
        
        # Log which API keys were loaded for debugging
        import logging
        if loaded_keys:
            logging.info(f"Loaded {len(loaded_keys)} saved API keys: {', '.join(loaded_keys)}")
        else:
            logging.info("No saved API keys found")
        
        self._create_menu()
        self._build_ui()
        self._poll_queue()
        
        # Set up graceful shutdown
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    

    def _on_close(self) -> None:
        """Gracefully stop the background event loop and close the GUI."""
        global _GUI_LOOP_RUNNING, _GUI_LOOP, _GUI_LOOP_THREAD
        
        if _GUI_LOOP and not _GUI_LOOP.is_closed():
            _GUI_LOOP.call_soon_threadsafe(_GUI_LOOP.stop)
        
        # Wait briefly for loop to stop
        if _GUI_LOOP_THREAD:
            try:
                _GUI_LOOP_THREAD.join(timeout=1.0)
            except:
                pass  # Best effort cleanup
        
        _GUI_LOOP_RUNNING = False
        _GUI_LOOP = None
        _GUI_LOOP_THREAD = None
        
        self.root.destroy()
    
    def _create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Configure Providers", command=self._configure_providers)
        tools_menu.add_command(label="Configure API Keys", command=self._configure_api_keys)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self._show_about)
    
    def _build_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        input_frame = ttk.LabelFrame(main_frame, text="Input", padding=10)
        input_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(input_frame, text="IOC Type:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        self.type_var = tk.StringVar(value="auto")
        type_combo = ttk.Combobox(input_frame, textvariable=self.type_var, 
                                  values=["auto", "ip", "domain", "url", "hash"], state="readonly", width=10)
        type_combo.grid(row=0, column=1, sticky="w", padx=(0, 10))
        
        ttk.Label(input_frame, text="IOC Value:").grid(row=0, column=2, sticky="w", padx=(0, 5))
        self.ioc_var = tk.StringVar()
        self.ioc_entry = ttk.Entry(input_frame, textvariable=self.ioc_var, width=40)
        self.ioc_entry.grid(row=0, column=3, sticky="ew", padx=(0, 10))
        self.ioc_entry.bind("<Return>", self._start_single)
        
        ttk.Button(input_frame, text="Check", command=self._start_single).grid(row=0, column=4)
        
        input_frame.columnconfigure(3, weight=1)
        
        file_frame = ttk.LabelFrame(main_frame, text="Batch Processing", padding=10)
        file_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(file_frame, text="File:").grid(row=0, column=0, sticky="w", padx=(0, 5))
        ttk.Entry(file_frame, textvariable=self.file_var, width=50).grid(row=0, column=1, sticky="ew", padx=(0, 10))
        ttk.Button(file_frame, text="Browse", command=self._browse).grid(row=0, column=2, padx=(0, 10))
        self.process_button = ttk.Button(file_frame, text="Process", command=self._start_batch)
        self.process_button.grid(row=0, column=3, padx=(0, 5))
        self.stop_button = ttk.Button(file_frame, text="Stop", command=self._stop_batch, state="disabled")
        self.stop_button.grid(row=0, column=4)
        
        file_frame.columnconfigure(1, weight=1)
        
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Checkbutton(options_frame, text="Show threats only", 
                       variable=self.show_threats_var, command=self._refresh_display).pack(side="left")
        
        ttk.Button(options_frame, text="Clear", command=self._clear).pack(side="right")
        
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding=10)
        results_frame.pack(fill="both", expand=True)
        
        # Initialize with all potential columns
        self.base_columns = ["Type", "IOC", "Verdict", "Flagged By"]
        self.columns = self.base_columns[:]  # Will be updated dynamically
        
        self.out = ttk.Treeview(results_frame, columns=self.columns, show="headings", height=15)
        
        # Configure base columns initially
        for col in self.base_columns:
            self.out.heading(col, text=col)
            if col in ("Type", "Verdict"):
                self.out.column(col, anchor="center", stretch=True, minwidth=80, width=120)
            elif col == "IOC":
                self.out.column(col, anchor="w", stretch=True, minwidth=200, width=300)
            elif col == "Flagged By":
                self.out.column(col, anchor="w", stretch=True, minwidth=120, width=180)
        
        def _resize(event):
            total = event.width
            MIN_WIDTH = sum(self.out.column(c, option="minwidth") for c in self.columns)
            if total <= MIN_WIDTH:
                return
            
            active_providers = self._selected_providers()
            provider_count = len(active_providers)
            
            # Proportional sizing: Type(8%), IOC(35%), Verdict(12%), Flagged By(15%), Providers(30% total)
            type_width = int(total * 0.08)
            ioc_width = int(total * 0.35)
            verdict_width = int(total * 0.12)
            flagged_width = int(total * 0.15)
            provider_total = int(total * 0.30)
            provider_width = provider_total // provider_count if provider_count else 80
            
            self.out.column("Type", width=max(type_width, 60))
            self.out.column("IOC", width=max(ioc_width, 200))
            self.out.column("Verdict", width=max(verdict_width, 80))
            self.out.column("Flagged By", width=max(flagged_width, 120))
            
            for provider in active_providers:
                self.out.column(provider.NAME, width=max(provider_width, 80))
        
        self.out.bind("<Configure>", _resize)
        
        scrollbar_v = ttk.Scrollbar(results_frame, orient="vertical", command=self.out.yview)
        scrollbar_h = ttk.Scrollbar(results_frame, orient="horizontal", command=self.out.xview)
        self.out.configure(yscrollcommand=scrollbar_v.set, xscrollcommand=scrollbar_h.set)
        
        self.out.grid(row=0, column=0, sticky="nsew")
        scrollbar_v.grid(row=0, column=1, sticky="ns")
        scrollbar_h.grid(row=1, column=0, sticky="ew")
        
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
        
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill="x", pady=(10, 0))
        
        self.progress_label = ttk.Label(status_frame, text="Ready")
        self.progress_label.pack(side="left")
        
    def _update_treeview_columns(self):
        """Update treeview columns based on selected providers."""
        active_providers = self._selected_providers()
        self.columns = self.base_columns + [p.NAME for p in active_providers]
        
        # Reconfigure treeview with new columns
        self.out.config(columns=self.columns)
        
        # Clear any stale columns that may exist
        current_columns = list(self.out["columns"])
        for col in current_columns:
            if col not in self.columns:
                self.out.heading(col, text="")
                self.out.column(col, width=0, stretch=False)
        
        # Set up headings and column properties for all columns
        for col in self.columns:
            self.out.heading(col, text=col)
            if col in ("Type", "Verdict"):
                self.out.column(col, anchor="center", stretch=True, minwidth=80, width=120)
            elif col == "IOC":
                self.out.column(col, anchor="w", stretch=True, minwidth=200, width=300)
            elif col == "Flagged By":
                self.out.column(col, anchor="w", stretch=True, minwidth=120, width=180)
            else:  # Provider columns
                self.out.column(col, anchor="center", stretch=True, minwidth=80, width=120)
    
    def _show_about(self):
        about_text = (
            "IOC Checker GUI\n"
            "Version 1.0\n\n"
            "Simple interface for checking IoCs across multiple threat intelligence providers.\n\n"
            "Features:\n"
            "• Multi-provider IOC scanning\n"
            "• Batch processing support\n"
            "• Secure API key storage (keyring with JSON fallback)\n"
            "• Real-time results display\n\n"
            "API keys are stored securely and persist between sessions."
        )
        messagebox.showinfo("About", about_text)
    
    def _configure_providers(self):
        # This would show the provider selection dialog
        self.show_providers_info()
    
    def show_providers_info(self):
        """Show a dialog with information about available providers and their status."""
        info_window = tk.Toplevel(self.root)
        info_window.title("Provider Configuration")
        info_window.geometry("800x600")
        info_window.transient(self.root)
        info_window.grab_set()
        
        main_frame = ttk.Frame(info_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        title_label = ttk.Label(main_frame, text="Provider Configuration", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Create a treeview for provider info with checkboxes
        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill="both", expand=True, pady=(0, 20))
        
        columns = ("Provider", "Status", "Hits")
        tree = ttk.Treeview(tree_frame, columns=columns, show="tree headings", selectmode="none")
        
        tree.heading("#0", text="✓", anchor="center")
        tree.column("#0", width=50, minwidth=50, stretch=False)
        
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, anchor="w" if col == "Provider" else "center")
        
        def _resize(event):
            total = event.width
            MIN_WIDTH = sum(tree.column(c, option="minwidth") for c in ("Provider", "Status", "Hits"))
            if total <= MIN_WIDTH:
                return
            widths = (0.4, 0.3, 0.3)  # Provider, Status, Hits
            for col, frac in zip(("Provider", "Status", "Hits"), widths):
                tree.column(col, width=int(total * frac))
        
        tree.bind("<Configure>", _resize)
        
        # Scrollbars for the tree
        tree_scroll_v = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        tree_scroll_h = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=tree_scroll_v.set, xscrollcommand=tree_scroll_h.set)
        
        tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll_v.grid(row=0, column=1, sticky="ns")
        tree_scroll_h.grid(row=1, column=0, sticky="ew")
        
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        
        # Populate tree with provider info
        provider_items = {}
        for provider_id, name, env_var, description, supported_types in self.providers_info:
            api_key = os.getenv(env_var, "")
            status = "Configured" if api_key else "No API Key"
            
            supported_text = ", ".join(supported_types)
            checkbox_text = "☑" if self.provider_config.get(provider_id, False) else "☐"
            
            item_id = tree.insert("", "end", text=checkbox_text, values=(name, status, supported_text))
            provider_items[item_id] = provider_id
        
        def on_tree_click(event):
            item = tree.identify("item", event.x, event.y)
            if item and item in provider_items:
                provider_id = provider_items[item]
                current_state = self.provider_config.get(provider_id, False)
                new_state = not current_state
                self.provider_config[provider_id] = new_state
                
                checkbox_text = "☑" if new_state else "☐"
                tree.item(item, text=checkbox_text)
        
        tree.bind("<Button-1>", on_tree_click)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill="x")
        
        def save_selection():
            try:
                self._update_treeview_columns()  # Update columns when providers change
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update provider columns: {str(e)}")
            finally:
                info_window.destroy()  # Always close dialog
        
        def select_all():
            for item_id, provider_id in provider_items.items():
                self.provider_config[provider_id] = True
                tree.item(item_id, text="☑")
        
        def clear_all():
            for item_id, provider_id in provider_items.items():
                self.provider_config[provider_id] = False
                tree.item(item_id, text="☐")
        
        ttk.Button(buttons_frame, text="Select All", command=select_all).pack(side="left")
        ttk.Button(buttons_frame, text="Clear All", command=clear_all).pack(side="left", padx=(10, 0))
        ttk.Button(buttons_frame, text="Cancel", command=info_window.destroy).pack(side="right")
        ttk.Button(buttons_frame, text="Save", command=save_selection).pack(side="right", padx=(0, 10))
    
    def _browse(self):
        filename = filedialog.askopenfilename(
            title="Select IOC file",
            filetypes=[
                ("CSV files", "*.csv"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.file_var.set(filename)
    
    def _clear(self):
        for item in self.out.get_children():
            self.out.delete(item)
        self.all_results.clear()
    
    def _selected_providers(self) -> list:
        from providers import get_providers, refresh
        # re-evaluate providers in case API keys changed
        refresh()
        all_prov = {p.NAME.lower(): p for p in get_providers()}

        chosen = []
        missing = []
        for prov_id, enabled in self.provider_config.items():
            if enabled:
                if prov_id in all_prov:
                    chosen.append(all_prov[prov_id])
                else:
                    missing.append(prov_id)

        if missing:
            missing_str = ", ".join(missing)
            messagebox.showwarning(
                "Provider unavailable",
                f"The following providers are unavailable (missing API key): {missing_str}"
            )

        return chosen
    
    def _start_single(self, *args):
        ioc_value = self.ioc_var.get().strip()
        if not ioc_value:
            messagebox.showerror("Error", "Please enter an IOC value.")
            return
        
        ioc_type = self.type_var.get()
        
        # Validate the IOC using the new validation function
        is_valid, detected_type, normalized_ioc, error_message = validate_ioc(
            ioc_value, 
            expected_type=None if ioc_type == "auto" else ioc_type
        )
        
        if not is_valid:
            messagebox.showerror("Invalid IOC", error_message)
            return
        
        # Use the validated and normalized values
        ioc_type = detected_type
        ioc_value = normalized_ioc
        
        if not self._prompt_provider_selection_if_needed():
            return
        
        # Update columns before processing
        self._update_treeview_columns()
        self._clear()
        
        selected_providers = self._selected_providers()
        if not selected_providers:
            messagebox.showerror("Error", "No valid providers available for scanning.\n\nPlease go to Tools > Configure Providers to select which providers to use.")
            return
        
        placeholder = self.out.insert('', 'end', values=tuple([ioc_type, ioc_value, "Processing...", ""] + [""] * len(selected_providers)))
        self.root.update()
        
        if self.loop is None:
            messagebox.showerror("Error", "Event loop not initialized")
            return
        
        future = asyncio.run_coroutine_threadsafe(
            scan_ioc(ioc_value, ioc_type, selected_providers), self.loop
        )
        future.add_done_callback(
            functools.partial(self._on_scan_done, ioc_value, ioc_type, placeholder)
        )
    
    def _on_scan_done(self, ioc, ioc_type, placeholder, fut):
        try:
            results = fut.result()
            self.root.after(0, lambda: self.update_table(results, ioc, ioc_type, placeholder))
        except Exception as e:
            error_msg = str(e)
            self.root.after(0, lambda: self.update_table({}, ioc, ioc_type, placeholder, error_msg))
    
    def update_table(self, results, ioc, ioc_type, placeholder=None, error_msg=None):
        # Use cached providers if available (during batch processing), otherwise get fresh providers
        active_providers = getattr(self, '_cached_providers', None) or self._selected_providers()
        
        if error_msg:
            row_values = [ioc_type, ioc, "Error", error_msg] + [""] * len(active_providers)
        else:
            overall_verdict = aggregate_verdict(list(results.values()))
            flagged_providers = [name for name, result in results.items() 
                               if result.status == IOCStatus.MALICIOUS]
            
            provider_values = []
            for provider in active_providers:
                provider_name = provider.NAME.lower()
                if provider_name in results:
                    result = results[provider_name]
                    status_text = _STATUS_MAP.get(result.status, result.status.name) or "Unknown"
                    if result.malicious_engines and result.total_engines:
                        status_text += f" ({result.malicious_engines}/{result.total_engines})"
                    # Show error message for ERROR status
                    if result.status == IOCStatus.ERROR and result.message:
                        status_text += f" - {result.message[:50]}..."
                    provider_values.append(status_text)
                else:
                    provider_values.append("")
            
            row_values = [
                ioc_type,
                ioc,
                _STATUS_MAP.get(overall_verdict, overall_verdict.name) or "Unknown",
                ", ".join(flagged_providers)
            ] + provider_values
        
        if placeholder and self.out.exists(placeholder):
            self.out.item(placeholder, values=tuple(row_values))
        else:
            self.out.insert("", "end", values=tuple(row_values))
        
        self.all_results.append(tuple(row_values))
    
    def _start_batch(self):
        filename = self.file_var.get().strip()
        
        if not filename:
            messagebox.showerror("Error", "Please select a file.")
            return
        
        # Extra safety: make sure providers are chosen *before* we disable UI
        if not self._prompt_provider_selection_if_needed():
            return
        
        if not os.path.exists(filename):
            messagebox.showerror("Error", "File not found.")
            return
        
        # Update columns before processing
        self._update_treeview_columns()
        self._clear()
        self.processed_iocs.clear()  # Clear duplicate tracking
        
        selected_providers = self._selected_providers()
        if not selected_providers:
            messagebox.showerror("Error", "No valid providers available for scanning.\n\nPlease go to Tools > Configure Providers to select which providers to use.")
            self._reset_batch_ui()
            return
        
        # Enable/disable buttons
        self.process_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_label.config(text="Loading IOCs...")
        log.debug("progress_label set to: 'Loading IOCs...'")
        self.root.update()
        
        try:
            from loader import load_iocs
            iocs = load_iocs(Path(filename))
            if not iocs:
                messagebox.showerror("Error", "No IOCs found in file.")
                self._reset_batch_ui()
                return
            
            # Check for provider/IOC type mismatches
            ioc_types_found, unsupported_iocs, provider_type_map = self._analyze_ioc_types(iocs)
            if unsupported_iocs:
                action, export_unsupported = self._show_provider_mismatch_dialog(ioc_types_found, unsupported_iocs, provider_type_map, len(iocs))
                if action == 'cancel':
                    self._reset_batch_ui()
                    return
                # If action == 'proceed', continue with all IOCs
            
            # Start the actual batch processing

            # Insert progress row and track it for later removal
            processing_values = ["Batch", filename, f"Processing {len(iocs)} IOCs...", ""] + [""] * len(selected_providers)
            progress_placeholder = self.out.insert('', 'end', values=tuple(processing_values))
            self.root.update()
            
            # Create index map to preserve original IOC order in CSV
            index_map = {}
            for idx, ioc_data in enumerate(iocs):
                ioc_value = ioc_data.get('value', str(ioc_data))
                is_valid, ioc_type, normalized_ioc, error_message = validate_ioc(ioc_value)
                if is_valid:
                    index_map[normalized_ioc] = idx
            
            async def process_batch() -> None:
                task_id = _safe_task_id()
                log.debug(f"[{task_id}] process_batch() starting with {len(iocs)} IOCs")
                
                valid_count = 0
                invalid_count = 0
                duplicate_count = 0
                csv_results = []
                completed_count = 0
                progress_lock = asyncio.Lock()  # Protect progress updates
                
                # Cache providers to avoid repeated calls during concurrent processing
                self._cached_providers = selected_providers
                log.debug(f"[{task_id}] Cached {len(selected_providers)} providers for batch processing")
                
                async def process_single_ioc(idx: int, ioc_data: dict) -> None:
                    task_id = _safe_task_id()
                    task_name = f"Task-{task_id}"
                    nonlocal valid_count, invalid_count, duplicate_count, completed_count
                    
                    ioc_value = ioc_data.get('value', str(ioc_data))
                    log.debug(f"[{task_name}] process_single_ioc() starting for idx={idx}, ioc='{ioc_value}'")
                    
                    # Check for duplicates
                    if ioc_value in self.processed_iocs:
                        log.debug(f"[{task_name}] idx={idx}, ioc='{ioc_value}' - DUPLICATE detected, skipping")
                        async with progress_lock:
                            duplicate_count += 1
                        return
                    
                    self.processed_iocs.add(ioc_value)
                    log.debug(f"[{task_name}] idx={idx}, ioc='{ioc_value}' - passed duplicate check")
                    
                    # Validate each IOC before processing
                    log.debug(f"[{task_name}] idx={idx}, ioc='{ioc_value}' - starting validation")
                    is_valid, ioc_type, normalized_ioc, error_message = validate_ioc(ioc_value)
                    
                    if is_valid:
                        log.debug(f"[{task_name}] idx={idx}, ioc='{ioc_value}' - VALID (type={ioc_type}, normalized='{normalized_ioc}')")
                        
                        # Check if IOC is supported by any active provider
                        supported_by_any = any(ioc_type in getattr(provider, 'SUPPORTED_TYPES', set()) 
                                             for provider in selected_providers)
                        
                        if not supported_by_any:
                            # Mark as unsupported without scanning
                            async with progress_lock:
                                invalid_count += 1
                                completed_count += 1
                            self._add_unsupported_result(csv_results, ioc_type, normalized_ioc, selected_providers)
                            return
                        
                        try:
                            # Scan IOC with selected providers (no extra timeout - scan_ioc has per-provider timeouts)
                            log.debug(f"[{task_name}] idx={idx}, ioc='{normalized_ioc}' - calling scan_ioc() with {len(selected_providers)} providers")
                            results = await scan_ioc(normalized_ioc, ioc_type, selected_providers)
                            log.debug(f"[{task_name}] idx={idx}, ioc='{normalized_ioc}' - scan_ioc() returned {len(results)} results")
                            
                            async with progress_lock:
                                valid_count += 1
                                completed_count += 1
                            
                            # Determine overall verdict for CSV
                            from ioc_checker import aggregate_verdict
                            from ioc_types import IOCStatus
                            overall_verdict = aggregate_verdict(list(results.values()))
                            flagged_providers = [
                                f"{name} ({res.malicious_engines}/{res.total_engines})"
                                if res.status == IOCStatus.MALICIOUS else name
                                for name, res in results.items() if res.status == IOCStatus.MALICIOUS
                            ]
                            
                            # Map IOCStatus to CSV text values
                            verdict_text_map = {
                                IOCStatus.MALICIOUS: "malicious",
                                IOCStatus.SUCCESS: "clean", 
                                IOCStatus.ERROR: "error",
                                IOCStatus.UNSUPPORTED: "unsupported",
                                IOCStatus.NOT_FOUND: "not_found"
                            }
                            verdict_text = verdict_text_map.get(overall_verdict, "unknown")
                            
                            csv_results.append({
                                'type': ioc_type,
                                'ioc': normalized_ioc,
                                'verdict': verdict_text,
                                'flagged_by': ', '.join(flagged_providers)
                            })
                            log.debug(f"[{task_name}] idx={idx}, ioc='{normalized_ioc}' - verdict='{verdict_text}', flagged_by={flagged_providers}")
                            
                            # Update UI with explicit providers to avoid _selected_providers() call
                            log.debug(f"[{task_name}] idx={idx}, ioc='{normalized_ioc}' - scheduling GUI update")
                            self.root.after(0, lambda r=results, norm_ioc=normalized_ioc, t=ioc_type, providers=selected_providers: 
                                          self.update_table_with_cached_providers(r, norm_ioc, t, providers))
                        
                        except Exception as e:
                            log.debug(f"[{task_name}] idx={idx}, ioc='{normalized_ioc}' - scan_ioc() raised exception: {str(e)}")
                            async with progress_lock:
                                invalid_count += 1
                                completed_count += 1
                            
                            csv_results.append({
                                'type': ioc_type,
                                'ioc': normalized_ioc,
                                'verdict': 'error',
                                'flagged_by': f'Scan Error: {str(e)}'
                            })
                            self.root.after(0, lambda val=normalized_ioc, t=ioc_type, err=str(e): 
                                          self.update_table({}, val, t, None, f"Scan Error: {err}"))
                    else:
                        log.debug(f"[{task_name}] idx={idx}, ioc='{ioc_value}' - INVALID: {error_message}")
                        async with progress_lock:
                            invalid_count += 1
                            completed_count += 1
                        
                        csv_results.append({
                            'type': 'invalid',
                            'ioc': ioc_value,
                            'verdict': 'error',
                            'flagged_by': f'Validation Error: {error_message}'
                        })
                        # Add invalid IOC to results table with error message
                        self.root.after(0, lambda val=ioc_value, err=error_message: 
                                      self.update_table({}, val, "invalid", None, f"Validation Error: {err}"))
                    
                    # ── NEW: show progress as soon as we start working on this IOC ──
                    async with progress_lock:
                        progress_text = f"Processing {idx+1}/{len(iocs)} IOCs…"
                        log.debug(f"[{task_name}] idx={idx} - updating progress_label to: '{progress_text}'")
                        self.root.after(
                            0,
                            lambda idx=idx: self.progress_label.config(
                                text=progress_text
                            ),
                        )
                    
                    log.debug(f"[{task_name}] idx={idx}, ioc='{ioc_value}' - process_single_ioc() completed")
                
                try:
                    # Create all tasks immediately - no semaphore to bottleneck them
                    # Use create_task to start them running immediately 
                    log.debug(f"[{task_id}] Creating {len(iocs)} tasks for parallel processing")
                    tasks = []
                    for i, ioc_data in enumerate(iocs):
                        task = asyncio.create_task(process_single_ioc(i, ioc_data))
                        tasks.append(task)
                        log.debug(f"[{task_id}] Created task for IOC idx={i}: {task}")
                    
                    # Apply concurrency limit AFTER tasks are created and running
                    semaphore = asyncio.Semaphore(6)
                    log.debug(f"[{task_id}] Created semaphore with limit=6")
                    
                    async def run_with_semaphore(task):
                        task_id = _safe_task_id()
                        log.debug(f"[{task_id}] Acquiring semaphore for task: {task}")
                        async with semaphore:
                            log.debug(f"[{task_id}] Semaphore acquired, running task: {task}")
                            result = await task
                            log.debug(f"[{task_id}] Task completed, releasing semaphore: {task}")
                            return result
                    
                    log.debug(f"[{task_id}] Starting asyncio.gather() with semaphore-wrapped tasks")
                    # Wait for all tasks with bounded concurrency
                    await asyncio.gather(*[run_with_semaphore(task) for task in tasks])
                    log.debug(f"[{task_id}] All tasks completed successfully")
                    
                    # Remove progress placeholder from GUI
                    try:
                        self.out.delete(progress_placeholder)
                    except tk.TclError:
                        pass  # Item may have been cleared already
                    
                    # Sort CSV results by original input order
                    csv_results.sort(key=lambda r: index_map.get(r['ioc'], 999999))
                    
                    # Export results to CSV
                    csv_path = self._export_batch_results(filename, csv_results)
                    
                    summary_message = f"Batch processing complete!\n\nValid IOCs processed: {valid_count}\nInvalid IOCs skipped: {invalid_count}"
                    if duplicate_count > 0:
                        summary_message += f"\nDuplicate IOCs skipped: {duplicate_count}"
                    summary_message += f"\nTotal: {len(iocs)}"
                    if csv_path:
                        summary_message += f"\n\nResults exported to: {csv_path}"
                    
                    log.debug(f"[{task_id}] process_batch() completed successfully, scheduling completion callback")
                    self.root.after(0, lambda: self._batch_complete(summary_message))
                    
                except asyncio.CancelledError:
                    log.debug(f"[{task_id}] process_batch() cancelled")
                    
                    # Remove progress placeholder from GUI
                    try:
                        self.out.delete(progress_placeholder)
                    except tk.TclError:
                        pass  # Item may have been cleared already
                    
                    # Export partial results if cancelled
                    if csv_results:
                        # Sort CSV results by original input order  
                        csv_results.sort(key=lambda r: index_map.get(r['ioc'], 999999))
                        
                        csv_path = self._export_batch_results(filename, csv_results, cancelled=True)
                        cancel_msg = f"Batch processing cancelled.\n\nProcessed {len(csv_results)} IOCs before cancellation."
                        if csv_path:
                            cancel_msg += f"\n\nPartial results exported to: {csv_path}"
                        self.root.after(0, lambda: self._batch_cancelled(cancel_msg))
                    else:
                        self.root.after(0, lambda: self._batch_cancelled("Batch processing cancelled."))
                    raise
                finally:
                    # Clear cached providers
                    self._cached_providers = None
                    log.debug(f"[{task_id}] process_batch() cleanup completed")
            
            if self.loop is None:
                messagebox.showerror("Error", "Event loop not initialized")
                self._reset_batch_ui()
                return
            
            self.batch_task = asyncio.run_coroutine_threadsafe(process_batch(), self.loop)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load IOCs: {str(e)}")
            self._reset_batch_ui()
    
    def _stop_batch(self):
        """Stop the current batch processing."""
        if self.batch_task and not self.batch_task.done():
            self.batch_task.cancel()
            log.debug("progress_label set to: 'Cancelling...'")
            self.progress_label.config(text="Cancelling...")
    
    def _batch_complete(self, message):
        """Handle batch completion."""
        messagebox.showinfo("Batch Complete", message)
        self._reset_batch_ui()
    
    def _batch_cancelled(self, message):
        """Handle batch cancellation."""
        messagebox.showwarning("Batch Cancelled", message)
        self._reset_batch_ui()
    
    def _reset_batch_ui(self):
        """Reset UI state after batch completion or cancellation."""
        self.process_button.config(state="normal")
        self.stop_button.config(state="disabled")
        log.debug("progress_label set to: 'Ready'")
        self.progress_label.config(text="Ready")
        self.batch_task = None
    
    def _analyze_ioc_types(self, iocs):
        """Analyze IOC types in the batch and detect type mismatches with selected providers.
        
        Returns:
            tuple: (ioc_types_found, unsupported_iocs, provider_type_map)
        """
        from ioc_types import detect_ioc_type, validate_ioc
        
        ioc_types_found = set()
        unsupported_iocs = []
        
        # Get selected providers and their supported types
        selected_providers = self._selected_providers()
        provider_type_map = {}
        for provider in selected_providers:
            # Find provider info from providers_info
            for pid, name, env_var, desc, supported_types in self.providers_info:
                if pid == provider.NAME.lower():
                    provider_type_map[provider.NAME] = set(supported_types)
                    break
            else:
                # Fallback: use provider.SUPPORTED_TYPES if available
                if hasattr(provider, 'SUPPORTED_TYPES'):
                    provider_type_map[provider.NAME] = set(provider.SUPPORTED_TYPES)
        
        # Analyze each IOC
        for ioc_data in iocs:
            ioc_value = ioc_data.get('value', str(ioc_data))
            
            # Validate and detect type
            is_valid, ioc_type, normalized_ioc, error_message = validate_ioc(ioc_value)
            
            if is_valid:
                ioc_types_found.add(ioc_type)
                
                # Check if any selected provider supports this IOC type
                supported_by_any = False
                for provider_name, supported_types in provider_type_map.items():
                    if ioc_type in supported_types:
                        supported_by_any = True
                        break
                
                if not supported_by_any:
                    unsupported_iocs.append({
                        'value': ioc_value,
                        'type': ioc_type,
                        'normalized': normalized_ioc
                    })
        
        return ioc_types_found, unsupported_iocs, provider_type_map

    def _show_provider_mismatch_dialog(self, ioc_types_found, unsupported_iocs, provider_type_map, total_iocs):
        """Show dialog when there are IOC/provider type mismatches."""
        dialog_result = {'action': 'cancel', 'export_unsupported': False}
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Provider/IOC Type Mismatch")
        dialog.geometry("600x400")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        unsupported_text = f"Unsupported IOCs: {len(unsupported_iocs)} out of {total_iocs}"

        main_frame = ttk.Frame(dialog)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="Provider Type Mismatch Detected", 
                               font=("Arial", 12, "bold"))
        title_label.pack(pady=(0, 15))
        
        # Description
        desc_text = ("The selected providers don't support all IOC types found in your file.\n"
                    "Some IOCs will be marked as 'unsupported' and won't be scanned.")
        ttk.Label(main_frame, text=desc_text, justify="center", wraplength=550).pack(pady=(0, 15))
        
        # Summary frame
        summary_frame = ttk.LabelFrame(main_frame, text="Summary", padding=10)
        summary_frame.pack(fill="x", pady=(0, 15))
        
        # IOC types found
        types_text = f"IOC types in file: {', '.join(sorted(ioc_types_found))}"
        ttk.Label(summary_frame, text=types_text).pack(anchor="w")
        
        # Selected providers and their types
        provider_text = "Selected providers and supported types:"
        ttk.Label(summary_frame, text=provider_text, font=("Arial", 9, "bold")).pack(anchor="w", pady=(10, 5))
        
        for provider_name, supported_types in provider_type_map.items():
            types_str = ', '.join(sorted(supported_types))
            ttk.Label(summary_frame, text=f"  • {provider_name}: {types_str}").pack(anchor="w")
        
        # Unsupported IOCs
        if unsupported_iocs:
            unsupported_text = f"Unsupported IOCs: {len(unsupported_iocs)} out of {total_iocs}"
            ttk.Label(summary_frame, text=unsupported_text, foreground="red").pack(anchor="w", pady=(5, 0))
        
        # Unsupported IOCs details (if any)
        if unsupported_iocs:
            details_frame = ttk.LabelFrame(main_frame, text="Unsupported IOCs (first 10 shown)", padding=10)
            details_frame.pack(fill="both", expand=True, pady=(0, 15))
            
            # Create treeview for unsupported IOCs
            columns = ("Type", "IOC")
            tree = ttk.Treeview(details_frame, columns=columns, show="headings", height=6)
            tree.heading("Type", text="Type")
            tree.heading("IOC", text="IOC")
            tree.column("Type", width=80, anchor="center")
            tree.column("IOC", width=400, anchor="w")
            
            # Add first 10 unsupported IOCs
            for ioc in unsupported_iocs[:10]:
                tree.insert('', 'end', values=(ioc['type'], ioc['value']))
            
            if len(unsupported_iocs) > 10:
                tree.insert('', 'end', values=("...", f"...and {len(unsupported_iocs) - 10} more"))
            
            # Scrollbar for treeview
            scrollbar = ttk.Scrollbar(details_frame, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=scrollbar.set)
            
            tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding=10)
        options_frame.pack(fill="x", pady=(0, 15))
        
        export_var = tk.BooleanVar(value=True)
        export_cb = ttk.Checkbutton(options_frame, 
                                   text="Export unsupported IOCs to separate CSV file",
                                   variable=export_var)
        export_cb.pack(anchor="w")
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x")
        
        def on_cancel():
            dialog_result['action'] = 'cancel'
            dialog.destroy()
        
        def on_skip():
            dialog_result['action'] = 'proceed'
            dialog_result['export_unsupported'] = export_var.get()
            dialog.destroy()
        
        def on_continue():
            dialog_result['action'] = 'proceed'
            dialog.destroy()
        
        # Buttons
        ttk.Button(button_frame, text="Cancel", command=on_cancel).pack(side="right", padx=(5, 0))
        ttk.Button(button_frame, text="Mark Unsupported", command=on_skip).pack(side="right", padx=(5, 0))
        ttk.Button(button_frame, text="Continue Anyway", command=on_continue).pack(side="right", padx=(5, 0))
        ttk.Button(button_frame, text="Go Back to Select Providers", command=on_cancel).pack(side="left")
        
        # Wait for dialog to close
        dialog.wait_window()
        
        return dialog_result['action'], dialog_result['export_unsupported']

    def _add_unsupported_result(self, csv_results, ioc_type, ioc_value, active_providers):
        """Add an unsupported IOC to results without scanning."""
        provider_names = ', '.join(p.NAME for p in active_providers)
        csv_results.append({
            'type': ioc_type,
            'ioc': ioc_value,
            'verdict': 'unsupported',
            'flagged_by': f'unsupported by {provider_names}'
        })
        self.root.after(0, lambda: self.update_table({}, ioc_value, ioc_type, None, f"Unsupported by {provider_names}"))
    
    def _export_unsupported_iocs(self, filename, unsupported_iocs):
        """Export unsupported IOCs to a separate CSV file."""
        try:
            from pathlib import Path
            from datetime import datetime
            
            input_path = Path(filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"unsupported_iocs_{timestamp}.csv"
            output_path = input_path.parent / output_filename
            
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['type', 'ioc', 'reason']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for ioc in unsupported_iocs:
                    writer.writerow({
                        'type': ioc['type'],
                        'ioc': ioc['value'],
                        'reason': f"No selected provider supports {ioc['type']} IOCs"
                    })
            
            return str(output_path)
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export unsupported IOCs: {str(e)}")
            return None

    def _export_batch_results(self, input_filename, results, cancelled=False):
        """Export batch results to CSV file."""
        try:
            
            # Generate output filename
            input_path = Path(input_filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            status_suffix = "_cancelled" if cancelled else ""
            output_filename = f"batch_results_{timestamp}{status_suffix}.csv"
            output_path = input_path.parent / output_filename
            
            # Write CSV
            # Filter out progress rows that shouldn't be exported
            filtered_results = [r for r in results 
                               if r.get('type') != 'Batch' and not input_filename.endswith(r.get('ioc', ''))]
            
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['type', 'ioc', 'verdict', 'flagged_by']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(filtered_results)
            
            return str(output_path)
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Export Error", f"Failed to export results: {str(e)}"))
            return None
    
    def _configure_api_keys(self):
        config_win = tk.Toplevel(self.root)
        config_win.title("API Key Configuration")
        config_win.geometry("650x400")
        config_win.transient(self.root)
        config_win.grab_set()
        
        main_frame = ttk.Frame(config_win)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(main_frame, text="Configure API Keys", font=("Arial", 14, "bold")).pack(pady=(0, 20))
        
        entries = {}
        eye_buttons = {}
        status_labels = {}  # Status indicators for each key
        original_values = {}  # Track original values to detect intentional clearing
        
        for provider_id, name, env_var, _, _ in self.providers_info:
            frame = ttk.Frame(main_frame)
            frame.pack(fill="x", pady=5)
            
            # Provider label
            ttk.Label(frame, text=f"{name} ({env_var}):", width=25).pack(side="left")
            
            # Entry field for API key
            entry = ttk.Entry(frame, show="*", width=40)
            entry.pack(side="left", fill="x", expand=True, padx=(10, 5))
            
            # Eye toggle button
            eye_button = ttk.Button(frame, text="👁", width=3)
            eye_button.pack(side="right", padx=(0, 5))
            
            # Status label (initially hidden)
            status_label = ttk.Label(frame, text="", foreground="green", width=8)
            status_label.pack(side="right")
            
            # Load saved key (prefer stored key over environment variable)
            saved_key = load_key(env_var) or ""
            entry.insert(0, saved_key)
            
            # Show initial status if key exists
            if saved_key:
                status_label.config(text="✓ Saved", foreground="green")
            
            # Store references and track original values
            entries[env_var] = entry
            eye_buttons[env_var] = eye_button
            status_labels[env_var] = status_label
            original_values[env_var] = saved_key
            
            # Create toggle function for this specific entry
            def create_toggle_function(entry_widget, button_widget):
                def toggle_visibility():
                    if entry_widget['show'] == '*':
                        entry_widget.config(show='')
                        button_widget.config(text="🙈")  # hide icon
                    else:
                        entry_widget.config(show='*')
                        button_widget.config(text="👁")   # show icon
                return toggle_visibility
            
            # Bind the toggle function to the button
            eye_button.config(command=create_toggle_function(entry, eye_button))
            
            # Add tooltip to the eye button
            ToolTip(eye_button, "Click to show/hide API key")
        
        # Add instruction text
        instruction_frame = ttk.Frame(main_frame)
        instruction_frame.pack(fill="x", pady=(10, 0))
        instruction_text = ttk.Label(
            instruction_frame, 
            text="💡 Click the eye button (👁) to show/hide API keys • Leave blank to remove a key",
            font=("Arial", 9),
            foreground="gray"
        )
        instruction_text.pack()
        
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill="x", pady=(20, 0))
        
        def save_keys():
            from providers import refresh
            import logging
            
            saved_count = 0
            cleared_count = 0
            errors = []
            
            # Update status labels in real-time
            for var, entry in entries.items():
                current_val = entry.get().strip()
                original_val = original_values[var]
                status_label = status_labels[var]
                
                try:
                    if current_val:
                        # Non-empty value: always save
                        save_key(var, current_val)
                        os.environ[var] = current_val
                        saved_count += 1
                        status_label.config(text="✓ Saved", foreground="green")
                        logging.info(f"Saved API key for {var}")
                    elif original_val and not current_val:
                        # Had a value before, now empty: user intentionally cleared it
                        save_key(var, "")
                        os.environ.pop(var, None)
                        cleared_count += 1
                        status_label.config(text="✓ Cleared", foreground="orange")
                        logging.info(f"Cleared API key for {var}")
                    else:
                        # No change needed
                        if not current_val and not original_val:
                            status_label.config(text="", foreground="gray")
                        else:
                            status_label.config(text="✓ Saved", foreground="green")
                except Exception as e:
                    errors.append(f"{var}: {str(e)}")
                    status_label.config(text="✗ Error", foreground="red")
                    logging.error(f"Failed to save API key for {var}: {e}")
            
            # Refresh providers after API key changes
            refresh()
            
            # Show results to user
            if errors:
                error_msg = f"Failed to save some API keys:\n\n" + "\n".join(errors)
                error_msg += f"\n\nPlease check file permissions for the configuration directory."
                messagebox.showerror("Save Failed", error_msg)
                return  # Don't close dialog on error
            
            # Show detailed success message
            status_parts = []
            if saved_count > 0:
                status_parts.append(f"{saved_count} key(s) saved")
            if cleared_count > 0:
                status_parts.append(f"{cleared_count} key(s) cleared")
            
            status_msg = "API keys updated: " + ", ".join(status_parts) if status_parts else "No changes made"
            status_msg += ". Keys will be remembered for future sessions."
            
            messagebox.showinfo("Success", status_msg)
            
            # Auto-close after a brief delay
            config_win.after(1500, config_win.destroy)
        
        ttk.Button(buttons_frame, text="Cancel", command=config_win.destroy).pack(side="right", padx=(5, 0))
        ttk.Button(buttons_frame, text="Save", command=save_keys).pack(side="right")
    
    def _prompt_provider_selection_if_needed(self):
        selected_providers = self._selected_providers()
        if not selected_providers:
            messagebox.showwarning("No Providers Selected", 
                                 "Please configure at least one provider in Tools > Configure Providers.")
            self._configure_providers()
            return len(self._selected_providers()) > 0
        return True
    
    def _refresh_display(self):
        for item in self.out.get_children():
            self.out.delete(item)
        
        for result in self.all_results:
            should_display = True
            if self.show_threats_var.get():
                status_text = str(result[2]).lower() if len(result) >= 3 else ""
                should_display = "malicious" in status_text or "error" in status_text
            
            if should_display:
                self.out.insert("", "end", values=result)
    
    def _poll_queue(self):
        try:
            while True:
                line = self.q.get_nowait()
                if line:
                    try:
                        log.debug(f"progress_label set via queue to: '{str(line)}'")
                        self.progress_label.config(text=str(line))
                    except Exception:
                        pass
        except queue.Empty:
            pass
        except Exception as e:
            try:
                error_text = f"Error: {str(e)}"
                log.debug(f"progress_label set to error: '{error_text}'")
                self.progress_label.config(text=error_text)
            except Exception:
                pass
        finally:
            self.root.after(100, self._poll_queue)
    
    def update_table_with_cached_providers(self, results, ioc, ioc_type, providers, placeholder=None, error_msg=None):
        """Update table with explicitly provided providers to avoid calling _selected_providers()."""
        task_id = _safe_task_id()
        log.debug(f"[{task_id}] update_table_with_cached_providers() called for ioc='{ioc}', type='{ioc_type}', error_msg='{error_msg}'")
        
        if error_msg:
            row_values = [ioc_type, ioc, "Error", error_msg] + [""] * len(providers)
            log.debug(f"[{task_id}] Creating error row for ioc='{ioc}': {row_values}")
        else:
            overall_verdict = aggregate_verdict(list(results.values()))
            flagged_providers = [name for name, result in results.items() 
                               if result.status == IOCStatus.MALICIOUS]
            
            provider_values = []
            for provider in providers:
                provider_name = provider.NAME.lower()
                if provider_name in results:
                    result = results[provider_name]
                    status_text = _STATUS_MAP.get(result.status, result.status.name) or "Unknown"
                    if result.malicious_engines and result.total_engines:
                        status_text += f" ({result.malicious_engines}/{result.total_engines})"
                    # Show error message for ERROR status
                    if result.status == IOCStatus.ERROR and result.message:
                        status_text += f" - {result.message[:50]}..."
                    provider_values.append(status_text)
                else:
                    provider_values.append("")
            
            row_values = [
                ioc_type,
                ioc,
                _STATUS_MAP.get(overall_verdict, overall_verdict.name) or "Unknown",
                ", ".join(flagged_providers)
            ] + provider_values
            log.debug(f"[{task_id}] Creating result row for ioc='{ioc}': verdict={overall_verdict.name}, flagged_by={flagged_providers}")
        
        if placeholder and self.out.exists(placeholder):
            log.debug(f"[{task_id}] Updating existing placeholder row for ioc='{ioc}'")
            self.out.item(placeholder, values=tuple(row_values))
        else:
            log.debug(f"[{task_id}] Inserting new row for ioc='{ioc}'")
            self.out.insert("", "end", values=tuple(row_values))
        
        self.all_results.append(tuple(row_values))
        log.debug(f"[{task_id}] update_table_with_cached_providers() completed for ioc='{ioc}'")

    def run(self):
        self.root.mainloop()


def run_gui():
    """Run the IOC Checker GUI."""
    global _GUI_LOOP_RUNNING, _GUI_LOOP, _GUI_LOOP_THREAD
    
    # Prevent duplicate loops/threads
    if _GUI_LOOP_RUNNING:
        print("GUI loop already running")
        return
    
    # Initialize the background event loop and thread
    _GUI_LOOP = asyncio.new_event_loop()
    _GUI_LOOP_THREAD = threading.Thread(target=_GUI_LOOP.run_forever, daemon=True)
    _GUI_LOOP_THREAD.start()
    _GUI_LOOP_RUNNING = True
    
    # Create and run the GUI
    gui = IOCCheckerGUI()
    gui.run()


if __name__ == "__main__":
    run_gui()
