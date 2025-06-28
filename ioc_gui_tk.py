#!/usr/bin/env python3
"""
Simplified Tkinter GUI for IOC checking using the unified result format.
"""
from __future__ import annotations

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

from ioc_types import IOCStatus, IOCResult, detect_ioc_type, validate_ioc
from providers import get_providers
from ioc_checker import aggregate_verdict, scan_ioc
from async_cache import _close_all_clients
from api_key_store import save as save_key, load as load_key

_STATUS_MAP = {
    IOCStatus.SUCCESS: "✔ Clean",
    IOCStatus.MALICIOUS: "✖ Malicious", 
    IOCStatus.ERROR: "⚠ Error",
    IOCStatus.UNSUPPORTED: "— N/A",
}

# Set UTF-8 encoding for console output when available
try:
    import locale
    locale.setlocale(locale.LC_ALL, '')
except (ImportError, locale.Error):
    pass

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("gui")

AVAILABLE_PROVIDERS = {
    'virustotal': 'VirusTotal',
    'abuseipdb': 'AbuseIPDB', 
    'otx': 'AlienVault OTX',
    'threatfox': 'ThreatFox',
    'greynoise': 'GreyNoise',
}

_LOOP = asyncio.new_event_loop()
threading.Thread(target=_LOOP.run_forever, daemon=True).start()

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
        self.root = tk.Tk()
        self.root.title("IOC Checker - Enhanced GUI")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        self.processing = False
        self.all_results = []
        self.q = queue.Queue()
        
        self.provider_config = {
            'virustotal': False,
            'abuseipdb': False,
            'otx': False,
            'threatfox': False,
            'greynoise': False,
        }
        
        self.providers_info = [
            ("virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", "Universal threat intelligence platform", ["ip", "domain", "url", "hash"]),
            ("abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", "IP reputation and abuse reports", ["ip"]),
            ("otx", "AlienVault OTX", "OTX_API_KEY", "Open threat exchange platform", ["ip", "domain", "url", "hash"]),
            ("threatfox", "ThreatFox", "THREATFOX_API_KEY", "Malware IOCs from abuse.ch", ["ip", "domain", "url", "hash"]),
            ("greynoise", "GreyNoise", "GREYNOISE_API_KEY", "Internet background noise analysis", ["ip"]),
        ]
        
        self.show_threats_var = tk.BooleanVar(value=False)
        self.file_var = tk.StringVar()
        self.dark_mode = tk.BooleanVar(value=False)
        
        # Load saved API keys before any provider discovery
        _API_VARS = ("VIRUSTOTAL_API_KEY", "OTX_API_KEY",
                     "ABUSEIPDB_API_KEY", "GREYNOISE_API_KEY", "THREATFOX_API_KEY")
        
        for var in _API_VARS:
            val = load_key(var)
            if val:
                os.environ[var] = val
        
        self._create_menu()
        self._build_ui()
        self._poll_queue()
        
        # Set up graceful shutdown
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
    

    def _on_close(self) -> None:
        """Gracefully stop the background event loop and close the GUI."""
        _LOOP.call_soon_threadsafe(_LOOP.stop)
        _close_all_clients()
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
        ttk.Button(file_frame, text="Process", command=self._start_batch).grid(row=0, column=3)
        
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
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
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
            messagebox.showerror("Error", "No valid providers available for scanning.")
            return
        
        placeholder = self.out.insert('', 'end', values=tuple([ioc_type, ioc_value, "Processing...", ""] + [""] * len(selected_providers)))
        self.root.update()
        
        future = asyncio.run_coroutine_threadsafe(
            scan_ioc(ioc_value, ioc_type, selected_providers), _LOOP
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
        active_providers = self._selected_providers()
        
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
        
        if not os.path.exists(filename):
            messagebox.showerror("Error", "File not found.")
            return
        
        if not self._prompt_provider_selection_if_needed():
            return
        
        # Update columns before processing
        self._update_treeview_columns()
        self._clear()
        
        selected_providers = self._selected_providers()
        if not selected_providers:
            messagebox.showerror("Error", "No valid providers available for scanning.")
            return
        
        try:
            from loader import load_iocs
            iocs = load_iocs(Path(filename))
            if not iocs:
                messagebox.showerror("Error", "No IOCs found in file.")
                return
            
            processing_values = ["Batch", filename, f"Processing {len(iocs)} IOCs...", ""] + [""] * len(selected_providers)
            self.out.insert('', 'end', values=tuple(processing_values))
            self.root.update()
            
            async def process_batch():
                valid_count = 0
                invalid_count = 0
                
                for ioc_data in iocs:
                    ioc_value = ioc_data.get('value', str(ioc_data))
                    
                    # Validate each IOC before processing
                    is_valid, ioc_type, normalized_ioc, error_message = validate_ioc(ioc_value)
                    
                    if is_valid:
                        valid_count += 1
                        results = await scan_ioc(normalized_ioc, ioc_type, selected_providers)
                        self.root.after(0, lambda r=results, i=normalized_ioc, t=ioc_type: 
                                      self.update_table(r, i, t))
                    else:
                        invalid_count += 1
                        # Add invalid IOC to results table with error message
                        self.root.after(0, lambda val=ioc_value, err=error_message: 
                                      self.update_table({}, val, "invalid", None, f"Validation Error: {err}"))
                
                summary_message = f"Batch processing complete!\n\nValid IOCs processed: {valid_count}\nInvalid IOCs skipped: {invalid_count}\nTotal: {len(iocs)}"
                if invalid_count > 0:
                    summary_message += f"\n\nInvalid IOCs are shown in the results table with error details."
                
                self.root.after(0, lambda: messagebox.showinfo("Batch Complete", summary_message))
            
            future = asyncio.run_coroutine_threadsafe(process_batch(), _LOOP)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load IOCs: {str(e)}")
    
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
            eye_button.pack(side="right")
            
            # Load saved key or fall back to environment variable
            saved_key = load_key(env_var) or os.getenv(env_var, "")
            entry.insert(0, saved_key)
            
            # Store references
            entries[env_var] = entry
            eye_buttons[env_var] = eye_button
            
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
            for var, entry in entries.items():
                val = entry.get().strip()
                if val:
                    save_key(var, val)
                    os.environ[var] = val
                else:                    # allow clearing
                    save_key(var, "")
                    os.environ.pop(var, None)
            
            # Refresh providers after API key changes
            refresh()
            messagebox.showinfo("Success", "API keys saved securely and will be remembered for future sessions.")
            config_win.destroy()
        
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
                        self.progress_label.config(text=str(line))
                    except Exception:
                        pass
        except queue.Empty:
            pass
        except Exception as e:
            try:
                self.progress_label.config(text=f"Error: {str(e)}")
            except Exception:
                pass
        finally:
            self.root.after(100, self._poll_queue)
    
    def run(self):
        self.root.mainloop()


def run_gui():
    app = IOCCheckerGUI()
    app.run()


if __name__ == "__main__":
    run_gui()
