#!/usr/bin/env python3
"""
Simplified Tkinter GUI for IOC checking using the unified result format.
"""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import asyncio
import logging
import os
import sys
import threading
import subprocess
import queue
from pathlib import Path
import functools

from ioc_types import IOCStatus, IOCResult, detect_ioc_type
from providers import get_providers
from ioc_checker import aggregate_verdict, scan_ioc
from async_cache import _close_all_clients

_STATUS_MAP = {
    IOCStatus.SUCCESS: "✔ Clean",
    IOCStatus.MALICIOUS: "✖ Malicious", 
    IOCStatus.ERROR: "⚠ Error",
    IOCStatus.UNSUPPORTED: "— N/A",
}

try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except AttributeError:
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
        
        self.provider_columns = ["virustotal", "abuseipdb", "otx", "threatfox", "greynoise"]
        self.columns = ["Type", "IOC", "Verdict", "Flagged By"] + [p.title() for p in self.provider_columns]
        
        self.out = ttk.Treeview(results_frame, columns=self.columns, show="headings", height=15)
        
        for col in self.columns:
            self.out.heading(col, text=col)
            self.out.column(col, width=100, minwidth=80)
        
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
    
    def _show_about(self):
        messagebox.showinfo("About", "IOC Checker GUI\nVersion 2.0\nUnified threat intelligence checking")
    
    def _configure_providers(self):
        self.show_providers_info()
    
    def show_providers_info(self):
        config_win = tk.Toplevel(self.root)
        config_win.title("Provider Configuration")
        config_win.geometry("800x600")
        config_win.transient(self.root)
        config_win.grab_set()
        
        main_frame = ttk.Frame(config_win)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        main_frame.grid_rowconfigure(3, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        
        title_label = ttk.Label(main_frame, text="Select Threat Intelligence Providers", 
                               font=("Arial", 14, "bold"))
        title_label.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        
        desc_label = ttk.Label(main_frame, 
                              text="Choose which providers to use for IOC analysis. Providers require valid API keys.",
                              font=("Arial", 10))
        desc_label.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        
        provider_frame = ttk.LabelFrame(main_frame, text="Available Providers", padding=10)
        provider_frame.grid(row=2, column=0, sticky="nsew", pady=(0, 15))
        
        self.provider_vars = {}
        
        for i, (provider_id, name, env_var, description, supported_types) in enumerate(self.providers_info):
            var = tk.BooleanVar(value=self.provider_config.get(provider_id, False))
            self.provider_vars[provider_id] = var
            
            api_key_available = bool(os.getenv(env_var, "").strip()) if env_var else True
            status_text = " ✓" if api_key_available else " ✗"
            
            frame = ttk.Frame(provider_frame)
            frame.pack(fill="x", pady=5, padx=5)
            
            checkbox = ttk.Checkbutton(frame, variable=var)
            checkbox.pack(side="left", padx=(0, 10))
            
            info_frame = ttk.Frame(frame)
            info_frame.pack(side="left", fill="x", expand=True)
            
            name_label = ttk.Label(info_frame, text=f"{name}{status_text}", font=("Arial", 11, "bold"))
            name_label.pack(anchor="w")
            
            desc_label = ttk.Label(info_frame, text=description, font=("Arial", 9), foreground="gray")
            desc_label.pack(anchor="w")
            
            types_label = ttk.Label(info_frame, text=f"Supports: {', '.join(supported_types).upper()}", 
                                   font=("Arial", 8), foreground="blue")
            types_label.pack(anchor="w")
            
            if env_var and not api_key_available:
                checkbox.config(state="disabled")
                key_label = ttk.Label(info_frame, text=f"API Key Required: {env_var}", 
                                     font=("Arial", 8), foreground="red")
                key_label.pack(anchor="w")
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=3, column=0, sticky="ew")
        
        def save_selection():
            for provider_id, var in self.provider_vars.items():
                self.provider_config[provider_id] = var.get()
            config_win.destroy()
        
        def select_all():
            for provider_id, var in self.provider_vars.items():
                provider_info = next((p for p in self.providers_info if p[0] == provider_id), None)
                if provider_info:
                    env_var = provider_info[2]
                    if env_var is None or os.getenv(env_var, "").strip():
                        var.set(True)
        
        def clear_all():
            for var in self.provider_vars.values():
                var.set(False)
        
        ttk.Button(btn_frame, text="Select All", command=select_all).pack(side="left", padx=(0, 10))
        ttk.Button(btn_frame, text="Clear All", command=clear_all).pack(side="left", padx=(0, 10))
        ttk.Button(btn_frame, text="Cancel", command=config_win.destroy).pack(side="right", padx=(10, 0))
        ttk.Button(btn_frame, text="Save", command=save_selection).pack(side="right")
    
    def _browse(self):
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
        self.out.delete(*self.out.get_children())
        self.all_results = []
    
    def _selected_providers(self):
        providers = get_providers()
        return [p for p in providers if self.provider_config.get(p.NAME.lower(), False)]
    
    def _start_single(self, *args):
        ioc_value = self.ioc_var.get().strip()
        if not ioc_value:
            messagebox.showerror("Error", "Please enter an IOC value.")
            return
        
        ioc_type = self.type_var.get()
        if ioc_type == "auto":
            detected_type, normalized_ioc = detect_ioc_type(ioc_value)
            if detected_type == "unknown":
                messagebox.showerror("Error", f"Could not auto-detect IOC type for: {ioc_value}")
                return
            ioc_type = detected_type
            ioc_value = normalized_ioc
        
        if not self._prompt_provider_selection_if_needed():
            return
        
        self._clear()
        
        placeholder = self.out.insert('', 'end', values=(ioc_type, ioc_value, "Processing...", ""))
        self.root.update()
        
        future = asyncio.run_coroutine_threadsafe(
            scan_ioc(ioc_value, ioc_type), _LOOP
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
        if error_msg:
            row_values = (ioc_type, ioc, "Error", error_msg) + tuple("" for _ in self.provider_columns)
        else:
            overall_verdict = aggregate_verdict(list(results.values()))
            flagged_providers = [name for name, result in results.items() 
                               if result.status == IOCStatus.MALICIOUS]
            
            provider_values = []
            for col in self.provider_columns:
                if col in results:
                    result = results[col]
                    status_text = _STATUS_MAP.get(result.status, result.status.name)
                    if result.malicious_engines and result.total_engines:
                        status_text += f" ({result.malicious_engines}/{result.total_engines})"
                    provider_values.append(status_text)
                else:
                    provider_values.append("")
            
            row_values = (
                ioc_type,
                ioc,
                _STATUS_MAP.get(overall_verdict, overall_verdict.name),
                ", ".join(flagged_providers)
            ) + tuple(provider_values)
        
        if placeholder and self.out.exists(placeholder):
            self.out.item(placeholder, values=row_values)
        else:
            self.out.insert("", "end", values=row_values)
        
        self.all_results.append(row_values)
    
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
        
        self._clear()
        
        try:
            from loader import load_iocs
            iocs = load_iocs(Path(filename))
            if not iocs:
                messagebox.showerror("Error", "No IOCs found in file.")
                return
            
            self.out.insert('', 'end', values=("Batch", filename, f"Processing {len(iocs)} IOCs...", ""))
            self.root.update()
            
            async def process_batch():
                for ioc_data in iocs:
                    ioc_value = ioc_data.get('value', str(ioc_data))
                    ioc_type, normalized_ioc = detect_ioc_type(ioc_value)
                    
                    if ioc_type != "unknown":
                        results = await scan_ioc(normalized_ioc, ioc_type)
                        self.root.after(0, lambda r=results, i=normalized_ioc, t=ioc_type: 
                                      self.update_table(r, i, t))
                
                self.root.after(0, lambda: messagebox.showinfo("Batch Complete", 
                                                              f"Successfully processed {len(iocs)} IOCs."))
            
            future = asyncio.run_coroutine_threadsafe(process_batch(), _LOOP)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load IOCs: {str(e)}")
    
    def _configure_api_keys(self):
        config_win = tk.Toplevel(self.root)
        config_win.title("API Key Configuration")
        config_win.geometry("600x400")
        config_win.transient(self.root)
        config_win.grab_set()
        
        main_frame = ttk.Frame(config_win)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(main_frame, text="Configure API Keys", font=("Arial", 14, "bold")).pack(pady=(0, 20))
        
        entries = {}
        for provider_id, name, env_var, _, _ in self.providers_info:
            frame = ttk.Frame(main_frame)
            frame.pack(fill="x", pady=5)
            
            ttk.Label(frame, text=f"{name} ({env_var}):", width=25).pack(side="left")
            entry = ttk.Entry(frame, show="*", width=40)
            entry.pack(side="left", fill="x", expand=True, padx=(10, 0))
            entry.insert(0, os.getenv(env_var, ""))
            entries[env_var] = entry
        
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill="x", pady=(20, 0))
        
        def save_keys():
            for env_var, entry in entries.items():
                value = entry.get().strip()
                if value:
                    os.environ[env_var] = value
                elif env_var in os.environ:
                    del os.environ[env_var]
            messagebox.showinfo("Success", "API keys saved to current session.")
            config_win.destroy()
        
        ttk.Button(buttons_frame, text="Cancel", command=config_win.destroy).pack(side="right", padx=(5, 0))
        ttk.Button(buttons_frame, text="Save", command=save_keys).pack(side="right")
    
    def _prompt_provider_selection_if_needed(self):
        if not any(self.provider_config.values()):
            messagebox.showwarning("No Providers Selected", 
                                 "Please configure at least one provider in Tools > Configure Providers.")
            self._configure_providers()
            return any(self.provider_config.values())
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
    """Main entry point for the GUI application."""
    try:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        app = IOCCheckerGUI()
        app.run()
        
    except Exception as e:
        print(f"Failed to start GUI: {e}")
        import traceback
        traceback.print_exc()
        
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Startup Error", 
                               f"Failed to start IOC Checker GUI:\n\n{e}\n\n"
                               "Please check the console for more details.")
            root.destroy()
        except:
            pass
        
        sys.exit(1)


__all__ = ["run_gui"]


if __name__ == "__main__":
    run_gui()
