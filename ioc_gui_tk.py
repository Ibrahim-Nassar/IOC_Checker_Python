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

from ioc_types import IOCStatus, IOCResult, detect_ioc_type
from providers import get_providers
from ioc_checker import aggregate_verdict, query_providers

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
        ioc_entry = ttk.Entry(input_frame, textvariable=self.ioc_var, width=40)
        ioc_entry.grid(row=0, column=3, sticky="ew", padx=(0, 10))
        ioc_entry.bind("<Return>", self._start_single)
        
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
        
        def run_single_check():
            try:
                selected_provider_names = [p.NAME.lower() for p in self._selected_providers()]
                
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
                results = loop.run_until_complete(
                    query_providers(ioc_value, ioc_type, selected_provider_names)
                )
                
                loop.close()
                
                overall_verdict = aggregate_verdict(results)
                flagged_providers = [r.message.split()[1] if "Provider" in r.message else "unknown" 
                                   for r in results if r.status == IOCStatus.MALICIOUS]
                
                provider_values = []
                for col in self.provider_columns:
                    result = next((r for r in results if col in r.message.lower()), None)
                    if result:
                        provider_values.append(_STATUS_MAP.get(result.status, result.status.name))
                    else:
                        provider_values.append("")
                
                row_values = (
                    ioc_type,
                    ioc_value, 
                    _STATUS_MAP.get(overall_verdict, overall_verdict.name),
                    ", ".join(flagged_providers)
                ) + tuple(provider_values)
                
                self.root.after(0, lambda: self._show_result(row_values, placeholder))
                
            except Exception as e:
                error_msg = str(e)
                self.root.after(0, lambda: self._show_result(
                    (ioc_type, ioc_value, "Error", error_msg) + tuple("" for _ in self.provider_columns), 
                    placeholder
                ))
        
        thread = threading.Thread(target=run_single_check, daemon=True)
        thread.start()
    
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
            
            def run_batch():
                try:
                    selected_provider_names = [p.NAME.lower() for p in self._selected_providers()]
                    
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    
                    for ioc_data in iocs:
                        ioc_value = ioc_data.get('value', str(ioc_data))
                        ioc_type, normalized_ioc = detect_ioc_type(ioc_value)
                        
                        if ioc_type != "unknown":
                            results = loop.run_until_complete(
                                query_providers(normalized_ioc, ioc_type, selected_provider_names)
                            )
                            
                            overall_verdict = aggregate_verdict(results)
                            flagged_providers = [r.message.split()[1] if "Provider" in r.message else "unknown"
                                               for r in results if r.status == IOCStatus.MALICIOUS]
                            
                            provider_values = []
                            for col in self.provider_columns:
                                result = next((r for r in results if col in r.message.lower()), None)
                                if result:
                                    provider_values.append(_STATUS_MAP.get(result.status, result.status.name))
                                else:
                                    provider_values.append("")
                            
                            row_values = (
                                ioc_type,
                                normalized_ioc,
                                _STATUS_MAP.get(overall_verdict, overall_verdict.name),
                                ", ".join(flagged_providers)
                            ) + tuple(provider_values)
                            
                            self.root.after(0, lambda vals=row_values: self._show_result(vals))
                    
                    loop.close()
                    self.root.after(0, lambda: self._batch_complete(len(iocs)))
                    
                except Exception as e:
                    error_msg = str(e)
                    self.root.after(0, lambda msg=error_msg: self._batch_error(msg))
            
            thread = threading.Thread(target=run_batch, daemon=True)
            thread.start()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load IOCs: {str(e)}")
    
    def _batch_complete(self, count):
        messagebox.showinfo("Batch Complete", f"Successfully processed {count} IOCs.")
    
    def _batch_error(self, error_msg):
        messagebox.showerror("Batch Processing Error", f"Batch processing failed:\n\n{error_msg}")
    
    def _show_result(self, *args, **kwargs):
        if isinstance(args[0], (tuple, list)):
            values_tuple = tuple(args[0])
            row_id = args[1] if len(args) > 1 else None
        else:
            values_tuple = args
            row_id = kwargs.get("row_id")
        
        if not hasattr(self, "all_results"):
            self.all_results = []
        
        self.all_results.append(values_tuple)
        
        def should_display():
            if not self.show_threats_var.get():
                return True
            status_text = str(values_tuple[2]).lower() if len(values_tuple) >= 3 else ""
            return "malicious" in status_text or "error" in status_text
        
        if row_id and self.out.exists(row_id):
            if should_display():
                self.out.item(row_id, values=values_tuple)
            else:
                self.out.delete(row_id)
        else:
            if should_display():
                self.out.insert("", "end", values=values_tuple)
    
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
    
    def _configure_api_keys(self):
        config_window = tk.Toplevel(self.root)
        config_window.title("API Key Configuration")
        config_window.geometry("700x400")
        config_window.transient(self.root)
        config_window.grab_set()
        
        main_frame = ttk.Frame(config_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ttk.Label(main_frame, text="API Key Configuration", font=("Arial", 14, "bold")).pack(pady=(0, 20))
        
        providers_env = [
            ("VirusTotal", "VT_API_KEY"),
            ("OTX AlienVault", "OTX_API_KEY"), 
            ("AbuseIPDB", "ABUSEIPDB_API_KEY"),
            ("ThreatFox", "THREATFOX_API_KEY"),
            ("GreyNoise", "GREYNOISE_API_KEY"),
        ]
        
        self._api_vars = {}
        
        for i, (prov_name, env_var) in enumerate(providers_env):
            frame = ttk.Frame(main_frame)
            frame.pack(fill="x", pady=5)
            
            ttk.Label(frame, text=prov_name, width=15).pack(side="left")
            
            var = tk.StringVar(value=os.environ.get(env_var, ""))
            self._api_vars[env_var] = var
            
            entry = ttk.Entry(frame, textvariable=var, show="•", width=50)
            entry.pack(side="left", fill="x", expand=True, padx=(10, 0))
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill="x", pady=(20, 0))
        
        def save_keys():
            try:
                from api_key_store import save
                for env_var, var in self._api_vars.items():
                    key_val = var.get().strip()
                    save(env_var, key_val)
                    if key_val:
                        os.environ[env_var] = key_val
                config_window.destroy()
                messagebox.showinfo("Success", "API keys saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save API keys: {str(e)}")
        
        ttk.Button(btn_frame, text="Save", command=save_keys).pack(side="right", padx=(10, 0))
        ttk.Button(btn_frame, text="Cancel", command=config_window.destroy).pack(side="right")
    
    def _prompt_provider_selection_if_needed(self):
        selected_providers = [p for p in self.provider_config.values() if p]
        
        if not selected_providers:
            try:
                self.show_providers_info()
                selected_providers = [p for p in self.provider_config.values() if p]
                if not selected_providers:
                    return False
            except Exception as e:
                log.error(f"Error opening provider selection dialog: {e}")
                return False
        
        return True
    
    def _refresh_display(self):
        current_children = list(self.out.get_children())
        self.out.delete(*current_children)
        
        for result in self.all_results:
            status_text = str(result[2]).lower() if len(result) >= 3 else ""
            should_show = (not self.show_threats_var.get() or 
                          "malicious" in status_text or "error" in status_text)
            
            if should_show:
                self.out.insert("", "end", values=result)
    
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
