#!/usr/bin/env python3
"""
Tkinter GUI for IOC checking with format-agnostic input, live progress bar, and provider selection.
• Drag & Drop • Format detection • Real-time progress • Provider selection dialog • Subprocess integration
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import subprocess
import sys
import threading
import queue
import os
import re
import logging
from pathlib import Path
from loader import load_iocs

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

def _classify(line: str) -> str:
    if ("🚨" in line or 
        re.search(r"(Malicious|Suspicious):[1-9]", line) or 
        "Found in" in line):
        return "threat"
    if any(t in line for t in ("✅", "Clean", "Not found", "Whitelisted")):
        return "clean"
    if any(t in line for t in ("⚠️", "Suspicious", "Medium")):
        return "warning"
    if "❌" in line or "ERROR" in line:
        return "error"
    if "ℹ️" in line or "INFO" in line:
        return "info"
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
    
    def __init__(self, parent, config=None):
        self.parent = parent
        self.result = None
        self.vars = {}
        
        # Default configuration
        default_config = {provider: False for provider in AVAILABLE_PROVIDERS.keys()}
        default_config.update({'abuseipdb': True, 'otx': True, 'threatfox': True})  # Always-on providers
        
        if config:
            default_config.update(config)
        
        self._build_dialog(default_config)
    
    def _build_dialog(self, config):
        """Build the provider selection dialog."""
        self.dialog = tk.Toplevel(self.parent)
        self.dialog.title("Select Threat Intelligence Providers")
        self.dialog.geometry("500x400")
        self.dialog.resizable(False, False)
        self.dialog.transient(self.parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (400 // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Select Threat Intelligence Providers", 
                               font=('Arial', 14, 'bold'))
        title_label.pack(anchor='w', pady=(0, 15))
        
        # Instructions
        instructions = ttk.Label(main_frame, 
                                text="Choose which threat intelligence providers to query.\n"
                                     "Always-on providers (AbuseIPDB, OTX, ThreatFox) are free and recommended.",
                                foreground='gray')
        instructions.pack(anchor='w', pady=(0, 15))
        
        # Scrollable frame for providers
        canvas = tk.Canvas(main_frame, height=200)
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Provider checkboxes
        for provider, description in AVAILABLE_PROVIDERS.items():
            var = tk.BooleanVar(value=config.get(provider, False))
            self.vars[provider] = var
            
            frame = ttk.Frame(scrollable_frame)
            frame.pack(fill='x', padx=5, pady=2)
            
            checkbox = ttk.Checkbutton(frame, text=f"{provider.upper()}", variable=var)
            checkbox.pack(side='left')
            
            desc_label = ttk.Label(frame, text=f"- {description}", foreground='gray')
            desc_label.pack(side='left', padx=(10, 0))
            
            # Mark always-on providers
            if provider in ['abuseipdb', 'otx', 'threatfox', 'urlhaus', 'malwarebazaar']:
                always_label = ttk.Label(frame, text="(Always On)", foreground='green', font=('Arial', 8))
                always_label.pack(side='right')
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(15, 0))
        
        ttk.Button(button_frame, text="Select All", command=self._select_all).pack(side='left')
        ttk.Button(button_frame, text="Select None", command=self._select_none).pack(side='left', padx=(10, 0))
        ttk.Button(button_frame, text="Defaults", command=self._select_defaults).pack(side='left', padx=(10, 0))
        
        ttk.Button(button_frame, text="Cancel", command=self._cancel).pack(side='right')
        ttk.Button(button_frame, text="OK", command=self.ok).pack(side='right', padx=(0, 10))
        
        # Bind Enter and Escape
        self.dialog.bind('<Return>', lambda e: self.ok())
        self.dialog.bind('<Escape>', lambda e: self._cancel())
        
        # Focus on OK button
        self.dialog.focus_set()
    
    def _select_all(self):
        """Select all providers."""
        for var in self.vars.values():
            var.set(True)
    
    def _select_none(self):
        """Deselect all providers."""
        for var in self.vars.values():
            var.set(False)
    
    def _select_defaults(self):
        """Select default providers (always-on + VirusTotal)."""
        for provider, var in self.vars.items():
            if provider in ['abuseipdb', 'otx', 'threatfox', 'urlhaus', 'malwarebazaar', 'virustotal']:
                var.set(True)
            else:
                var.set(False)
    
    def ok(self):
        """Accept the provider selection."""
        self.result = {provider: var.get() for provider, var in self.vars.items()}
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
        
        main_frame = ttk.Frame(self.dialog, padding=20)
        main_frame.pack(fill='both', expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="HTTP Proxy Configuration", 
                               font=('Arial', 12, 'bold'))
        title_label.pack(anchor='w', pady=(0, 10))
        
        # Proxy input
        ttk.Label(main_frame, text="Proxy URL (e.g., http://proxy:8080):").pack(anchor='w')
        
        self.var = tk.StringVar(value=os.environ.get("http_proxy", ""))
        self.entry = ttk.Entry(main_frame, textvariable=self.var, width=50)
        self.entry.pack(fill='x', pady=(5, 15))
        
        # Instructions
        instructions = ttk.Label(main_frame, 
                                text="Leave empty to disable proxy. Changes apply to current session only.",
                                foreground='gray')
        instructions.pack(anchor='w', pady=(0, 15))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x')
        
        ttk.Button(button_frame, text="Cancel", command=self._cancel).pack(side='right')
        ttk.Button(button_frame, text="OK", command=self.ok).pack(side='right', padx=(0, 10))
        
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

class IOCCheckerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("IOC Checker - Advanced")
        self.root.geometry("1000x700")
        self.q = queue.Queue()
        self.running = False
        self.process = None  # Track the running process
        self.show_only = tk.BooleanVar(value=True)
        self.no_virustotal = tk.BooleanVar(value=False)
        self.stats = {'threat': 0, 'clean': 0, 'error': 0, 'total': 0}
        
        # Provider configuration
        self.provider_config = {
            'abuseipdb': True, 'otx': True, 'threatfox': True, 'urlhaus': True, 'malwarebazaar': True,
            'virustotal': True, 'greynoise': False, 'pulsedive': False, 'shodan': False
        }
        
        # Progress tracking
        self.total_iocs = 0
        self.processed_iocs = 0
        
        self._build_ui()
        self._poll()

    def _build_ui(self):
        s = ttk.Style()
        s.configure('Act.TButton', padding=(10, 4))
        s.configure('Bad.TButton', foreground='red')
        s.configure('Provider.TButton', foreground='blue')
        
        main = ttk.Frame(self.root, padding=15)
        main.grid(sticky="nsew")
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        
        # Title with provider count
        title_frame = ttk.Frame(main)
        title_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        title_frame.columnconfigure(0, weight=1)
        
        title_label = ttk.Label(title_frame, text="IOC Threat Intelligence Checker", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, sticky="w")
        
        self.provider_status = ttk.Label(title_frame, text="", foreground='gray')
        self.provider_status.grid(row=0, column=1, sticky="e")
        self._update_provider_status()
        
        # Single IOC input
        inp = ttk.Frame(main)
        inp.grid(row=1, column=0, sticky="ew", pady=10)
        main.columnconfigure(0, weight=1)
        
        ttk.Label(inp, text="Type").grid(row=0, column=0)
        self.type_cb = ttk.Combobox(inp, values=IOC_TYPES, state="readonly", width=10)
        self.type_cb.current(0)
        self.type_cb.grid(row=0, column=1, padx=5)
        
        ttk.Label(inp, text="Value").grid(row=0, column=2)
        self.val = tk.Entry(inp, width=40)
        self.val.grid(row=0, column=3, sticky="ew", padx=5)
        inp.columnconfigure(3, weight=1)
        
        # Single IOC buttons
        btnf = ttk.Frame(inp)
        btnf.grid(row=0, column=4, padx=5)
        self.btn_check = ttk.Button(btnf, text="Check", style='Act.TButton', 
                                   command=self._start_single)
        self.btn_check.pack(side=tk.LEFT)
        self.btn_stop = ttk.Button(btnf, text="Stop", style='Bad.TButton', 
                                  command=self._stop_processing, state='disabled')
        self.btn_stop.pack(side=tk.LEFT, padx=(5, 0))
        ttk.Button(btnf, text="Clear", command=self._clear).pack(side=tk.LEFT, padx=(5, 0))
        
        # Batch processing
        batch = ttk.Frame(main)
        batch.grid(row=2, column=0, sticky="ew", pady=5)
        self.file_var = tk.StringVar()
        
        ttk.Label(batch, text="File:").grid(row=0, column=0)
        file_entry = ttk.Entry(batch, textvariable=self.file_var, width=40)
        file_entry.grid(row=0, column=1, sticky="ew", padx=5)
        batch.columnconfigure(1, weight=1)
        
        ttk.Button(batch, text="Browse", command=self._browse).grid(row=0, column=2, padx=(5, 0))
        self.btn_batch = ttk.Button(batch, text="Start Processing", style='Act.TButton', 
                                   command=self._start_batch)
        self.btn_batch.grid(row=0, column=3, padx=(5, 0))
        
        # Configuration buttons
        config_frame = ttk.Frame(batch)
        config_frame.grid(row=0, column=4, padx=(10, 0))
        
        ttk.Button(config_frame, text="Providers", style='Provider.TButton',
                  command=self._configure_providers).pack(side='left')
        ttk.Button(config_frame, text="Proxy", style='Provider.TButton',
                  command=self._configure_proxy).pack(side='left', padx=(5, 0))
        
        # Format info label
        self.format_label = ttk.Label(batch, text="Supported: CSV, TSV, XLSX, TXT", foreground="gray")
        self.format_label.grid(row=1, column=0, columnspan=5, sticky="w", pady=(5,0))
        
        # Progress bar (initially hidden)
        self.progress_frame = ttk.Frame(main)
        self.progress_frame.grid(row=3, column=0, sticky="ew", pady=(10,5))
        self.progress_frame.columnconfigure(0, weight=1)
        
        self.progress_label = ttk.Label(self.progress_frame, text="")
        self.progress_label.grid(row=0, column=0, sticky="w")
        
        self.progress = ttk.Progressbar(self.progress_frame, mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew", pady=(5,0))
        
        # Initially hide progress
        self.progress_frame.grid_remove()
        
        # Results
        res = ttk.LabelFrame(main, text="Results")
        res.grid(row=4, column=0, sticky="nsew")
        main.rowconfigure(4, weight=1)
        
        self.out = scrolledtext.ScrolledText(res, font=('Consolas', 10), 
                                           state=tk.DISABLED, wrap=tk.WORD)
        self.out.pack(expand=True, fill='both')
        
        for t, c in COLORS.items():
            self.out.tag_configure(t, foreground=c)
        
        # Status bar
        st = ttk.Frame(main)
        st.grid(row=5, column=0, sticky="ew")
        
        self.lab_stats = {k: ttk.Label(st, text=f"{k}:0") for k in self.stats}
        for i, (k, l) in enumerate(self.lab_stats.items()):
            l.grid(row=0, column=i, padx=8, sticky="w")
        
        checkbox = ttk.Checkbutton(st, text="Show only threats", variable=self.show_only)
        checkbox.grid(row=0, column=5, padx=20)
        
        self.root.bind("<Return>", self._start_single)
        
        # Setup drag and drop
        self._setup_drag_drop()

    def _update_provider_status(self):
        """Update the provider status display."""
        enabled_count = sum(1 for enabled in self.provider_config.values() if enabled)
        total_count = len(self.provider_config)
        self.provider_status.config(text=f"Providers: {enabled_count}/{total_count} enabled")

    def _configure_providers(self):
        """Open provider configuration dialog."""
        dialog = ProviderDlg(self.root, self.provider_config.copy())
        self.root.wait_window(dialog.dialog)
        
        if dialog.result is not None:
            self.provider_config.update(dialog.result)
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

    def _build_provider_args(self):
        """Build provider arguments for command line."""
        args = []
        
        # Add enabled providers
        for provider, enabled in self.provider_config.items():
            if enabled and provider not in ['abuseipdb', 'otx', 'threatfox', 'urlhaus', 'malwarebazaar']:
                args.append(f"--{provider}")
        
        # Add rate limiting if any rate-limited providers are enabled
        rate_limited_providers = ['virustotal', 'greynoise', 'pulsedive', 'shodan']
        if any(self.provider_config.get(p, False) for p in rate_limited_providers):
            args.append("--rate")
        
        return args

    def _classify(self, line: str) -> str:
        if ("🚨" in line or 
            re.search(r"(Malicious|Suspicious):[1-9]", line) or 
            "Found in" in line):
            return "threat"
        if any(t in line for t in ("✅", "Clean", "Not found", "Whitelisted")):
            return "clean"
        if any(t in line for t in ("⚠️", "Suspicious", "Medium")):
            return "warning"
        if "❌" in line or "ERROR" in line:
            return "error"
        if "ℹ️" in line or "INFO" in line:
            return "info"
        return "default"

    def _should_show(self, line: str, only: bool) -> bool:
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

    def _show_progress(self, message):
        """Show progress bar with message."""
        self.progress_label.config(text=message)
        self.progress_frame.grid()
        self.progress.config(mode="indeterminate")
        self.progress.start(10)

    def _update_progress(self, processed, total, message=""):
        """Update progress bar with determinate progress."""
        self.root.after(0, self._update_progress_ui, processed, total, message)

    def _update_progress_ui(self, processed, total, message):
        """Update progress UI on main thread."""
        if total > 0:
            self.progress.stop()
            self.progress.config(mode="determinate", maximum=total, value=processed)
            percent = int((processed / total) * 100)
            self.progress_label.config(text=f"{message} ({processed}/{total} - {percent}%)")
        else:
            self.progress_label.config(text=message)

    def _hide_progress(self):
        """Hide progress bar."""
        self.root.after(0, self._hide_progress_ui)

    def _hide_progress_ui(self):
        """Hide progress UI on main thread."""
        self.progress.stop()
        self.progress_frame.grid_remove()

    def _run_sub(self, cmd):
        try:
            self._show_progress("Starting process...")
            self.process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.STDOUT, text=True)
            for line in self.process.stdout:
                line_stripped = line.rstrip()
                self.q.put((_classify(line_stripped), line_stripped))
                
                # Track progress for batch processing
                if "Found" in line_stripped and "IOCs to process:" in line_stripped:
                    try:
                        parts = line_stripped.split()
                        self.total_iocs = int(parts[1])
                        self._update_progress(0, self.total_iocs, "Processing IOCs")
                    except (ValueError, IndexError):
                        pass
                
                elif line_stripped.startswith("Processing IOC:"):
                    self.processed_iocs += 1
                    if self.total_iocs > 0:
                        self._update_progress(self.processed_iocs, self.total_iocs, "Processing IOCs")
                        
        except Exception as e:
            self.q.put(("error", f"Process error: {str(e)}"))
        finally:
            self._hide_progress()
            self.q.put(("info", "✓ completed"))

    def _poll(self):
        while not self.q.empty():
            typ, msg = self.q.get_nowait()
            self._log(typ, msg)
            if "✓ completed" in msg.lower():
                self._reset_ui_state()
        self.root.after_idle(lambda: self.root.after(150, self._poll))

    def _start_single(self, *_):
        if self.running:
            return
        v = self.val.get().strip()
        t = self.type_cb.get()
        if not v:
            return
        
        # Check if value looks like a date/time and reject it
        if self._is_datetime_format(v):
            self._log("error", "Date/time values are not valid IOCs. Please enter an IP, domain, URL, or hash.")
            return
            
        self._log("info", f"=== {t}:{v} ===")
        cmd = [PYTHON, SCRIPT, t, v]
        
        # Add provider arguments based on user selection
        provider_args = self._build_provider_args()
        cmd.extend(provider_args)
        
        self.processed_iocs = 0
        self.total_iocs = 1
        self._start_processing()
        threading.Thread(target=self._run_sub, args=(cmd,), daemon=True).start()

    def _start_batch(self):
        if self.running:
            return
        p = self.file_var.get().strip()
        if not p or not os.path.exists(p):
            return
        
        self._log("info", f"=== Batch {p} ===")
        
        # Use format-agnostic approach with file flag
        cmd = [PYTHON, SCRIPT, "--file", p]
        
        # Add provider arguments based on user selection
        provider_args = self._build_provider_args()
        cmd.extend(provider_args)
        
        self.processed_iocs = 0
        self.total_iocs = 0
        self._start_processing()
        threading.Thread(target=self._run_sub, args=(cmd,), daemon=True).start()

    def _is_datetime_format(self, value):
        """Check if value looks like a date/time format to avoid false positives."""
        # Common date/time patterns that might be mistaken for IOCs
        datetime_patterns = [
            r'^\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'^\d{2}[-/]\d{2}[-/]\d{4}',  # MM/DD/YYYY or DD/MM/YYYY
            r'^\d{1,2}:\d{2}',  # HH:MM
            r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}',  # ISO datetime
        ]
        
        for pattern in datetime_patterns:
            if re.match(pattern, value.strip()):
                return True
        return False

    def _clear(self):
        self.out.config(state=tk.NORMAL)
        self.out.delete("1.0", tk.END)
        self.out.config(state=tk.DISABLED)
        for k in self.stats:
            self.stats[k] = 0
            self.lab_stats[k].configure(text=f"{k}:0")

    def _log(self, typ, msg):
        if _should_show(msg, self.show_only.get()):
            self.out.config(state=tk.NORMAL)
            self.out.insert(tk.END, msg + "\n", typ)
            self.out.see(tk.END)
            self.out.config(state=tk.DISABLED)
        self.stats['total'] += 1
        if typ in ('threat', 'clean', 'error'):
            self.stats[typ] += 1
            self.lab_stats[typ].configure(text=f"{typ}:{self.stats[typ]}")
        self.lab_stats['total'].configure(text=f"total:{self.stats['total']}")

    def run(self):
        self.root.mainloop()

    def _setup_drag_drop(self):
        """Setup drag and drop functionality."""
        try:
            from tkinterdnd2 import DND_FILES, TkinterDnD
            # Convert existing window to TkinterDnD
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self._on_drop)
            log.info("Drag & drop enabled")
        except ImportError:
            log.info("Drag & drop not available (tkinterdnd2 not installed)")
        except Exception as e:
            log.warning(f"Drag & drop setup failed: {e}")

    def _on_drop(self, event):
        """Handle file drop."""
        try:
            files = self.root.tk.splitlist(event.data)
            if files:
                file_path = files[0]
                # Remove curly braces if present
                if file_path.startswith('{') and file_path.endswith('}'):
                    file_path = file_path[1:-1]
                
                self.file_var.set(file_path)
                self._update_format_info(file_path)
                self._validate_file(file_path)
        except Exception as e:
            log.error(f"Drop handling error: {e}")

    def _update_format_info(self, file_path):
        """Update format information label."""
        try:
            p = Path(file_path)
            suffix = p.suffix.lower()
            format_map = {
                '.csv': 'CSV (Comma-separated)',
                '.tsv': 'TSV (Tab-separated)', 
                '.xlsx': 'Excel Spreadsheet',
                '.txt': 'Plain Text'
            }
            format_text = format_map.get(suffix, f'Unknown format ({suffix})')
            self.format_label.config(text=f"Detected: {format_text}")
        except Exception:
            self.format_label.config(text="Supported: CSV, TSV, XLSX, TXT")

    def _validate_file(self, file_path):
        """Validate file and show preview of IOCs."""
        try:
            path = Path(file_path)
            if not path.exists():
                self.format_label.config(text="File not found", foreground="red")
                return
            
            # Try to load a few IOCs for preview
            threading.Thread(target=self._preview_file, args=(path,), daemon=True).start()
            
        except Exception as e:
            self.format_label.config(text=f"Error: {e}", foreground="red")

    def _preview_file(self, file_path):
        """Preview file IOCs in background."""
        try:
            iocs = load_iocs(file_path)
            count = len(iocs)
            
            # Update UI on main thread
            self.root.after(0, self._update_preview, count, iocs[:3])
            
        except Exception as e:
            self.root.after(0, self._update_preview_error, str(e))

    def _update_preview(self, count, sample_iocs):
        """Update preview on main thread."""
        preview_text = f"Preview: {count} IOCs found"
        if sample_iocs:
            types = list(set(ioc['type'] for ioc in sample_iocs))
            preview_text += f" (types: {', '.join(types)})"
        
        self.format_label.config(text=preview_text, foreground="green")

    def _update_preview_error(self, error):
        """Update preview error on main thread."""
        self.format_label.config(text=f"Error: {error}", foreground="red")

    def _stop_processing(self):
        """Stop the current processing operation."""
        if self.process and self.running:
            try:
                self.process.terminate()
                self._log("warning", "Processing stopped by user")
                self.running = False
                self._hide_progress()
                self._reset_ui_state()
            except Exception as e:
                self._log("error", f"Error stopping process: {e}")

    def _reset_ui_state(self):
        """Reset UI state after processing completes or stops."""
        self.btn_check.config(state='normal')
        self.btn_batch.config(state='normal')
        self.btn_stop.config(state='disabled')
        self.running = False
        self.process = None

    def _start_processing(self):
        """Common setup when starting any processing operation."""
        self.btn_check.config(state='disabled')
        self.btn_batch.config(state='disabled')
        self.btn_stop.config(state='normal')
        self.running = True

    def _browse(self):
        filetypes = [
            ("All Supported", "*.csv;*.tsv;*.xlsx;*.txt"),
            ("CSV files", "*.csv"),
            ("TSV files", "*.tsv"), 
            ("Excel files", "*.xlsx"),
            ("Text files", "*.txt"),
            ("All files", "*.*")
        ]
        p = filedialog.askopenfilename(filetypes=filetypes)
        if p:
            self.file_var.set(p)
            self._update_format_info(p)
            self._validate_file(p)

# Keep original class name for compatibility
App = IOCCheckerGUI

def main():
    """Main entry point."""
    logging.basicConfig(level=logging.INFO)
    IOCCheckerGUI().run()

if __name__ == "__main__":
    main()
