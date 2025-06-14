"""
Tkinter GUI for IOC checking with format-agnostic input and live progress bar.
• Drag & Drop • Format detection • Real-time progress • Subprocess integration
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

class IOCCheckerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("IOC Checker - Format Agnostic")
        self.root.geometry("1000x700")
        self.q = queue.Queue()
        self.running = False
        self.show_only = tk.BooleanVar(value=True)
        self.no_virustotal = tk.BooleanVar(value=False)
        self.stats = {'threat': 0, 'clean': 0, 'error': 0, 'total': 0}
        
        # Progress tracking
        self.total_iocs = 0
        self.processed_iocs = 0
        
        self._build_ui()
        self._poll()

    def _build_ui(self):
        s = ttk.Style()
        s.configure('Act.TButton', padding=(10, 4))
        s.configure('Bad.TButton', foreground='red')
        
        main = ttk.Frame(self.root, padding=15)
        main.grid(sticky="nsew")
        self.root.rowconfigure(0, weight=1)
        self.root.columnconfigure(0, weight=1)
        
        title_label = ttk.Label(main, text="IOC Threat Intelligence Checker", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, sticky="w")
        
        inp = ttk.Frame(main)
        inp.grid(row=1, column=0, sticky="ew", pady=10)
        main.columnconfigure(0, weight=1)
        
        ttk.Label(inp, text="Type").grid(row=0, column=0)
        self.type_cb = ttk.Combobox(inp, values=IOC_TYPES, state="readonly", width=10)
        self.type_cb.current(0)
        self.type_cb.grid(row=0, column=1, padx=5)
        
        ttk.Label(inp, text="Value").grid(row=0, column=2)
        self.val = tk.Entry(inp, width=50)
        self.val.grid(row=0, column=3, sticky="ew", padx=5)
        inp.columnconfigure(3, weight=1)
        
        btnf = ttk.Frame(inp)
        btnf.grid(row=0, column=4, padx=5)
        self.btn_check = ttk.Button(btnf, text="Check", style='Act.TButton', 
                                   command=self._start_single)
        self.btn_check.pack(side=tk.LEFT)
        ttk.Button(btnf, text="Clear", command=self._clear).pack(side=tk.LEFT, padx=5)
        
        batch = ttk.Frame(main)
        batch.grid(row=2, column=0, sticky="ew", pady=5)
        self.file_var = tk.StringVar()
        
        ttk.Label(batch, text="File:").grid(row=0, column=0)
        file_entry = ttk.Entry(batch, textvariable=self.file_var, width=50)
        file_entry.grid(row=0, column=1, sticky="ew", padx=5)
        batch.columnconfigure(1, weight=1)
        
        ttk.Button(batch, text="Browse", command=self._browse).grid(row=0, column=2)
        self.btn_batch = ttk.Button(batch, text="Start Processing", style='Act.TButton', 
                                   command=self._start_batch)
        self.btn_batch.grid(row=0, column=3, padx=5)
        
        # Format info label
        self.format_label = ttk.Label(batch, text="Supported: CSV, TSV, XLSX, TXT", foreground="gray")
        self.format_label.grid(row=1, column=0, columnspan=4, sticky="w", pady=(5,0))
        
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
        
        res = ttk.LabelFrame(main, text="Results")
        res.grid(row=4, column=0, sticky="nsew")
        main.rowconfigure(4, weight=1)
        
        self.out = scrolledtext.ScrolledText(res, font=('Consolas', 10), 
                                           state=tk.DISABLED, wrap=tk.WORD)
        self.out.pack(expand=True, fill='both')
        
        for t, c in COLORS.items():
            self.out.tag_configure(t, foreground=c)
        
        st = ttk.Frame(main)
        st.grid(row=5, column=0, sticky="ew")
        
        self.lab_stats = {k: ttk.Label(st, text=f"{k}:0") for k in self.stats}
        for i, (k, l) in enumerate(self.lab_stats.items()):
            l.grid(row=0, column=i, padx=8, sticky="w")
        
        checkbox = ttk.Checkbutton(st, text="Show only threats", variable=self.show_only)
        checkbox.grid(row=0, column=5, padx=20)
        
        vt_checkbox = ttk.Checkbutton(st, text="Skip VirusTotal", variable=self.no_virustotal)
        vt_checkbox.grid(row=0, column=6, padx=20)
        
        self.root.bind("<Return>", self._start_single)
        
        # Setup drag and drop
        self._setup_drag_drop()

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
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
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

    def _start_single(self, *_):
        if self.running:
            return
        v = self.val.get().strip()
        t = self.type_cb.get()
        if not v:
            return
        self._log("info", f"=== {t}:{v} ===")
        cmd = [PYTHON, SCRIPT, t, v]
        if self.no_virustotal.get():
            cmd.append("--no-virustotal")
        
        self.processed_iocs = 0
        self.total_iocs = 1
        threading.Thread(target=self._run_sub, args=(cmd,), daemon=True).start()
        self.running = True

    def _start_batch(self):
        if self.running:
            return
        p = self.file_var.get().strip()
        if not p or not os.path.exists(p):
            return
        
        self._log("info", f"=== Batch {p} ===")
        
        # Use format-agnostic approach
        path = Path(p)
        if path.suffix.lower() in ['.csv', '.tsv', '.xlsx', '.txt']:
            cmd = [PYTHON, SCRIPT, "--file", p]
        else:
            # Fallback to old behavior
            t = self.type_cb.get()
            if p.lower().endswith(".csv"):
                cmd = [PYTHON, SCRIPT, "--csv", p]
            else:
                cmd = [PYTHON, SCRIPT, t, "--file", p]
        
        if self.no_virustotal.get():
            cmd.append("--no-virustotal")
        
        self.processed_iocs = 0
        self.total_iocs = 0
        threading.Thread(target=self._run_sub, args=(cmd,), daemon=True).start()
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

    def _poll(self):
        while not self.q.empty():
            typ, msg = self.q.get_nowait()
            self._log(typ, msg)
            if "✓ completed" in msg.lower():
                self.running = False
        self.root.after_idle(lambda: self.root.after(150, self._poll))

    def run(self):
        self.root.mainloop()

# Keep original class name for compatibility
App = IOCCheckerGUI

def main():
    """Main entry point."""
    logging.basicConfig(level=logging.INFO)
    IOCCheckerGUI().run()

if __name__ == "__main__":
    main()
