"""
Tkinter GUI with robust subprocess handling and UTF-8 support.
• Single IOC lookup  • Batch CSV/TXT
• Outlined buttons  • Clear output button
• Auto-clear toggle  • Enter ↵ triggers Check
• Cross-platform UTF-8 handling
"""
from __future__ import annotations
import subprocess, sys, os, tkinter as tk, logging
from tkinter import ttk, filedialog, messagebox, font
from pathlib import Path
from typing import Optional

# Set up logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("ioc_gui")

SCRIPT, PY = "ioc_checker.py", sys.executable
IOC_TYPES = ("ip", "domain", "url", "hash", "email", "filepath", "registry", "wallet", "asn", "attack")

# ────────── theme ──────────
def theme(root: tk.Tk) -> None:
    """Apply modern theme to the GUI."""
    try:
        ttk.Style().theme_use("clam")
        f = font.nametofont("TkDefaultFont")
        f.configure(family="Segoe UI", size=10)
        root.option_add("*Font", f)
        s = ttk.Style()
        s.configure(".", padding=2, borderwidth=0, relief="flat")
        s.configure("Outline.TButton", padding=(10, 4), borderwidth=1, relief="ridge")
    except Exception as e:
        log.warning(f"Theme setup failed: {e}")

# ────────── dialogs ──────────
class ProviderDlg(tk.Toplevel):
    """Provider configuration dialog."""
    def __init__(self, master: tk.Tk, cfg: dict):
        super().__init__(master)
        self.title("Providers")
        self.grab_set()
        self.result = None
        self.vars = {k: tk.BooleanVar(value=v) for k, v in cfg.items()}
        for i, (k, v) in enumerate(self.vars.items()):
            ttk.Checkbutton(self, text=k, variable=v).grid(row=i, column=0, sticky="w")
        ttk.Button(self, text="OK", command=self.ok, style="Outline.TButton").grid(
            row=len(self.vars), column=0, pady=6
        )

    def ok(self) -> None:
        """Save configuration and close dialog."""
        self.result = {k: v.get() for k, v in self.vars.items()}
        self.destroy()

class ProxyDlg(tk.Toplevel):
    """Proxy configuration dialog."""
    def __init__(self, master: tk.Tk):
        super().__init__(master)
        self.title("Proxy")
        self.grab_set()
        self.var = tk.StringVar(value=os.environ.get("https_proxy", ""))
        ttk.Entry(self, textvariable=self.var, width=40).grid(row=0, column=0, padx=6, pady=6)
        ttk.Button(self, text="OK", command=self.ok, style="Outline.TButton").grid(
            row=1, column=0, pady=(0, 6)
        )

    def ok(self) -> None:
        """Save proxy settings and close dialog."""
        p = self.var.get().strip()
        if p:
            os.environ["http_proxy"] = os.environ["https_proxy"] = p
        else:
            os.environ.pop("http_proxy", None)
            os.environ.pop("https_proxy", None)
        self.destroy()

# ────────── main app ──────────
class App(tk.Tk):
    """Main application window."""
    def __init__(self):
        super().__init__()
        theme(self)
        self.title("IOC Checker")
        self.cfg = {"virustotal": False, "greynoise": False, "pulsedive": False, "shodan": False}
        self.auto_clear = tk.BooleanVar(value=True)
        self.proc: Optional[subprocess.Popen] = None
        self._build()
        self.after(100, self._poll)

    def _build(self) -> None:
        """Build the GUI layout."""
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        # Single lookup section
        sf = ttk.LabelFrame(frm, text="Single IOC lookup")
        sf.grid(row=0, column=0, sticky="ew")
        ttk.Label(sf, text="Type").grid(row=0, column=0)
        self.typ = ttk.Combobox(sf, values=IOC_TYPES, width=12, state="readonly")
        self.typ.current(0)
        self.typ.grid(row=0, column=1, padx=(4, 8))
        ttk.Label(sf, text="Value").grid(row=0, column=2)
        self.val = tk.StringVar()
        ent = ttk.Entry(sf, textvariable=self.val, width=40)
        ent.grid(row=0, column=3, sticky="ew")
        ttk.Button(sf, text="Check", command=self.single, style="Outline.TButton").grid(
            row=0, column=4, padx=(10, 0)
        )
        sf.columnconfigure(3, weight=1)
        ent.bind("<Return>", lambda e: self.single())
        self.bind("<Return>", lambda e: self.single())

        # Batch processing section
        bf = ttk.LabelFrame(frm, text="Batch CSV/TXT processing")
        bf.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(bf, text="File").grid(row=0, column=0)
        self.path = tk.StringVar()
        ttk.Entry(bf, textvariable=self.path, width=40).grid(row=0, column=1, sticky="ew")
        ttk.Button(bf, text="Browse", command=self.browse, style="Outline.TButton").grid(
            row=0, column=2, padx=(5, 0)
        )
        ttk.Button(bf, text="Run", command=self.batch, style="Outline.TButton").grid(
            row=0, column=3
        )
        bf.columnconfigure(1, weight=1)

        # Control section
        ctl = ttk.Frame(frm)
        ctl.grid(row=2, column=0, sticky="w", pady=(8, 0))
        ttk.Button(ctl, text="Providers", command=self.providers, style="Outline.TButton").pack(
            side="left"
        )
        ttk.Button(ctl, text="Proxy", command=self.proxy, style="Outline.TButton").pack(
            side="left", padx=(6, 0)
        )
        ttk.Button(ctl, text="Clear Output", command=self.clear, style="Outline.TButton").pack(
            side="left", padx=(12, 0)
        )
        ttk.Checkbutton(ctl, text="Auto-clear on start", variable=self.auto_clear).pack(
            side="left", padx=(12, 0)
        )

        # Output section
        self.out = tk.Text(frm, height=25, state=tk.DISABLED)
        self.out.grid(row=3, column=0, sticky="nsew", pady=(10, 0))
        frm.rowconfigure(3, weight=1)
        frm.columnconfigure(0, weight=1)

    # ────────── actions ──────────
    def browse(self) -> None:
        """Browse for CSV/TXT file."""
        f = filedialog.askopenfilename(filetypes=[("CSV/TXT", "*.csv *.txt")])
        if f:
            self.path.set(f)

    def providers(self) -> None:
        """Configure providers."""
        d = ProviderDlg(self, self.cfg)
        self.wait_window(d)
        if hasattr(d, "result") and d.result:
            self.cfg.update(d.result)

    def proxy(self) -> None:
        """Configure proxy."""
        ProxyDlg(self)

    def clear(self) -> None:
        """Clear output text."""
        self.out.config(state=tk.NORMAL)
        self.out.delete("1.0", tk.END)
        self.out.config(state=tk.DISABLED)

    def single(self) -> None:
        """Run single IOC lookup."""
        if self.proc:
            return
        v = self.val.get().strip()
        if not v:
            messagebox.showerror("Input", "Enter an IOC value")
            return
        cmd = [PY, SCRIPT, self.typ.get(), v]
        
        # Add individual provider flags based on GUI selection
        for provider, enabled in self.cfg.items():
            if enabled:
                cmd.append(f"--{provider}")
        
        self._start(cmd)

    def batch(self) -> None:
        """Run batch CSV processing."""
        if self.proc:
            return
        p = self.path.get().strip()
        if not p:
            messagebox.showerror("File", "Select a CSV/TXT file")
            return
        if not Path(p).exists():
            messagebox.showerror("File", "File not found")
            return
        cmd = [PY, SCRIPT, "--csv", p, "-o", str(Path(p).with_suffix("_results.csv"))]
        
        # Add individual provider flags based on GUI selection
        for provider, enabled in self.cfg.items():
            if enabled:
                cmd.append(f"--{provider}")
        
        self._start(cmd)

    def _start(self, cmd: list) -> None:
        """Start subprocess with UTF-8 handling."""
        if self.auto_clear.get():
            self.clear()
        
        # Prevent starting multiple processes
        if self.proc and self.proc.poll() is None:
            log.warning("Process already running, ignoring new request")
            return
        
        try:
            # Set environment for UTF-8 output
            env = os.environ.copy()
            env['PYTHONIOENCODING'] = 'utf-8'
            
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                env=env
            )
            log.info(f"Started subprocess: {' '.join(cmd)}")
        except Exception as e:
            log.error(f"Failed to start subprocess: {e}")
            messagebox.showerror("Error", f"Failed to start process: {e}")

    def _poll(self) -> None:
        """Poll subprocess for output."""
        if self.proc:
            try:
                # Read available lines without blocking
                lines_read = 0
                while lines_read < 10:  # Limit lines per poll to prevent UI blocking
                    line = self.proc.stdout.readline()
                    if not line:
                        break
                    lines_read += 1
                    self.out.config(state=tk.NORMAL)
                    self.out.insert(tk.END, line)
                    self.out.see(tk.END)
                    self.out.config(state=tk.DISABLED)
                
                if self.proc.poll() is not None:
                    self.proc = None
                    log.info("Subprocess completed")
            except Exception as e:
                log.error(f"Error polling subprocess: {e}")
                self.proc = None
        
        self.after(100, self._poll)

if __name__ == "__main__":
    try:
        App().mainloop()
    except Exception as e:
        log.error(f"Application error: {e}")
        print(f"Fatal error: {e}")
