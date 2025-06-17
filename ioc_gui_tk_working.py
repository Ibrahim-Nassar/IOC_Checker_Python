#!/usr/bin/env python3
import subprocess
import sys
import threading
import queue
import os
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog
import re

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

# ── **patched**: smarter filter for "Show only threats" ───────────────────
def _should_show(line: str, only: bool) -> bool:
    """
    Return True if the line should appear given the 'only threats' setting.
    We now ignore clean VT lines like 'Malicious:0 Suspicious:0'.
    """
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
# ──────────────────────────────────────────────────────────────────────────

class IOCCheckerGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("IOC Checker")
        self.root.geometry("1000x700")
        self.q = queue.Queue()
        self.running = False
        self.show_only = tk.BooleanVar(value=True)
        self.no_virustotal = tk.BooleanVar(value=False)
        self.stats = {'threat': 0, 'clean': 0, 'error': 0, 'total': 0}        self._build_ui()
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
        
        file_entry = ttk.Entry(batch, textvariable=self.file_var, width=50)
        file_entry.grid(row=0, column=1, sticky="ew", padx=5)
        batch.columnconfigure(1, weight=1)
        
        ttk.Button(batch, text="Browse", command=self._browse).grid(row=0, column=2)
        self.btn_batch = ttk.Button(batch, text="Batch", style='Act.TButton', 
                                   command=self._start_batch)
        self.btn_batch.grid(row=0, column=3, padx=5)
          res = ttk.LabelFrame(main, text="Results")
        res.grid(row=3, column=0, sticky="nsew")
        main.rowconfigure(3, weight=1)
        
        self.out = scrolledtext.ScrolledText(res, font=('Consolas', 10), 
                                           state=tk.DISABLED, wrap=tk.WORD)
        self.out.pack(expand=True, fill='both')
        
        for t, c in COLORS.items():
            self.out.tag_configure(t, foreground=c)
        
        st = ttk.Frame(main)
        st.grid(row=4, column=0, sticky="ew")
        
        self.lab_stats = {k: ttk.Label(st, text=f"{k}:0") for k in self.stats}
        for i, (k, l) in enumerate(self.lab_stats.items()):
            l.grid(row=0, column=i, padx=8, sticky="w")
        
        checkbox = ttk.Checkbutton(st, text="Show only threats", variable=self.show_only)
        checkbox.grid(row=0, column=5, padx=20)
        
        vt_checkbox = ttk.Checkbutton(st, text="Skip VirusTotal", variable=self.no_virustotal)
        vt_checkbox.grid(row=0, column=6, padx=20)
        
        self.root.bind("<Return>", self._start_single)

    def _run_sub(self, cmd):
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, 
                                     stderr=subprocess.STDOUT, text=True)
            for line in process.stdout:
                self.q.put((_classify(line.rstrip()), line.rstrip()))
        except Exception as e:
            self.q.put(("error", f"Process error: {str(e)}"))
        finally:
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
        threading.Thread(target=self._run_sub, args=(cmd,), daemon=True).start()
        self.running = True

    def _start_batch(self):
        if self.running:
            return
        p = self.file_var.get().strip()
        t = self.type_cb.get()
        if not p or not os.path.exists(p):
            return
        self._log("info", f"=== Batch {p} ===")
        if p.lower().endswith(".csv"):
            cmd = [PYTHON, SCRIPT, "--csv", p]
        else:
            cmd = [PYTHON, SCRIPT, t, "--file", p]
        if self.no_virustotal.get():
            cmd.append("--no-virustotal")
        threading.Thread(target=self._run_sub, args=(cmd,), daemon=True).start()
        self.running = True

    def _browse(self):
        filetypes = [("CSV/TXT", "*.csv *.txt"), ("All", "*.*")]
        p = filedialog.askopenfilename(filetypes=filetypes)
        if p:
            self.file_var.set(p)

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

if __name__ == "__main__":
    IOCCheckerGUI().run()
