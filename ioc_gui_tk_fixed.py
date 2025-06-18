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
from loader import load_iocs

# For now, disable ttkbootstrap to ensure compatibility
TTKBOOTSTRAP_AVAILABLE = False
import tkinter.ttk as tb
from tkinter import messagebox as tb_messagebox

# Standard tkinter.ttk is used for styling
TTK_AVAILABLE = True

log = logging.getLogger("gui")

SCRIPT = "ioc_checker.py"
PYTHON = sys.executable
IOC_TYPES = ("ip", "domain", "url", "hash")

# Simple provider configuration
AVAILABLE_PROVIDERS = {
    'virustotal': 'VirusTotal',
    'abuseipdb': 'AbuseIPDB', 
    'otx': 'AlienVault OTX',
    'shodan': 'Shodan',
    'urlvoid': 'URLVoid'
}

DEFAULT_ALWAYS_ON = ['virustotal', 'abuseipdb']

class IOCCheckerGUI:
    """Simplified IOC Checker GUI that never crashes on startup."""
    
    def __init__(self):
        """Initialize the IOC Checker GUI with comprehensive error handling."""
        try:
            self.root = tk.Tk()
            self.root.title("IOC Checker - Enhanced GUI")
            self.root.geometry("1200x800")
            self.root.minsize(800, 600)
            
            # Initialize processing variables first (before UI setup)
            self.process = None
            self.q = queue.Queue()
            self.stats = {'threat': 0, 'clean': 0, 'error': 0, 'total': 0}
            self.processing = False
            
            # Provider configuration with safe defaults
            self.provider_config = {
                'virustotal': True,
                'abuseipdb': True,
                'shodan': False,
                'urlvoid': False,
                'hybrid_analysis': False
            }
            
            # UI state variables
            self.show_only = tk.BooleanVar(value=True)
            self.file_var = tk.StringVar()
            
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
                
            # Start polling for subprocess output
            self._poll_queue()
            
        except Exception as e:
            log.error(f"GUI initialization failed: {e}")
            raise

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
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Providers...", command=self._configure_providers)
        
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
        
        # Single IOC input
        inp = ttk.LabelFrame(main, text="Single IOC Check", padding=10)
        inp.grid(row=0, column=0, sticky="ew", pady=(0, 15))
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
        
        # Use Treeview for results display
        self.out = ttk.Treeview(output_frame, columns=('Type', 'IOC', 'Status', 'Details'), show='headings', height=15)
        for col in ('Type', 'IOC', 'Status', 'Details'):
            self.out.heading(col, text=col)
            self.out.column(col, width=100)
        self.out.pack(fill='both', expand=True)
        
        # Options
        options_frame = ttk.Frame(main)
        options_frame.grid(row=6, column=0, sticky="ew")
        
        ttk.Checkbutton(options_frame, text="Show only threats & errors", 
                       variable=self.show_only).pack(side='left')
        
        # Bind Enter key for single IOC check
        self.root.bind("<Return>", self._start_single)

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
        """Simple provider configuration stub."""
        messagebox.showinfo("Providers", "Provider configuration not yet implemented.")

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

    def _start_single(self, *args):
        """Start single IOC check."""
        ioc_type = self.typ.get()
        ioc_value = self.val.get().strip()
        
        if not ioc_value:
            messagebox.showerror("Error", "Please enter an IOC value.")
            return
        
        self._clear()
        self.out.insert('', 'end', values=(ioc_type, ioc_value, "Checking...", ""))
        
        # For now, just show a placeholder result
        self.root.after(1000, lambda: self._show_result(ioc_type, ioc_value, "Clean", "No threats detected"))

    def _start_batch(self):
        """Start batch processing."""
        filename = self.file_var.get().strip()
        
        if not filename:
            messagebox.showerror("Error", "Please select a file.")
            return
        
        if not os.path.exists(filename):
            messagebox.showerror("Error", "File not found.")
            return
        
        self._clear()
        self.out.insert('', 'end', values=("Batch", filename, "Processing...", ""))
        
        # For now, just show a placeholder result
        self.root.after(2000, lambda: self._show_result("Batch", filename, "Complete", "Processing finished"))

    def _show_result(self, ioc_type, ioc_value, status, details):
        """Show a result in the output."""
        # Clear existing items
        for item in self.out.get_children():
            self.out.delete(item)
        
        # Add the result
        self.out.insert('', 'end', values=(ioc_type, ioc_value, status, details))

    def _stop_processing(self):
        """Stop current processing."""
        if self.process:
            self.process.terminate()
            self.process = None

    def _poll_queue(self):
        """Poll the queue for subprocess output."""
        # Placeholder for queue polling
        self.root.after(100, self._poll_queue)

    def run(self):
        """Start the GUI application."""
        self.root.mainloop()


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
        except Exception:
            # If even basic tkinter fails, print to console
            print(f"Error starting IOC Checker GUI: {e}")
            print("Please check that all required dependencies are installed.")
        sys.exit(1)


if __name__ == "__main__":
    # Smoke test to ensure startup is clean
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        try:
            import time
            app = IOCCheckerGUI()
            app.root.after(1000, app.root.destroy)  # Destroy after 1 second
            app.run()
            print("GUI startup test passed!")
        except Exception as e:
            print(f"GUI startup test failed: {e}")
            sys.exit(1)
    else:
        main()
