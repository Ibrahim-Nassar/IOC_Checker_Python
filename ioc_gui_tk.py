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
    'threatfox': 'ThreatFox',
    'urlhaus': 'URLHaus',
    'malwarebazaar': 'MalwareBazaar',
    'greynoise': 'GreyNoise',
    'pulsedive': 'Pulsedive',
    'shodan': 'Shodan'
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
            self.processing = False              # Provider configuration - no providers selected by default
            self.provider_config = {
                'virustotal': False,
                'abuseipdb': False,
                'otx': False,
                'threatfox': False,
                'urlhaus': False,
                'malwarebazaar': False,
                'greynoise': False,
                'pulsedive': False,
                'shodan': False,
            }
              # API key storage (loaded from environment or .env file)
            self.api_keys = {
                'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
                'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', ''),
                'otx': os.getenv('OTX_API_KEY', ''),
                'threatfox': os.getenv('THREATFOX_API_KEY', ''),
                'greynoise': os.getenv('GREYNOISE_API_KEY', ''),
                'pulsedive': os.getenv('PULSEDIVE_API_KEY', ''),
                'shodan': os.getenv('SHODAN_API_KEY', '')
            }
            
            # Define providers with their supported IOC types
            self.providers_info = [
                ("virustotal", "VirusTotal", "VIRUSTOTAL_API_KEY", "Universal threat intelligence platform", ["ip", "domain", "url", "hash"]),
                ("abuseipdb", "AbuseIPDB", "ABUSEIPDB_API_KEY", "IP reputation and abuse reports", ["ip"]),
                ("otx", "AlienVault OTX", "OTX_API_KEY", "Open threat exchange platform", ["ip", "domain", "url", "hash"]),
                ("threatfox", "ThreatFox", "THREATFOX_API_KEY", "Malware IOCs from abuse.ch", ["ip", "domain", "url", "hash"]),
                ("urlhaus", "URLHaus", None, "Malicious URL database (abuse.ch)", ["url"]),
                ("malwarebazaar", "MalwareBazaar", None, "Malware sample database (abuse.ch)", ["hash"]),
                ("greynoise", "GreyNoise", "GREYNOISE_API_KEY", "Internet background noise analysis", ["ip"]),
                ("pulsedive", "Pulsedive", "PULSEDIVE_API_KEY", "Threat intelligence platform", ["ip", "domain", "url"]),
                ("shodan", "Shodan", "SHODAN_API_KEY", "Internet-connected devices search", ["ip"]),
            ]
            
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
        settings_menu.add_command(label="API Keys...", command=self._configure_api_keys)
        settings_menu.add_separator()
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
        self.out = ttk.Treeview(output_frame, columns=('Type', 'IOC', 'Status', 'Flagged By', 'Details'), show='headings', height=15)
        
        # Configure columns
        self.out.heading('Type', text='Type')
        self.out.heading('IOC', text='IOC')
        self.out.heading('Status', text='Status')
        self.out.heading('Flagged By', text='Flagged By')
        self.out.heading('Details', text='Details')
        
        # Set column widths
        self.out.column('Type', width=80)
        self.out.column('IOC', width=200)
        self.out.column('Status', width=100)
        self.out.column('Flagged By', width=150)
        self.out.column('Details', width=200)
        
        self.out.pack(fill='both', expand=True)
          # Options
        options_frame = ttk.Frame(main)
        options_frame.grid(row=6, column=0, sticky="ew")
        
        ttk.Checkbutton(options_frame, text="Show only threats & errors", 
                       variable=self.show_only).pack(side='left')
        
        # Add Providers button
        ttk.Button(options_frame, text="Providers", command=self.show_providers_info).pack(side='right')
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
        
        # Create main frame
        main_frame = ttk.Frame(config_win)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        # Title
        title_label = ttk.Label(main_frame, text="Select Threat Intelligence Providers", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 10))
        
        # Instructions
        instruction_label = ttk.Label(main_frame, 
                                    text="Choose which providers to use for IOC checking:",
                                    font=("Arial", 11))
        instruction_label.pack(pady=(0, 15))
        
        # Filter frame
        filter_frame = ttk.LabelFrame(main_frame, text="Filter by IOC Type", padding=10)
        filter_frame.pack(fill="x", pady=(0, 15))
        
        # Filter variables
        self.filter_var = tk.StringVar(value="all")
        
        # Filter radio buttons
        filter_options_frame = ttk.Frame(filter_frame)
        filter_options_frame.pack(fill="x")
        
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
        
        # Provider selection frame with scrollbar
        provider_frame = ttk.LabelFrame(main_frame, text="Available Providers", padding=10)
        provider_frame.pack(fill="both", expand=True, pady=(0, 15))
        
        # Create canvas and scrollbar for providers
        canvas = tk.Canvas(provider_frame, height=300)
        scrollbar = ttk.Scrollbar(provider_frame, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
          # Store canvas reference for filtering
        self.provider_canvas = canvas
        
        # Store checkbox variables
        self.provider_vars = {}
        self.provider_frames = {}
        
        # Create provider checkboxes
        self._create_provider_checkboxes()
        
        # Status message
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill="x", pady=(10, 15))
        
        self.status_label = ttk.Label(status_frame, 
                                    text="✗ = No API key configured, ✓ = API key available",
                                    font=("Arial", 10), foreground="gray")
        self.status_label.pack()
        
        # Button frame
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack()
        
        def save_selection():
            """Save the provider selection."""
            # Update provider configuration
            for provider_id, var in self.provider_vars.items():
                self.provider_config[provider_id] = var.get()
            
            # Show confirmation
            enabled_providers = [pid for pid, enabled in self.provider_config.items() if enabled]
            if enabled_providers:
                provider_names = []
                for provider_id in enabled_providers:
                    provider_info = next((p for p in self.providers_info if p[0] == provider_id), None)
                    if provider_info:
                        provider_names.append(provider_info[1])
                
                messagebox.showinfo("Providers Updated", 
                                  f"Selected providers: {', '.join(provider_names)}")
            else:
                messagebox.showinfo("No Providers Selected", 
                                  "No providers are currently selected. You will be prompted to select providers when checking IOCs.")
            
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
                        if env_var is None or (os.getenv(env_var) and os.getenv(env_var).strip()):
                            var.set(True)
        
        def clear_all():
            """Clear all provider selections."""
            for var in self.provider_vars.values():
                var.set(False)
        
        # Arrange buttons
        ttk.Button(btn_frame, text="Select Filtered", command=select_filtered).pack(side="left", padx=(0, 10))
        ttk.Button(btn_frame, text="Clear All", command=clear_all).pack(side="left", padx=(0, 20))
        ttk.Button(btn_frame, text="Save", command=save_selection).pack(side="left", padx=(0, 10))
        ttk.Button(btn_frame, text="Cancel", command=config_win.destroy).pack(side="left")
    
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

    def _start_single(self, *args):
        """Start single IOC check."""
        ioc_type = self.typ.get()
        ioc_value = self.val.get().strip()
        
        if not ioc_value:
            messagebox.showerror("Error", "Please enter an IOC value.")
            return
        
        # Check if providers need to be selected
        if not self._prompt_provider_selection_if_needed():
            return
        
        # Get selected providers after potential dialog
        selected_providers = [provider for provider, enabled in self.provider_config.items() if enabled]
        
        self._clear()
        self.out.insert('', 'end', values=(ioc_type, ioc_value, "Checking...", ""))
        self.root.update()
          # Start checking in a separate thread
        def run_single_check():
            try:
                # Import here to avoid circular imports
                from ioc_checker import check_single_ioc
                
                # Run the check with selected providers
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    check_single_ioc(ioc_value, ioc_type, selected_providers=selected_providers)
                )
                loop.close()
                
                # Extract information for display
                status = result.get('overall_verdict', 'unknown').title()
                flagged_by = result.get('flagged_by_text', '')
                summary = result.get('summary', 'No additional details')
                
                # Update GUI on main thread
                self.root.after(0, lambda: self._show_result(ioc_type, ioc_value, status, summary, flagged_by))
                
            except Exception as e:
                # Update GUI with error on main thread
                self.root.after(0, lambda: self._show_result(ioc_type, ioc_value, "Error", str(e), ""))
        
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
                    
                except Exception as e:
                    # Update GUI with error on main thread
                    self.root.after(0, lambda: self._batch_error(str(e)))
            
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

    def _show_result(self, ioc_type, ioc_value, status, details, flagged_by=""):
        """Show a result in the output."""
        # Clear existing items
        for item in self.out.get_children():
            self.out.delete(item)
        
        # Add the result with the new flagged_by column
        self.out.insert('', 'end', values=(ioc_type, ioc_value, status, flagged_by, details))

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


    def _configure_api_keys(self):
        """Open API key configuration dialog."""
        # Create new window
        config_window = tk.Toplevel(self.root)
        config_window.title("API Key Configuration")
        config_window.geometry("600x500")
        config_window.transient(self.root)
        config_window.grab_set()
        
        # Center the window
        config_window.geometry("+%d+%d" % (
            self.root.winfo_rootx() + 50,
            self.root.winfo_rooty() + 50
        ))
        
        # Main frame
        main_frame = ttk.Frame(config_window, padding=20)
        main_frame.pack(fill="both", expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="API Key Configuration", 
                               font=("TkDefaultFont", 12, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Description
        desc_text = """Enter your API keys below. Get free API keys from:
• VirusTotal: https://www.virustotal.com/gui/my-apikey
• AbuseIPDB: https://www.abuseipdb.com/register
• Others are optional for enhanced analysis"""
        
        desc_label = ttk.Label(main_frame, text=desc_text, justify="left")
        desc_label.pack(pady=(0, 20), anchor="w")
        
        # API key entries
        self.api_key_vars = {}
        entries_frame = ttk.Frame(main_frame)
        entries_frame.pack(fill="x", pady=(0, 20))        
        api_key_configs = [
            ("virustotal", "VirusTotal", "Required for malware/URL analysis"),
            ("abuseipdb", "AbuseIPDB", "Required for IP reputation"),
            ("otx", "AlienVault OTX", "Optional - Open threat exchange"),
            ("threatfox", "ThreatFox", "Optional - Malware IOCs from abuse.ch"),
            ("greynoise", "GreyNoise", "Optional - Advanced IP analysis"),
            ("pulsedive", "Pulsedive", "Optional - Threat intelligence platform"),
            ("shodan", "Shodan", "Optional - Infrastructure analysis"),
        ]
        
        # Note about free services
        note_frame = ttk.Frame(entries_frame)
        note_frame.pack(fill="x", pady=(0, 10))
        
        note_text = "Note: URLHaus and MalwareBazaar (abuse.ch) are free services that don't require API keys."
        note_label = ttk.Label(note_frame, text=note_text, font=("TkDefaultFont", 8), 
                              foreground="blue", wraplength=550)
        note_label.pack(anchor="w")
        
        for i, (key, name, desc) in enumerate(api_key_configs):
            # Label frame for each API key
            frame = ttk.LabelFrame(entries_frame, text=f"{name} API Key", padding=10)
            frame.pack(fill="x", pady=5)
            
            # Description
            desc_label = ttk.Label(frame, text=desc, font=("TkDefaultFont", 8))
            desc_label.pack(anchor="w")
            
            # Entry field
            self.api_key_vars[key] = tk.StringVar(value=self.api_keys.get(key, ''))
            entry = ttk.Entry(frame, textvariable=self.api_key_vars[key], 
                             width=60, show="*" if self.api_key_vars[key].get() else "")
            entry.pack(fill="x", pady=(5, 0))
            
            # Show/Hide button for the entry
            def toggle_visibility(entry_widget, var_name):
                current_show = entry_widget.cget("show")
                if current_show == "*":
                    entry_widget.config(show="")
                else:
                    entry_widget.config(show="*")
            
            show_btn = ttk.Button(frame, text="Show/Hide", 
                                 command=lambda e=entry: toggle_visibility(e, key))
            show_btn.pack(anchor="e", pady=(2, 0))
        
        # Status frame
        status_frame = ttk.Frame(main_frame)
        status_frame.pack(fill="x", pady=(0, 20))
        
        status_label = ttk.Label(status_frame, text="Current Status:")
        status_label.pack(anchor="w")
        
        # Show current API key status
        status_text = tk.Text(status_frame, height=6, width=60, state="disabled")
        status_text.pack(fill="x")
        
        def update_status():
            status_text.config(state="normal")
            status_text.delete(1.0, tk.END)
            
            for key, name, _ in api_key_configs:
                current_key = self.api_keys.get(key, '')
                if current_key and current_key.strip():
                    status_text.insert(tk.END, f"✅ {name}: Configured\n")
                else:
                    status_text.insert(tk.END, f"❌ {name}: No API key\n")
            
            status_text.config(state="disabled")
        
        update_status()
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.pack(fill="x")
        
        def save_keys():
            """Save API keys and update environment."""
            # Update internal storage
            for key in self.api_key_vars:
                new_value = self.api_key_vars[key].get().strip()
                self.api_keys[key] = new_value
                # Update environment variable for current session
                if new_value:
                    os.environ[f"{key.upper()}_API_KEY"] = new_value
                else:
                    os.environ.pop(f"{key.upper()}_API_KEY", None)
            
            # Try to save to .env file
            try:
                self._save_env_file()
                messagebox.showinfo("Success", 
                    "API keys saved successfully!\n\n"
                    "Keys are now active for this session and saved to .env file.")
            except Exception as e:
                messagebox.showwarning("Partial Success", 
                    f"API keys updated for this session, but couldn't save to .env file:\n{e}\n\n"
                    "Keys will be lost when the application restarts.")
            
            update_status()
        
        def test_keys():
            """Test API key validity."""
            messagebox.showinfo("Test API Keys", 
                "API key testing will be implemented in a future update.\n\n"
                "For now, try running a scan to see if the keys work.")
        
        ttk.Button(buttons_frame, text="Save", command=save_keys).pack(side="left", padx=(0, 10))
        ttk.Button(buttons_frame, text="Test Keys", command=test_keys).pack(side="left", padx=(0, 10))
        ttk.Button(buttons_frame, text="Cancel", command=config_window.destroy).pack(side="right")
    
    def _save_env_file(self):
        """Save API keys to .env file."""
        env_path = os.path.join(os.path.dirname(__file__), '.env')
        
        # Read existing .env file if it exists
        existing_lines = []
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                existing_lines = f.readlines()
        
        # Update or add API key lines
        api_key_lines = {}
        for key, value in self.api_keys.items():
            env_var = f"{key.upper()}_API_KEY"
            if value and value.strip():
                api_key_lines[env_var] = f"{env_var}={value}\n"
            else:
                api_key_lines[env_var] = f"# {env_var}=\n"
        
        # Merge with existing lines (preserve non-API key settings)
        final_lines = []
        used_keys = set()
        
        for line in existing_lines:
            line_upper = line.strip().upper()
            # Check if this line is for an API key we're managing
            is_api_key_line = any(key in line_upper for key in api_key_lines.keys())
            
            if is_api_key_line:
                # Find which API key this line is for
                for env_var, new_line in api_key_lines.items():
                    if env_var in line_upper:
                        final_lines.append(new_line)
                        used_keys.add(env_var)
                        break
            else:
                # Keep non-API key lines as is
                final_lines.append(line)
        
        # Add any new API keys that weren't in the existing file
        for env_var, new_line in api_key_lines.items():
            if env_var not in used_keys:
                final_lines.append(new_line)
        
        # Write the updated .env file
        with open(env_path, 'w') as f:
            f.writelines(final_lines)

    def _prompt_provider_selection_if_needed(self):
        """Prompt user to select providers if none are currently selected."""
        selected_providers = [provider for provider, enabled in self.provider_config.items() if enabled]
        
        if not selected_providers:
            # Show dialog asking user to select providers
            result = messagebox.askyesno(
                "No Providers Selected",
                "No threat intelligence providers are selected.\n\n"
                "Would you like to select providers now?\n\n"
                "Click 'Yes' to choose providers, or 'No' to cancel the check."
            )
            
            if result:
                # Open provider selection dialog
                self.show_providers_info()
                
                # Check again after dialog closes
                selected_providers = [provider for provider, enabled in self.provider_config.items() if enabled]
                if not selected_providers:
                    messagebox.showwarning("No Providers Selected", 
                                         "No providers were selected. IOC check cancelled.")
                    return False
                return True
            else:
                return False
        
        return True

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
