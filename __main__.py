#!/usr/bin/env python3
"""
IOC Checker Package Entry Point

This allows running the package with:
    python -m IOC_Checker_Python          # Runs GUI by default
    python -m IOC_Checker_Python cli      # Runs CLI
    python -m IOC_Checker_Python gui      # Runs GUI explicitly
"""

import sys
import os

# Only add to path if running as a script (not installed package)
if __name__ == "__main__" and not hasattr(sys, '_called_from_test'):
    # Add the IOC_Checker_Python directory to Python path for imports
    sys.path.insert(0, os.path.dirname(__file__))

def main():
    # Check for help requests
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print("IOC Checker - Threat Intelligence Scanner")
        print()
        print("Usage:")
        print("  python -m IOC_Checker_Python           # Launch GUI (default)")
        print("  python -m IOC_Checker_Python gui       # Launch GUI explicitly") 
        print("  python -m IOC_Checker_Python cli       # Launch CLI mode")
        print("  python -m IOC_Checker_Python cli --help  # CLI help")
        print()
        print("Examples:")
        print("  python -m IOC_Checker_Python")
        print("  python -m IOC_Checker_Python cli 9.9.9.9 --type ip")
        return
    
    # Check if first argument is 'cli'
    if len(sys.argv) > 1 and sys.argv[1] == "cli":
        # Remove 'cli' from argv and run the CLI with remaining args
        sys.argv = [sys.argv[0]] + sys.argv[2:]
        from ioc_checker import main as cli_main
        cli_main()
    elif len(sys.argv) > 1 and sys.argv[1] == "gui":
        # Explicit GUI mode
        from ioc_gui_tk import run_gui
        run_gui()
    elif len(sys.argv) == 1:
        # Default to GUI mode when no arguments
        from ioc_gui_tk import run_gui
        run_gui()
    else:
        # Unknown argument
        print(f"Unknown argument: {sys.argv[1]}")
        print("Use --help for usage information")
        sys.exit(1)

if __name__ == "__main__":
    main() 