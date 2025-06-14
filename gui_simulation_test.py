#!/usr/bin/env python3
"""
Quick GUI provider selection demonstration.
This script simulates GUI provider selection behavior.
"""
import subprocess
import os

def simulate_gui_provider_selection():
    """Simulate what the GUI does when providers are selected."""
    
    print("🖥️  GUI Provider Selection Simulation")
    print("=" * 50)
    
    # Simulate GUI configuration
    gui_configs = [
        {
            "name": "No providers selected (default)",
            "config": {"virustotal": False, "greynoise": False, "pulsedive": False, "shodan": False},
            "expected_cmd": ["python", "ioc_checker.py", "ip", "8.8.8.8"]
        },
        {
            "name": "Only VirusTotal selected",
            "config": {"virustotal": True, "greynoise": False, "pulsedive": False, "shodan": False},
            "expected_cmd": ["python", "ioc_checker.py", "ip", "8.8.8.8", "--virustotal"]
        },
        {
            "name": "VirusTotal + GreyNoise selected", 
            "config": {"virustotal": True, "greynoise": True, "pulsedive": False, "shodan": False},
            "expected_cmd": ["python", "ioc_checker.py", "ip", "8.8.8.8", "--virustotal", "--greynoise"]
        },
        {
            "name": "All providers selected",
            "config": {"virustotal": True, "greynoise": True, "pulsedive": True, "shodan": True},
            "expected_cmd": ["python", "ioc_checker.py", "ip", "8.8.8.8", "--virustotal", "--greynoise", "--pulsedive", "--shodan"]
        }
    ]
    
    for i, test in enumerate(gui_configs, 1):
        print(f"\n{i}. {test['name']}")
        print("-" * 30)
        
        # Build command like GUI does
        cmd = ["python", "ioc_checker.py", "ip", "8.8.8.8"]
        
        # Add individual provider flags based on GUI selection
        for provider, enabled in test["config"].items():
            if enabled:
                cmd.append(f"--{provider}")
        
        print(f"Command built: {' '.join(cmd)}")
        print(f"Expected:      {' '.join(test['expected_cmd'])}")
        
        if cmd == test["expected_cmd"]:
            print("✅ Command building: CORRECT")
        else:
            print("❌ Command building: INCORRECT")
            
        # Actually run the command to see provider results
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, cwd=r"c:\KAS\Python Scripts\ioc_checker")
            if result.returncode == 0:
                # Parse providers from output
                lines = result.stdout.strip().split('\n')
                providers_used = []
                for line in lines:
                    if ':' in line and line.strip():
                        parts = line.split(':')
                        if len(parts) >= 2:
                            provider = parts[0].strip()
                            if provider not in ["IOC", ""] and not provider.startswith("-"):
                                providers_used.append(provider)
                
                print(f"Providers used: {sorted(providers_used)}")
                print("✅ Execution: SUCCESS")
            else:
                print(f"❌ Execution failed: {result.stderr}")
                
        except Exception as e:
            print(f"❌ Execution error: {e}")

    print("\n" + "=" * 50)
    print("🎯 GUI Provider Selection Simulation Complete")

if __name__ == "__main__":
    simulate_gui_provider_selection()
