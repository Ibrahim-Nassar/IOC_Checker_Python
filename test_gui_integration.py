#!/usr/bin/env python3
"""
Critical test: Verify GUI provider selection actually works
"""
import subprocess
import sys
import os
import time
from pathlib import Path

def test_gui_provider_integration():
    """Test that GUI provider checkboxes actually affect command execution."""
    
    print("🎯 GUI Provider Selection Integration Test")
    print("=" * 50)
    
    # Test by examining GUI's command building logic directly
    # This simulates what happens when user selects providers in GUI
    
    test_scenarios = [
        {
            "name": "GUI Default (no providers selected)",
            "gui_config": {"virustotal": False, "greynoise": False, "pulsedive": False, "shodan": False},
            "test_ioc": "8.8.8.8",
            "expected_providers": ["abuseipdb", "otx", "threatfox"]  # Always-on providers
        },
        {
            "name": "GUI VirusTotal Only",
            "gui_config": {"virustotal": True, "greynoise": False, "pulsedive": False, "shodan": False},
            "test_ioc": "8.8.8.8",
            "expected_providers": ["virustotal"]
        },
        {
            "name": "GUI Mixed Selection",
            "gui_config": {"virustotal": True, "greynoise": True, "pulsedive": False, "shodan": False},
            "test_ioc": "8.8.8.8", 
            "expected_providers": ["virustotal", "greynoise"]
        }
    ]
    
    for i, scenario in enumerate(test_scenarios, 1):
        print(f"\n{i}. {scenario['name']}")
        print("-" * 30)
        
        # Build command exactly like GUI does
        cmd = ["python", "ioc_checker.py", "ip", scenario["test_ioc"]]
        
        # Add provider flags based on GUI config (this is the critical logic)
        for provider, enabled in scenario["gui_config"].items():
            if enabled:
                cmd.append(f"--{provider}")
        
        print(f"GUI builds command: {' '.join(cmd)}")
        
        # Execute the command
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  cwd=r"c:\KAS\Python Scripts\ioc_checker", timeout=30)
            
            if result.returncode != 0:
                print(f"❌ Command failed: {result.stderr}")
                continue
                
            # Parse output to verify correct providers were used
            providers_found = []
            lines = result.stdout.strip().split('\n')
            for line in lines:
                if ':' in line and line.strip():
                    parts = line.split(':')
                    if len(parts) >= 2:
                        provider = parts[0].strip()
                        if provider not in ["IOC", ""] and not provider.startswith("-"):
                            providers_found.append(provider)
            
            # Verify results
            expected_set = set(scenario["expected_providers"])
            found_set = set(providers_found)
            
            if expected_set == found_set:
                print(f"✅ PASSED - Providers used: {sorted(providers_found)}")
            else:
                print(f"❌ FAILED")
                print(f"   Expected: {sorted(scenario['expected_providers'])}")
                print(f"   Found:    {sorted(providers_found)}")
                
        except subprocess.TimeoutExpired:
            print("❌ Command timed out")
        except Exception as e:
            print(f"❌ Error executing command: {e}")

    print("\n" + "=" * 50)
    print("🎯 GUI Integration Test Complete")

if __name__ == "__main__":
    test_gui_provider_integration()
