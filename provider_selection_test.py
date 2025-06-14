#!/usr/bin/env python3
"""
Test script to validate provider selection functionality.
"""
import subprocess
import sys
import json

def run_command(cmd):
    """Run command and return stdout/stderr."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        return result.stdout, result.stderr, result.returncode
    except Exception as e:
        return "", str(e), 1

def test_provider_selection():
    """Test various provider selection scenarios."""
    
    test_cases = [
        {
            "name": "Default behavior (always-on providers only)",
            "cmd": "python ioc_checker.py ip 8.8.8.8",
            "expected_providers": ["abuseipdb", "otx", "threatfox"]
        },
        {
            "name": "Rate flag (all providers)",
            "cmd": "python ioc_checker.py ip 8.8.8.8 --rate", 
            "expected_providers": ["abuseipdb", "otx", "threatfox", "virustotal", "greynoise", "pulsedive", "shodan"]
        },
        {
            "name": "Only VirusTotal",
            "cmd": "python ioc_checker.py ip 8.8.8.8 --virustotal",
            "expected_providers": ["virustotal"]
        },
        {
            "name": "VirusTotal + GreyNoise",
            "cmd": "python ioc_checker.py ip 8.8.8.8 --virustotal --greynoise",
            "expected_providers": ["virustotal", "greynoise"]
        },
        {
            "name": "All rate-limited providers",
            "cmd": "python ioc_checker.py ip 8.8.8.8 --virustotal --greynoise --pulsedive --shodan",
            "expected_providers": ["virustotal", "greynoise", "pulsedive", "shodan"]
        }
    ]
    
    print("🧪 Testing Provider Selection Functionality\n")
    print("=" * 60)
    
    for i, test in enumerate(test_cases, 1):
        print(f"\n{i}. {test['name']}")
        print("-" * 40)
        
        stdout, stderr, returncode = run_command(test["cmd"])
        
        if returncode != 0:
            print(f"❌ Command failed: {stderr}")
            continue
            
        # Parse output to get providers used
        lines = stdout.strip().split('\n')
        providers_found = []
        for line in lines:
            if ':' in line and line.strip():
                # Look for lines like "virustotal  : Clean"
                parts = line.split(':')
                if len(parts) >= 2:
                    provider = parts[0].strip()
                    if provider not in ["IOC", ""] and not provider.startswith("-"):
                        providers_found.append(provider)
        
        # Check if expected providers match found providers
        expected_set = set(test["expected_providers"])
        found_set = set(providers_found)
        
        if expected_set == found_set:
            print(f"✅ PASSED - Found providers: {sorted(providers_found)}")
        else:
            print(f"❌ FAILED")
            print(f"   Expected: {sorted(test['expected_providers'])}")
            print(f"   Found:    {sorted(providers_found)}")
            
            # Show what's missing or extra
            missing = expected_set - found_set
            extra = found_set - expected_set
            if missing:
                print(f"   Missing:  {sorted(missing)}")
            if extra:
                print(f"   Extra:    {sorted(extra)}")

    print("\n" + "=" * 60)
    print("🎯 Provider Selection Test Complete")

if __name__ == "__main__":
    test_provider_selection()
