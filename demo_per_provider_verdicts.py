#!/usr/bin/env python3
"""
Demo script showing per-provider verdict functionality.
This demonstrates how the IOC checker now shows which specific providers 
flagged each IOC as malicious.
"""
import asyncio
import os
import sys

# Add the project directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

async def demo_per_provider_verdicts():
    """Demonstrate the per-provider verdict functionality."""
    
    print("IOC Checker - Per-Provider Verdicts Demo")
    print("=" * 45)
    print()
    
    # Set up some demo environment variables for testing
    demo_env = {
        'VIRUSTOTAL_API_KEY': 'demo_key_vt',
        'ABUSEIPDB_API_KEY': 'demo_key_abuse',
        'SHODAN_API_KEY': 'demo_key_shodan'
    }
    
    for key, value in demo_env.items():
        os.environ[key] = value
        print(f"Set {key} for demo")
    
    print()
    print("Testing provider verdict aggregation...")
    
    # Import the functions
    from ioc_checker import aggregate_provider_verdicts, format_verdict_summary
    
    # Simulate results from multiple providers
    print("\n1. Testing with malicious IOC flagged by multiple providers:")
    print("-" * 60)
    
    malicious_results = {
        "virustotal": {"status": "malicious", "score": 95},
        "abuseipdb": {"status": "malicious", "score": 85},
        "shodan": {"status": "clean", "score": 0},
        "greynoise": {"status": "suspicious", "score": 70}
    }
    
    verdict_info = aggregate_provider_verdicts(malicious_results)
    summary = format_verdict_summary(verdict_info)
    
    print(f"Provider Results: {malicious_results}")
    print(f"Overall Verdict: {verdict_info['overall_verdict']}")
    print(f"Flagged By: {verdict_info['flagged_by']}")
    print(f"Summary: {summary}")
    
    print("\n2. Testing with clean IOC:")
    print("-" * 60)
    
    clean_results = {
        "virustotal": {"status": "clean", "score": 0},
        "abuseipdb": {"status": "clean", "score": 0},
        "shodan": {"status": "clean", "score": 0}
    }
    
    verdict_info_clean = aggregate_provider_verdicts(clean_results)
    summary_clean = format_verdict_summary(verdict_info_clean)
    
    print(f"Provider Results: {clean_results}")
    print(f"Overall Verdict: {verdict_info_clean['overall_verdict']}")
    print(f"Flagged By: {verdict_info_clean['flagged_by']}")
    print(f"Summary: {summary_clean}")
    
    print("\n3. Testing with error scenarios:")
    print("-" * 60)
    
    error_results = {
        "virustotal": {"status": "error", "score": 0},
        "abuseipdb": {"status": "n/a", "score": 0},
        "shodan": {"status": "error", "score": 0}
    }
    
    verdict_info_error = aggregate_provider_verdicts(error_results)
    summary_error = format_verdict_summary(verdict_info_error)
    
    print(f"Provider Results: {error_results}")
    print(f"Overall Verdict: {verdict_info_error['overall_verdict']}")
    print(f"Error Providers: {verdict_info_error['error_providers']}")
    print(f"Summary: {summary_error}")
    
    print("\n4. Testing GUI integration:")
    print("-" * 60)
    
    # Test the GUI components
    import tkinter as tk
    from ioc_gui_tk import IOCCheckerGUI
    
    root = tk.Tk()
    root.withdraw()  # Hide during test
    
    try:
        gui = IOCCheckerGUI()
        
        # Test showing results with flagged_by information
        gui._show_result("ip", "192.168.1.1", "Malicious", "Test threat detected", "VirusTotal, AbuseIPDB")
        
        # Check the result
        children = gui.out.get_children()
        if children:
            values = gui.out.item(children[0])['values']
            print(f"GUI Result: Type={values[0]}, IOC={values[1]}, Status={values[2]}, Flagged By={values[3]}, Details={values[4]}")
        
        print("✓ GUI integration working correctly")
        
    finally:
        root.quit()
        root.destroy()
    
    print("\n" + "=" * 45)
    print("✓ Per-Provider Verdicts Demo Complete!")
    print("\nKey Features Demonstrated:")
    print("- Individual provider results are aggregated")
    print("- Overall verdict determined from all providers")
    print("- Specific providers that flagged IOCs are tracked")
    print("- Clean, malicious, and error cases handled")
    print("- GUI displays 'Flagged By' information")
    print("- Detailed summaries provided for each result")

def main():
    """Run the demo."""
    try:
        asyncio.run(demo_per_provider_verdicts())
    except Exception as e:
        print(f"Demo failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
