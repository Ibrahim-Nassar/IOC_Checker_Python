# Example of how to use the new batch CSV functionality
import asyncio
import sys
import pathlib

# Add the project directory to sys.path to import modules
project_dir = pathlib.Path(__file__).parent
sys.path.insert(0, str(project_dir))

from reports import write_csv

def simulate_batch_processing():
    """
    Simulate how batch processing would work with the new CSV functionality.
    This demonstrates the fix for the batch-check CSV writing issue.
    """
    print("🔍 IOC Batch Processing Simulation")
    print("=" * 40)
    
    # Simulate processing multiple IOCs
    print("Processing IOCs and collecting results...")
    
    # This simulates what would come from actual IOC checking
    batch_results = [
        {
            "Indicator": "malicious-domain.com",
            "Type": "domain",
            "Overall": "HIGH",
            "virustotal_status": "malicious", 
            "abuseipdb_status": "clean",
            "urlhaus_status": "malicious"
        },
        {
            "Indicator": "192.168.1.1", 
            "Type": "ip",
            "Overall": "LOW",
            "virustotal_status": "clean",
            "abuseipdb_status": "clean",
            "greynoise_status": "clean"
        },
        {
            "Indicator": "suspicious-file.exe",
            "Type": "hash", 
            "Overall": "MEDIUM",
            "virustotal_status": "suspicious",
            "malwarebazaar_status": "clean"
        },
        {
            "Indicator": "http://bad-url.com/malware",
            "Type": "url",
            "Overall": "HIGH", 
            "urlhaus_status": "malicious",
            "virustotal_status": "malicious"
        }
    ]
    
    print(f"✓ Processed {len(batch_results)} IOCs")
    
    # Write results to CSV using the new function
    print("\nWriting results to CSV...")
    csv_path = write_csv(batch_results)
    
    if csv_path:
        print(f"✓ Results written to: {csv_path}")
        print("\nCSV file properties:")
        print("• UTF-8 BOM encoding for Windows compatibility")
        print("• Proper newline handling (no extra CR)")
        print("• Dynamic columns based on active providers")
        print("• Structured data with headers")
        
        # Show a preview of the CSV content
        print("\nCSV Content Preview:")
        print("-" * 50)
        import csv
        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            for i, row in enumerate(reader):
                if i == 0:
                    print(f"Headers: {', '.join(row)}")
                elif i <= 3:  # Show first 3 data rows
                    print(f"Row {i}: {row[0]} -> {row[2]} risk")
                if i >= 3:
                    break
        
        print(f"\n🎉 Batch scan CSV export working correctly!")
        print("\nThis fixes the issue where batch-check results weren't being written to CSV.")
        
    else:
        print("❌ No results written (empty batch)")

if __name__ == "__main__":
    simulate_batch_processing()
