# Quick test of batch processing with the test URLs
import asyncio
import sys
import pathlib
import os

# Add the project directory to sys.path to import modules
project_dir = pathlib.Path(__file__).parent
sys.path.insert(0, str(project_dir))

from ioc_checker import batch_check_indicators
from loader import load_iocs

async def test_batch_with_file():
    """Test batch processing with the test URLs file."""
    print("🧪 Testing Batch Processing with URLs File")
    print("=" * 45)
    
    test_file = "test_urls.txt"
    
    if not os.path.exists(test_file):
        print(f"❌ Test file {test_file} not found")
        return
    
    print(f"Loading IOCs from {test_file}...")
    
    try:
        # Load IOCs using the same method as GUI (convert to Path object)
        iocs = load_iocs(pathlib.Path(test_file))
        print(f"✓ Loaded {len(iocs)} IOCs:")
        for ioc in iocs:
            print(f"  - {ioc.get('value', str(ioc))} ({ioc.get('type', 'unknown')})")
        
        # Extract just the values
        ioc_values = [ioc.get('value', str(ioc)) for ioc in iocs]
        
        print(f"\nProcessing {len(ioc_values)} IOCs...")
        
        # Test with safe providers (no API keys needed)
        selected_providers = ['virustotal', 'abuseipdb'] 
        
        # Remove existing results.csv
        if os.path.exists("results.csv"):
            os.remove("results.csv")
            print("Removed existing results.csv")
        
        # Run batch processing
        await batch_check_indicators(ioc_values, rate=False, selected_providers=selected_providers)
        
        # Check if CSV was created
        if os.path.exists("results.csv"):
            print(f"\n✅ SUCCESS! Results written to results.csv")
            
            # Show CSV content
            import csv
            with open("results.csv", newline="", encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                rows = list(reader)
                print(f"\nCSV contains {len(rows)} rows:")
                if rows:
                    print(f"Headers: {', '.join(rows[0])}")
                    for i, row in enumerate(rows[1:], 1):
                        if i <= 3:  # Show first 3 rows
                            indicator = row[0] if row else "N/A"
                            print(f"Row {i}: {indicator}")
        else:
            print(f"\n❌ No results.csv file was created")
            
    except Exception as e:
        print(f"❌ Error during batch processing: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_batch_with_file())
