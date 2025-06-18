# Test the batch processing functionality directly
import asyncio
import sys
import pathlib

# Add the project directory to sys.path to import modules
project_dir = pathlib.Path(__file__).parent
sys.path.insert(0, str(project_dir))

from ioc_checker import batch_check_indicators
from loader import load_iocs

async def test_batch_from_file():
    """Test batch processing by loading IOCs from a file."""
    print("🧪 Testing batch processing from file...")
    
    # Load IOCs from our test file
    test_file = "test_malicious_urls.txt"
    
    try:
        iocs = load_iocs(test_file)
        print(f"Loaded {len(iocs)} IOCs from {test_file}")
        
        # Extract just the values
        ioc_values = [ioc.get('value', str(ioc)) for ioc in iocs]
        print(f"IOC values: {ioc_values}")
        
        # Process them
        print("Starting batch processing...")
        await batch_check_indicators(ioc_values, rate=False, selected_providers=['virustotal', 'abuseipdb'])
        
        print("✅ Batch processing completed!")
        
        # Check if CSV was created
        import os
        if os.path.exists("results.csv"):
            print(f"✅ CSV file created: {os.path.abspath('results.csv')}")
            
            # Show content preview
            with open("results.csv", "r", encoding="utf-8-sig") as f:
                lines = f.readlines()
                print(f"CSV has {len(lines)} lines:")
                for i, line in enumerate(lines[:5]):  # Show first 5 lines
                    print(f"  Line {i+1}: {line.strip()}")
        else:
            print("❌ No CSV file was created")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(test_batch_from_file())
