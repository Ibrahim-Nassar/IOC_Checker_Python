# Test batch checking functionality
import asyncio
import sys
import pathlib

# Add the project directory to sys.path to import modules
project_dir = pathlib.Path(__file__).parent
sys.path.insert(0, str(project_dir))

from ioc_checker import batch_check_indicators

async def test_batch_check():
    """Test the batch checking functionality with sample IOCs."""
    print("Testing batch check functionality...")
    
    # Sample IOCs to test (using known safe examples)
    test_indicators = [
        "8.8.8.8",  # Google DNS
        "1.1.1.1",  # Cloudflare DNS  
        "example.com"  # Example domain
    ]
    
    print(f"Processing {len(test_indicators)} test indicators...")
    await batch_check_indicators(test_indicators, rate=False)
    print("Batch check test completed.")

if __name__ == "__main__":
    asyncio.run(test_batch_check())
