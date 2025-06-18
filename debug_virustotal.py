# Debug the VirusTotal "n/a" issue by showing what's happening behind the scenes
import asyncio
import sys
import pathlib

# Add the project directory to sys.path
project_dir = pathlib.Path(__file__).parent
sys.path.insert(0, str(project_dir))

from providers import VirusTotal

async def debug_virustotal():
    """Debug what's happening with VirusTotal when API key is missing."""
    print("🔍 Debugging VirusTotal 'n/a' Issue")
    print("=" * 40)
    
    # Create VirusTotal provider instance
    vt = VirusTotal()
    
    print(f"Provider name: {vt.name}")
    print(f"Supported IOC types: {vt.ioc_kinds}")
    print(f"API key configured: {'Yes' if vt.key else 'No'}")
    print(f"API key value: {repr(vt.key)}")
    
    # Test with a sample URL
    test_url = "https://example.com"
    print(f"\nTesting with URL: {test_url}")
    
    import aiohttp
    async with aiohttp.ClientSession() as session:
        # This will call the raw query method
        raw_response = await vt._raw_query(session, "url", test_url)
        print(f"Raw response: {repr(raw_response)}")
        
        # This will parse the response
        parsed_response = await vt.query(session, "url", test_url)
        print(f"Parsed response: {parsed_response}")
    
    print(f"\n💡 Explanation:")
    if not vt.key:
        print("❌ No API key found in environment variable VIRUSTOTAL_API_KEY")
        print("   → Raw response: 'nokey'")
        print("   → Parsed status: 'n/a'")
        print("\n✅ Solution:")
        print("1. Get free VirusTotal API key from: https://www.virustotal.com/gui/my-apikey")
        print("2. Create .env file with: VIRUSTOTAL_API_KEY=your_key_here")
        print("3. Restart the application")
    else:
        print("✅ API key is configured")
        print("   If still getting 'n/a', the key might be invalid or there's an API error")

if __name__ == "__main__":
    asyncio.run(debug_virustotal())
