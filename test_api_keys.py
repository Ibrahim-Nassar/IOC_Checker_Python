# test_api_keys.py
import os
from pathlib import Path
import sys

# Add project directory to path
project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir))

try:
    from dotenv import load_dotenv
    # Load .env file
    load_dotenv()
    dotenv_available = True
except ImportError:
    dotenv_available = False

def test_api_keys():
    """Test if API keys are properly configured."""
    providers = {
        "VirusTotal": os.getenv("VIRUSTOTAL_API_KEY"),
        "AbuseIPDB": os.getenv("ABUSEIPDB_API_KEY"),
        "GreyNoise": os.getenv("GREYNOISE_API_KEY"),
        "Shodan": os.getenv("SHODAN_API_KEY"),
        "Pulsedive": os.getenv("PULSEDIVE_API_KEY")
    }
    
    print("🔑 API Key Configuration Status:")
    print("=" * 40)
    
    configured_count = 0
    for provider, key in providers.items():
        if key and key.strip():
            # Show first 8 characters for verification
            masked_key = key[:8] + "..." if len(key) > 8 else key
            print(f"✅ {provider}: Configured ({masked_key})")
            configured_count += 1
        else:
            print(f"❌ {provider}: Not configured")
    
    print(f"\n📊 Summary: {configured_count}/{len(providers)} providers configured")
    
    # Check .env file status
    env_file = project_dir / ".env"
    print(f"\n📁 Configuration File Status:")
    if env_file.exists():
        print(f"✅ .env file exists: {env_file}")
        # Show file size
        size = env_file.stat().st_size
        print(f"   File size: {size} bytes")
    else:
        print(f"❌ .env file not found: {env_file}")
    
    print(f"\n🐍 Python dotenv support: {'✅ Available' if dotenv_available else '❌ Not installed'}")
    
    # Provide specific guidance
    print(f"\n📝 To fix the 'n/a' VirusTotal issue:")
    if not configured_count:
        print("1. Create a .env file in the project directory")
        print("2. Add: VIRUSTOTAL_API_KEY=your_api_key_here")
        print("3. Get free API key from: https://www.virustotal.com/gui/my-apikey")
        print("4. Restart the application")
    elif not providers["VirusTotal"]:
        print("1. Add VIRUSTOTAL_API_KEY to your .env file")
        print("2. Get free API key from: https://www.virustotal.com/gui/my-apikey")
        print("3. Restart the application")
    else:
        print("✅ VirusTotal API key is configured!")
        print("   If you're still seeing 'n/a', check that the key is valid")

if __name__ == "__main__":
    test_api_keys()
