# 🔑 API Key Configuration Guide

## Why VirusTotal Shows "n/a"

The VirusTotal results show "n/a" because **no API key is configured**. Without an API key, the IOC checker cannot make requests to the VirusTotal API.

## Required API Keys

The IOC checker supports several providers that require API keys:

### 1. **VirusTotal** (Recommended)
- **Free tier**: 4 requests/minute, 500 requests/day
- **Sign up**: https://www.virustotal.com/gui/join-us
- **Get API key**: https://www.virustotal.com/gui/my-apikey
- **Environment variable**: `VIRUSTOTAL_API_KEY`

### 2. **AbuseIPDB** (For IP reputation)
- **Free tier**: 1,000 requests/day
- **Sign up**: https://www.abuseipdb.com/register
- **Environment variable**: `ABUSEIPDB_API_KEY`

### 3. **Other Providers** (Optional)
- **GreyNoise**: `GREYNOISE_API_KEY`
- **Shodan**: `SHODAN_API_KEY`
- **Pulsedive**: `PULSEDIVE_API_KEY`

## How to Configure API Keys

### Method 1: Create a .env file (Recommended)

1. **Create** a file named `.env` in the project directory:
   ```
   c:\KAS\Python Scripts\Python_IOC_Checker\.env
   ```

2. **Add your API keys** to the file:
   ```bash
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   # GREYNOISE_API_KEY=your_greynoise_api_key_here
   # SHODAN_API_KEY=your_shodan_api_key_here
   ```

3. **Save the file** and restart the application

### Method 2: System Environment Variables

Set environment variables in Windows:
1. Open **System Properties** → **Advanced** → **Environment Variables**
2. Add **New** user variables:
   - Variable: `VIRUSTOTAL_API_KEY`
   - Value: `your_api_key_here`

## Testing API Key Configuration

Create this test file to verify your API keys work:

```python
# test_api_keys.py
import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

def test_api_keys():
    """Test if API keys are properly configured."""
    providers = {
        "VirusTotal": os.getenv("VIRUSTOTAL_API_KEY"),
        "AbuseIPDB": os.getenv("ABUSEIPDB_API_KEY"),
        "GreyNoise": os.getenv("GREYNOISE_API_KEY"),
        "Shodan": os.getenv("SHODAN_API_KEY")
    }
    
    print("🔑 API Key Configuration Status:")
    print("=" * 40)
    
    for provider, key in providers.items():
        if key and key.strip():
            print(f"✅ {provider}: Configured ({key[:8]}...)")
        else:
            print(f"❌ {provider}: Not configured")
    
    print("\n📝 To configure missing keys:")
    print("1. Create a .env file in the project directory")
    print("2. Add: PROVIDER_API_KEY=your_key_here")
    print("3. Restart the application")

if __name__ == "__main__":
    test_api_keys()
```

## Expected Results After Configuration

Once you configure the VirusTotal API key, instead of "n/a" you should see:
- **"malicious"** - URL/domain/IP detected as malicious
- **"suspicious"** - Flagged by some engines but not confirmed malicious  
- **"clean"** - No detection by any antivirus engines

## Quick Start (VirusTotal Only)

1. **Get VirusTotal API key**:
   - Go to https://www.virustotal.com/gui/join-us
   - Sign up for free account
   - Go to https://www.virustotal.com/gui/my-apikey
   - Copy your API key

2. **Create .env file**:
   ```bash
   VIRUSTOTAL_API_KEY=your_actual_api_key_here
   ```

3. **Test with batch processing**:
   - Use the test_urls.txt file
   - Run batch processing in GUI
   - Results should now show actual VirusTotal status instead of "n/a"

## Free Tier Limitations

- **VirusTotal**: 4 requests/minute, 500/day
- **AbuseIPDB**: 1,000 requests/day
- For higher limits, consider paid plans

The "n/a" status will change to actual results once API keys are configured! 🔑
