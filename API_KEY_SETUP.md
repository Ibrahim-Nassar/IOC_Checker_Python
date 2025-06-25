# 🔑 API Key Configuration Guide

## Why VirusTotal Shows "n/a"

The VirusTotal results show "n/a" because **no API key is configured**. Without an API key, the IOC checker cannot make requests to the VirusTotal API.

## Required Environment Variables

| Provider | Environment Variable | Fallback Variable |
|----------|---------------------|-------------------|
| VirusTotal | `VIRUSTOTAL_API_KEY` | `VT_API_KEY` |
| AlienVault OTX | `OTX_API_KEY` | `ALIENVAULT_OTX_API_KEY` |
| ThreatFox | `THREATFOX_API_KEY` | - |
| AbuseIPDB | `ABUSEIPDB_API_KEY` | - |
| GreyNoise | `GREYNOISE_API_KEY` | - |

## Setup Instructions

### Option 1: Environment Variables (Recommended)

Set environment variables in your shell:

```bash
export VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

### Option 2: .env File

Create a `.env` file in the project root with your API keys. See `.env.example` for the format.

### Option 3: GUI Configuration

If environment variables are not detected, the GUI will prompt you to enter API keys manually. These are stored locally and persist between sessions.

## Getting API Keys

- **VirusTotal**: Register at https://www.virustotal.com/gui/join-us
- **AlienVault OTX**: Register at https://otx.alienvault.com/
- **ThreatFox**: Register at https://threatfox.abuse.ch/
- **AbuseIPDB**: Register at https://www.abuseipdb.com/
- **GreyNoise**: Register at https://www.greynoise.io/

## Notes

- Free API keys have rate limits and feature restrictions
- Some providers work without API keys but with limited functionality
- The tool gracefully handles missing API keys by skipping those providers

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
