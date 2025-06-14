# IOC Checker

A cross-platform async IOC (Indicator of Compromise) checker that supports checking IPs, domains, URLs, hashes, and IP:port combinations against multiple threat intelligence sources.

## Features

- **Multiple IOC Types**: IP addresses (with/without ports), domains, URLs, file hashes
- **Multiple APIs**: VirusTotal, AbuseIPDB, AlienVault OTX, ThreatFox, URLhaus, MalwareBazaar
- **Async Processing**: Fast concurrent API calls with intelligent rate limiting
- **CSV Batch Processing**: Process hundreds of IOCs from CSV files with structured results
- **Rate Limiting**: Automatic VirusTotal API throttling (4 calls per minute)
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **IPv6 Support**: Full IPv6 address validation and checking
- **Structured Output**: CSV results with per-service analysis and threat detection flags

## Installation

1. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Set up API keys in `.env` file:
   ```
   ABUSEIPDB_API_KEY=your_key_here
   VIRUSTOTAL_API_KEY=your_key_here
   OTX_API_KEY=your_key_here
   GREYNOISE_API_KEY=your_key_here
   THREATFOX_API_KEY=your_key_here
   ```

## Usage

### Command Line

Check a single IOC:
```bash
python ioc_checker.py ip 8.8.8.8
python ioc_checker.py ip 192.168.1.1:8080  # IP with port
python ioc_checker.py ip "[2001:db8::1]:8080"  # IPv6 with port
python ioc_checker.py domain example.com
python ioc_checker.py url https://example.com
python ioc_checker.py hash d41d8cd98f00b204e9800998ecf8427e
```

Check IOCs from a file:
```bash
python ioc_checker.py ip --file ips.txt
```

### CSV Batch Processing (ENHANCED!)

Process multiple IOCs from CSV file with **flexible formats**:
```bash
# Basic CSV processing (auto-generates output filename)
python ioc_checker.py --csv input_iocs.csv

# Custom output filename
python ioc_checker.py --csv input_iocs.csv --output results.csv
```

**Flexible CSV Support:**
- **Auto-detects column names** - works with `type`/`value`, `ioc_type`/`ioc_value`, `indicator_type`/`observable`, etc.
- **Case-insensitive matching** - `IOC_TYPE`, `Type`, `type` all work
- **Auto-type detection** - if no type column exists, IOC types are detected from values
- **Smart type mapping** - `ipv4`→`ip`, `fqdn`→`domain`, `md5`→`hash`, etc.

**Supported CSV Formats:**
```csv
# Standard format
ioc_type,ioc_value,description
ip,8.8.8.8,Google DNS

# Alternative format
Type,Indicator,Notes  
IP,8.8.8.8,DNS server

# Auto-detection format (no type column)
IOC,Description
8.8.8.8,Auto-detected as IP
example.com,Auto-detected as domain

# Security tool format
indicator_type,observable,confidence
ipv4,1.1.1.1,high
fqdn,google.com,medium
```

**CSV Output includes:**
- Per-service results and threat detection flags
- Overall threat assessment
- Timestamps and error reporting
- Compatible with Excel and analysis tools

**CSV Template:**
Use `ioc_template.csv` as a starting point for your IOC files. This template includes examples of all supported IOC types with the correct format. See `CSV_TEMPLATE_GUIDE.md` for detailed usage instructions.

Run test suite:
```bash
python ioc_checker.py --test
```

Interactive mode:
```bash
python ioc_checker.py
```

## API Keys

To get the most out of this tool, you'll need API keys from:

- [AbuseIPDB](https://www.abuseipdb.com/api) - Free tier available
- [VirusTotal](https://www.virustotal.com/gui/join-us) - Free tier available  
- [AlienVault OTX](https://otx.alienvault.com/) - Free registration required
- [GreyNoise](https://www.greynoise.io/viz/signup) - Community API available
- [ThreatFox](https://auth.abuse.ch/) - Free registration required

**Note about ThreatFox**: ThreatFox focuses on very recent threats (last 6 months) and has a smaller, more curated dataset compared to VirusTotal or OTX. It specializes in fresh IOCs from active malware campaigns, so many older or commonly-flagged IPs may not appear in ThreatFox even if they're detected by other services.

## Supported IOC Types

- **ip**: IPv4 and IPv6 addresses (with or without ports)
- **domain**: Domain names
- **url**: Full URLs (http/https)
- **hash**: MD5, SHA1, SHA256 file hashes

## Output

The tool provides color-coded output:
- 🚨 Red: Threats detected/malicious
- ⚠️ Yellow: Suspicious/medium confidence
- ✅ Green: Clean/not found
- ❌ Red: Errors (API issues, missing keys)
- ℹ️ Blue: Information/fallback responses

## Rate Limits

- VirusTotal: Automatically throttled to 4 requests per minute (free tier limit)
- Other APIs: Follow their respective rate limits

## Recent Improvements

### Core Functionality
- **CSV Batch Processing**: Added comprehensive CSV input/output functionality for bulk IOC analysis
- **Enhanced API Integration**: Improved response handling for URLhaus, ThreatFox, and other services
- **Better IPv6 Support**: Enhanced validation and OTX API integration for IPv6 addresses
- **Structured Output**: CSV results with per-service analysis and threat detection flags
- **Auto Rate Limiting**: Intelligent throttling for VirusTotal API compliance

### Technical Improvements
- **Async Processing**: Fast concurrent API calls with intelligent rate limiting
- **Error Resilience**: Robust exception handling that continues processing despite individual failures
- **Progress Tracking**: Real-time logging of batch processing progress
- **Cross-platform Compatibility**: Tested on Windows, macOS, and Linux
- **Memory Efficiency**: Streaming CSV processing for large datasets
