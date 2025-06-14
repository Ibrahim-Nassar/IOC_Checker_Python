# CSV Template Usage Guide

## Flexible CSV Processing

The IOC Checker now supports **flexible CSV formats** and can automatically detect common column layouts.

### Supported Column Names:

#### IOC Type Column (any of these):
- `ioc_type`, `type`, `ioc-type`, `ioctype`
- `indicator_type`, `indicatortype`
- `category`, `kind`, `class`

#### IOC Value Column (any of these):
- `ioc_value`, `value`, `ioc-value`, `iocvalue`
- `indicator`, `ioc`, `indicator_value`, `indicatorvalue`
- `data`, `content`, `observable`, `artifact`, `item`

### Auto-Detection Features:

1. **Column Name Matching**: Case-insensitive matching of common column name variations
2. **Content Analysis**: If no type column is found, the tool analyzes content to find the best column
3. **IOC Type Detection**: If no type column exists, IOC types are auto-detected from values
4. **Smart Suggestions**: The tool provides helpful suggestions when columns can't be found

### Supported IOC Type Values:

**Standard types**: `ip`, `domain`, `url`, `hash`

**Alternative names** (automatically converted):
- `ipv4`, `ipv6` → `ip`
- `hostname`, `fqdn` → `domain`  
- `md5`, `sha1`, `sha256`, `sha512` → `hash`

### Supported IOC Types:

1. **ip**: IPv4 and IPv6 addresses (with or without ports)
   - Example: `8.8.8.8`, `2001:4860:4860::8888`
   - Example with port: `192.168.1.1:8080`, `[2001:db8::1]:443`

2. **domain**: Domain names
   - Example: `example.com`, `malicious-site.net`

3. **url**: Full URLs (http/https)
   - Example: `https://example.com/path`, `http://suspicious-site.com`

4. **hash**: MD5, SHA1, SHA256 file hashes
   - Example: `d41d8cd98f00b204e9800998ecf8427e` (MD5)
   - Example: `da39a3ee5e6b4b0d3255bfef95601890afd80709` (SHA1)
   - Example: `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` (SHA256)

### Example CSV Formats:

#### Standard Format:
```csv
ioc_type,ioc_value,description
ip,8.8.8.8,Google DNS
domain,example.com,Test domain
```

#### Alternative Format 1:
```csv
Type,Indicator,Notes
IP,192.168.1.1:8080,Internal server
Domain,malicious.com,Known bad domain
```

#### Alternative Format 2 (auto-detection):
```csv
IOC,Description
8.8.8.8,DNS server
example.com,Test site
https://malicious.com/path,Bad URL
d41d8cd98f00b204e9800998ecf8427e,Empty file hash
```

#### Alternative Format 3:
```csv
indicator_type,observable,confidence
ipv4,1.1.1.1,high
fqdn,google.com,low
md5,5d41402abc4b2a76b9719d911017c592,medium
```

### Usage:
1. **No strict format required** - use any reasonable column names
2. **Auto-detection available** - the tool will try to figure out your format
3. **Run**: `python ioc_checker.py --csv your_file.csv`
4. **Results**: Saved to `your_file_results.csv`

### Error Handling:
- Clear error messages with column suggestions
- Detailed logging of what columns were detected
- Automatic type detection with validation
- Graceful handling of unsupported formats
