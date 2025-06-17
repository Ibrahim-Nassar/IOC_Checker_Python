"""
Format-agnostic IOC loader that supports CSV, TSV, XLSX, and plain text files.
Automatically discovers and validates IOCs regardless of file layout.
"""
from __future__ import annotations
import logging
from pathlib import Path
from typing import List, Dict, Any, Set
import re

# Import IOC detection
from ioc_types import detect_ioc_type

log = logging.getLogger("loader")

# Try pandas and polars imports with fallback
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    log.warning("Pandas not available - limited to basic CSV/TXT support")

try:
    import polars as pl
    POLARS_AVAILABLE = True
except ImportError:
    POLARS_AVAILABLE = False
    log.warning("Polars not available - falling back to pandas")


def _clean_value(value: Any) -> str:
    """Clean and normalize a value for IOC detection."""
    if value is None:
        return ""
    
    # Convert to string and strip whitespace
    clean = str(value).strip()
    
    # Remove common CSV artifacts
    clean = clean.strip('"\'')
    
    # Skip empty values and common non-IOC patterns
    if not clean or clean.lower() in ('nan', 'null', 'none', 'n/a', ''):
        return ""
    
    return clean


def _identify_ioc_columns(df: pd.DataFrame) -> List[str]:
    """Identify columns that likely contain IOCs."""
    ioc_columns = []
    
    # Common IOC column names (case-insensitive)
    ioc_column_patterns = [
        'ioc', 'ioc_value', 'indicator', 'observable', 'artifact',
        'url', 'domain', 'ip', 'hash', 'address', 'hostname'
    ]
    
    for col in df.columns:
        col_lower = str(col).lower()
        # Check if column name suggests it contains IOCs
        if any(pattern in col_lower for pattern in ioc_column_patterns):
            ioc_columns.append(col)
    
    return ioc_columns


def _is_likely_ioc(ioc_type: str, value: str) -> bool:
    """Filter out obvious false positives based on IOC type and value."""
    value_lower = value.lower()
    
    # Filter out malware family names that look like filepaths
    if ioc_type == "filepath":
        # Common malware family patterns
        malware_patterns = [
            'win.', 'apk.', 'js.', 'elf.', 'osx.', 'linux.', 'android.', 'ios.',
            'trojan.', 'backdoor.', 'adware.', 'spyware.', 'ransomware.', 'worm.', 'virus.'
        ]
        
        if any(value_lower.startswith(pattern) for pattern in malware_patterns):
            return False
        
        # Filter out very short "filepaths" (likely not real paths)
        if len(value) < 5:
            return False
    
    # Filter out ASN-like values that are probably not actual ASNs in this context
    if ioc_type == "asn":
        # In a URL-focused dataset, ASN detections are likely false positives
        # unless they're in a column specifically for ASNs
        return False
    
    # Filter out reference URLs that are not malicious IOCs
    if ioc_type == "url":
        # Common non-malicious reference domains
        safe_domains = [
            'urlscan.io', 'virustotal.com', 'app.any.run', 'bazaar.abuse.ch',
            'tria.ge', 'infosec.exchange', 'github.com', 'twitter.com',
            'drive.google.com', 'onedrive.live.com'
        ]
        
        # Don't filter these out completely, but note they might be references
        # For now, keep them as they could still be useful
        pass
    
    return True


def _extract_iocs_from_dataframe(df: pd.DataFrame) -> List[Dict[str, str]]:
    """Extract IOCs from a pandas DataFrame by scanning all cells."""
    iocs = []
    seen_values: Set[str] = set()
    
    log.info(f"Scanning DataFrame with {len(df)} rows and {len(df.columns)} columns")
    
    # Try to identify IOC value columns first
    ioc_columns = _identify_ioc_columns(df)
    
    if ioc_columns:
        log.info(f"Found likely IOC columns: {ioc_columns}")
        # Focus on IOC-specific columns
        for row_idx, row in df.iterrows():
            for col_name in ioc_columns:
                if col_name in row:
                    clean_value = _clean_value(row[col_name])
                    if not clean_value or clean_value in seen_values:
                        continue
                    
                    # Try to detect IOC type
                    ioc_type, normalized = detect_ioc_type(clean_value)
                    if ioc_type and ioc_type != "unknown":
                        # Additional filtering for false positives
                        if _is_likely_ioc(ioc_type, normalized):
                            iocs.append({
                                "value": normalized,
                                "type": ioc_type,
                                "original": clean_value,
                                "source": f"row_{row_idx}_{col_name}"
                            })
                            seen_values.add(clean_value)
                            log.debug(f"Found {ioc_type}: {normalized}")
    else:
        # Fallback: scan all cells but be more selective
        log.info("No specific IOC columns identified, scanning all cells with strict filtering")
        for row_idx, row in df.iterrows():
            for col_name, cell_value in row.items():
                clean_value = _clean_value(cell_value)
                if not clean_value or clean_value in seen_values:
                    continue
                
                # Try to detect IOC type
                ioc_type, normalized = detect_ioc_type(clean_value)
                if ioc_type and ioc_type != "unknown":
                    # Apply strict filtering for false positives
                    if _is_likely_ioc(ioc_type, normalized):
                        iocs.append({
                            "value": normalized,
                            "type": ioc_type,
                            "original": clean_value,
                            "source": f"row_{row_idx}_{col_name}"
                        })
                        seen_values.add(clean_value)
                        log.debug(f"Found {ioc_type}: {normalized}")
    
    return iocs


def _extract_iocs_from_polars_dataframe(df: pl.DataFrame) -> List[Dict[str, str]]:
    """Extract IOCs from a Polars DataFrame by scanning all cells."""
    iocs = []
    seen_values: Set[str] = set()
    
    log.info(f"Scanning Polars DataFrame with {df.height} rows and {df.width} columns")
    
    # Convert to dicts for easier processing (similar to pandas iterrows)
    rows = df.to_dicts()
    
    # Try to identify IOC value columns first
    column_names = df.columns
    ioc_columns = []
    
    # Common IOC column names (case-insensitive)
    ioc_column_patterns = [
        'ioc', 'ioc_value', 'indicator', 'observable', 'artifact',
        'url', 'domain', 'ip', 'hash', 'address', 'hostname'
    ]
    
    for col in column_names:
        col_lower = col.lower()
        if any(pattern in col_lower for pattern in ioc_column_patterns):
            ioc_columns.append(col)
    
    if ioc_columns:
        log.info(f"Found likely IOC columns: {ioc_columns}")
        # Focus on IOC-specific columns
        for row_idx, row in enumerate(rows):
            for col_name in ioc_columns:
                if col_name in row:
                    clean_value = _clean_value(row[col_name])
                    if not clean_value or clean_value in seen_values:
                        continue
                    
                    # Try to detect IOC type
                    ioc_type, normalized = detect_ioc_type(clean_value)
                    if ioc_type and ioc_type != "unknown":
                        # Additional filtering for false positives
                        if _is_likely_ioc(ioc_type, normalized):
                            iocs.append({
                                "value": normalized,
                                "type": ioc_type,
                                "original": clean_value,
                                "source": f"row_{row_idx}_{col_name}"
                            })
                            seen_values.add(clean_value)
                            log.debug(f"Found {ioc_type}: {normalized}")
    else:
        # Fallback: scan all cells but be more selective
        log.info("No specific IOC columns identified, scanning all cells with strict filtering")
        for row_idx, row in enumerate(rows):
            for col_name, cell_value in row.items():
                clean_value = _clean_value(cell_value)
                if not clean_value or clean_value in seen_values:
                    continue
                
                # Try to detect IOC type
                ioc_type, normalized = detect_ioc_type(clean_value)
                if ioc_type and ioc_type != "unknown":
                    # Apply strict filtering for false positives
                    if _is_likely_ioc(ioc_type, normalized):
                        iocs.append({
                            "value": normalized,
                            "type": ioc_type,
                            "original": clean_value,
                            "source": f"row_{row_idx}_{col_name}"
                        })
                        seen_values.add(clean_value)
                        log.debug(f"Found {ioc_type}: {normalized}")
    
    return iocs


def _extract_iocs_from_text(content: str) -> List[Dict[str, str]]:
    """Extract IOCs from plain text content."""
    iocs = []
    seen_values: Set[str] = set()
    
    lines = content.split('\n')
    log.info(f"Scanning {len(lines)} text lines")
    
    # Try to detect if this is a CSV file
    is_csv = False
    data_start_line = None
    ioc_column_index = None
    
    # Look for CSV header (might be in comments)
    for i, line in enumerate(lines):
        line_clean = line.strip()
        if not line_clean:
            continue
        
        # Check for header in comments
        if line_clean.startswith('#') and ('ioc_value' in line_clean or 'first_seen_utc' in line_clean):
            # This looks like the ThreatFox header format
            header_content = line_clean.lstrip('#').strip()
            if '"' in header_content:
                # Extract column names from quoted CSV header
                columns = [col.strip(' "') for col in header_content.split('","')]
                for j, col in enumerate(columns):
                    if col.lower() in ['ioc_value', 'indicator', 'url']:
                        ioc_column_index = j
                        log.info(f"Found IOC column '{col}' at index {j} in comment header")
                        is_csv = True
                        # Data starts after comments
                        for k in range(i + 1, len(lines)):
                            if lines[k].strip() and not lines[k].strip().startswith('#'):
                                data_start_line = k
                                break
                        break
                break
        
        # Check for regular CSV header (not in comments)
        elif not line_clean.startswith('#') and ',' in line_clean:
            if any(col in line_clean.lower() for col in ['ioc', 'url', 'indicator', 'value']):
                columns = [col.strip(' "') for col in line_clean.split(',')]
                for j, col in enumerate(columns):
                    col_lower = col.lower()
                    if col_lower in ['ioc_value', 'indicator', 'url', 'ioc']:
                        ioc_column_index = j
                        log.info(f"Found IOC column '{col}' at index {j}")
                        is_csv = True
                        data_start_line = i + 1
                        break
                break
    
    if is_csv and ioc_column_index is not None and data_start_line is not None:
        # Process as CSV, focusing on the IOC column
        log.info("Processing as CSV format, focusing on IOC column")
        for line_num, line in enumerate(lines[data_start_line:], data_start_line + 1):
            line_clean = line.strip()
            if line_clean.startswith('#') or not line_clean:
                continue
            
            try:
                # Handle CSV with quoted values
                import csv
                from io import StringIO
                reader = csv.reader(StringIO(line_clean))
                values = next(reader)
                
                if len(values) > ioc_column_index:
                    clean_value = _clean_value(values[ioc_column_index])
                    if not clean_value or clean_value in seen_values:
                        continue
                    
                    # Try to detect IOC type
                    ioc_type, normalized = detect_ioc_type(clean_value)
                    if ioc_type and ioc_type != "unknown":
                        if _is_likely_ioc(ioc_type, normalized):
                            iocs.append({
                                "value": normalized,
                                "type": ioc_type,
                                "original": clean_value,
                                "source": f"line_{line_num}_col_{ioc_column_index}"
                            })
                            seen_values.add(clean_value)
                            log.debug(f"Found {ioc_type}: {normalized}")
            except Exception as e:
                log.debug(f"Error parsing CSV line {line_num}: {e}")
                continue
    else:
        # Process as plain text, split by common delimiters
        log.info("Processing as plain text")
        text_lines = re.split(r'[\n\r,;\t|]+', content)
        
        for line_num, line in enumerate(text_lines, 1):
            clean_value = _clean_value(line)
            if not clean_value or clean_value in seen_values:
                continue
            
            # Try to detect IOC type
            ioc_type, normalized = detect_ioc_type(clean_value)
            if ioc_type and ioc_type != "unknown":
                if _is_likely_ioc(ioc_type, normalized):
                    iocs.append({
                        "value": normalized,
                        "type": ioc_type,
                        "original": clean_value,
                        "source": f"line_{line_num}"
                    })
                    seen_values.add(clean_value)
                    log.debug(f"Found {ioc_type}: {normalized}")
    
    return iocs


def load_iocs(file_path: Path) -> List[Dict[str, str]]:
    """
    Load IOCs from any supported file format.
    
    Args:
        file_path: Path to input file (.csv, .tsv, .xlsx, .txt)
    
    Returns:
        List of IOC dictionaries with keys: value, type, original, source
    
    Raises:
        ValueError: If no IOCs found or file format unsupported
        FileNotFoundError: If file doesn't exist
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
      # Check for supported file formats
    supported_extensions = {'.csv', '.tsv', '.xlsx', '.txt'}
    if file_path.suffix.lower() not in supported_extensions:
        raise ValueError(f"Unsupported file format: {file_path.suffix}. Supported formats: {', '.join(supported_extensions)}")
    
    log.info(f"Loading IOCs from {file_path} (format: {file_path.suffix})")
    
    iocs = []
    
    try:
        # Try structured data first (prefer Polars for CSV/TSV, fall back to pandas for XLSX)
        if file_path.suffix.lower() in ['.csv', '.tsv']:
            if POLARS_AVAILABLE:
                iocs = _load_with_polars(file_path)
            elif PANDAS_AVAILABLE:
                iocs = _load_with_pandas(file_path)
        elif PANDAS_AVAILABLE and file_path.suffix.lower() == '.xlsx':
            iocs = _load_with_pandas(file_path)
        
        # Fallback to text processing if no IOCs found or structured loading failed
        if not iocs:
            iocs = _load_as_text(file_path)
            
    except Exception as e:
        log.error(f"Error loading file {file_path}: {e}")
        # Final fallback to text processing
        try:
            iocs = _load_as_text(file_path)
        except Exception as fallback_e:
            log.error(f"Fallback text processing also failed: {fallback_e}")
            raise ValueError(f"Could not load file {file_path}: {fallback_e}")
    
    if not iocs:
        raise ValueError(f"No IOCs found in {file_path}. Supported types: ip, domain, url, hash, email, filepath, registry, wallet, asn, attack")
    
    log.info(f"Successfully loaded {len(iocs)} unique IOCs from {file_path}")
    
    # Log summary by type
    type_counts = {}
    for ioc in iocs:
        ioc_type = ioc['type']
        type_counts[ioc_type] = type_counts.get(ioc_type, 0) + 1
    
    for ioc_type, count in type_counts.items():
        log.info(f"  {ioc_type}: {count}")
    
    return iocs


def _load_with_pandas(file_path: Path, ioc_columns: List[str] = None, max_rows: int = None) -> List[Dict[str, str]]:
    """Load structured data using pandas."""
    if not PANDAS_AVAILABLE:
        return []
    
    try:
        # Try different pandas readers based on extension
        if file_path.suffix.lower() == '.xlsx':
            df = pd.read_excel(file_path, engine='openpyxl', usecols=ioc_columns or None, nrows=max_rows)
        elif file_path.suffix.lower() == '.tsv':
            df = pd.read_csv(file_path, sep='\t', engine='python', comment='#', 
                           usecols=ioc_columns or None, encoding='utf-8', errors='ignore', nrows=max_rows)
        else:  # .csv or other
            # Try auto-detection of delimiter, skip comment lines
            df = pd.read_csv(file_path, sep=None, engine='python', comment='#', 
                           usecols=ioc_columns or None, encoding='utf-8', errors='ignore', nrows=max_rows)
        
        return _extract_iocs_from_dataframe(df)
                        
    except UnicodeDecodeError:
        # Try with different encodings if UTF-8 fails
        for encoding in ['latin-1', 'cp1252', 'iso-8859-1']:
            try:
                if file_path.suffix.lower() == '.tsv':
                    df = pd.read_csv(file_path, sep='\t', engine='python', comment='#', 
                                   usecols=ioc_columns or None, encoding=encoding, errors='ignore', nrows=max_rows)
                else:
                    df = pd.read_csv(file_path, sep=None, engine='python', comment='#', 
                                   usecols=ioc_columns or None, encoding=encoding, errors='ignore', nrows=max_rows)
                return _extract_iocs_from_dataframe(df)
            except:
                continue
        # If all encodings fail, fall back to text loading
        log.warning(f"Pandas loading with various encodings failed, falling back to text extraction")
        return _load_as_text(file_path, max_lines=max_rows)
        
    except Exception as e:
        log.warning(f"Pandas loading failed: {e}")
        return []


def _load_with_polars(file_path: Path, ioc_columns: List[str] = None, max_rows: int = None) -> List[Dict[str, str]]:
    """Load structured data using Polars for high-speed CSV processing."""
    if not POLARS_AVAILABLE:
        return []
    
    try:
        # Determine separator based on file extension
        separator = '\t' if file_path.suffix.lower() == '.tsv' else ','
        
        # Use Polars streaming CSV reader with string casting for all columns
        df = pl.read_csv(
            file_path, 
            separator=separator,
            ignore_errors=True,
            encoding='utf8-lossy'
        ).with_columns(pl.col("*").cast(pl.Utf8))
        
        # Apply row limit if specified
        if max_rows:
            df = df.head(max_rows)
        
        # Select specific columns if requested
        if ioc_columns:
            available_columns = [col for col in ioc_columns if col in df.columns]
            if available_columns:
                df = df.select(available_columns)
        
        return _extract_iocs_from_polars_dataframe(df)
                        
    except Exception as e:
        log.warning(f"Polars loading failed: {e}, falling back to pandas")
        # Fall back to pandas if available
        if PANDAS_AVAILABLE:
            return _load_with_pandas(file_path, ioc_columns, max_rows)
        return []


def _load_as_text(file_path: Path, max_lines: int = None) -> List[Dict[str, str]]:
    """Load file as plain text and extract IOCs."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            if max_lines:
                lines = []
                for i, line in enumerate(f):
                    if i >= max_lines:
                        break
                    lines.append(line)
                content = ''.join(lines)
            else:
                content = f.read()
    except UnicodeDecodeError:
        # Try different encodings
        for encoding in ['latin-1', 'cp1252', 'ascii']:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    if max_lines:
                        lines = []
                        for i, line in enumerate(f):
                            if i >= max_lines:
                                break
                            lines.append(line)
                        content = ''.join(lines)
                    else:
                        content = f.read()
                break
            except:
                continue
        else:
            raise ValueError(f"Could not decode file {file_path}")
    
    return _extract_iocs_from_text(content)