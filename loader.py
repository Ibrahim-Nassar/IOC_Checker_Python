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

# Try pandas import with fallback
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    log.warning("Pandas not available - limited to basic CSV/TXT support")


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


def _extract_iocs_from_dataframe(df: pd.DataFrame) -> List[Dict[str, str]]:
    """Extract IOCs from a pandas DataFrame by scanning all cells."""
    iocs = []
    seen_values: Set[str] = set()
    
    log.info(f"Scanning DataFrame with {len(df)} rows and {len(df.columns)} columns")
    
    # Iterate through all cells in the DataFrame
    for row_idx, row in df.iterrows():
        for col_name, cell_value in row.items():
            clean_value = _clean_value(cell_value)
            if not clean_value or clean_value in seen_values:
                continue
            
            # Try to detect IOC type
            ioc_type, normalized = detect_ioc_type(clean_value)
            if ioc_type and ioc_type != "unknown":
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
    
    # Split by common delimiters and newlines
    lines = re.split(r'[\n\r,;\t|]+', content)
    
    log.info(f"Scanning {len(lines)} text lines")
    
    for line_num, line in enumerate(lines, 1):
        clean_value = _clean_value(line)
        if not clean_value or clean_value in seen_values:
            continue
        
        # Try to detect IOC type
        ioc_type, normalized = detect_ioc_type(clean_value)
        if ioc_type and ioc_type != "unknown":
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
        # Try structured data first (pandas)
        if PANDAS_AVAILABLE and file_path.suffix.lower() in ['.csv', '.tsv', '.xlsx']:
            iocs = _load_with_pandas(file_path)
        
        # Fallback to text processing if no IOCs found or pandas failed
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


def _load_with_pandas(file_path: Path) -> List[Dict[str, str]]:
    """Load structured data using pandas."""
    if not PANDAS_AVAILABLE:
        return []
    
    try:
        # Try different pandas readers based on extension
        if file_path.suffix.lower() == '.xlsx':
            df = pd.read_excel(file_path, engine='openpyxl')
        elif file_path.suffix.lower() == '.tsv':
            df = pd.read_csv(file_path, sep='\t', engine='python')
        else:  # .csv or other
            # Try auto-detection of delimiter
            df = pd.read_csv(file_path, sep=None, engine='python')
        
        return _extract_iocs_from_dataframe(df)
                        
    except Exception as e:
        log.warning(f"Pandas loading failed: {e}")
        return []


def _load_as_text(file_path: Path) -> List[Dict[str, str]]:
    """Load file as plain text and extract IOCs."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except UnicodeDecodeError:
        # Try different encodings
        for encoding in ['latin-1', 'cp1252', 'ascii']:
            try:
                with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                    content = f.read()
                break
            except:
                continue
        else:
            raise ValueError(f"Could not decode file {file_path}")
    
    return _extract_iocs_from_text(content)