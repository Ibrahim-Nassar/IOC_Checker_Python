"""Light-weight IOC loader used by GUI, CLI, and tests.

The goal is **not** to provide a full‐blown parser – only a pragmatic
implementation that can read the simple fixture files used in the test-suite:

*  .txt  – one IOC per line
*  .csv – CSV with a header row (column names are flexible)

For every IOC we return a dictionary::

    {"value": "1.2.3.4", "type": "ip"}

An extremely small heuristic is used to guess the IOC type when it is not
explicitly supplied by the input file.
"""

from __future__ import annotations

from pathlib import Path
import csv
from typing import Dict, List

from ioc_types import detect_ioc_type

__all__ = ["load_iocs", "stream_iocs", "aget"]


# Convenience helper for tests/providers
async def aget(url: str, **kw) -> str:
    """Simple stub that returns empty string."""
    return ""


# ──────────────────────────────────────────────────────────────────────────────
def _guess_type(indicator: str) -> str:
    """Guess IOC type using detect_ioc_type, with fallback to domain for unknown types."""
    indicator = indicator.strip()
    detected_type, _ = detect_ioc_type(indicator)
    
    # If detect_ioc_type returns 'unknown', fall back to domain as before
    if detected_type == "unknown":
        return "domain"
    
    return detected_type


# ──────────────────────────────────────────────────────────────────────────────
def _load_txt(path: Path) -> List[Dict[str, str]]:
    """Load IOC lines from a text file."""
    data: List[Dict[str, str]] = []
    with path.open(encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            data.append({"value": line, "type": _guess_type(line)})
    return data


def _load_csv(path: Path):
    """Load IOC rows from a CSV file as a generator.

    The function is liberal regarding the column names.  It accepts the first
    column as *value* if no well-known column names are found.
    """
    with path.open(newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            if not row:
                continue
            # Try a handful of common column names (case-insensitive)
            value = (
                row.get("Indicator")
                or row.get("indicator")
                or row.get("IOC")
                or row.get("ioc")
                or row.get("value")
                or row.get(next(iter(row)))  # fall back to *first* column
            )
            if value is None:
                continue
            value = value.strip()
            ioc_type = (row.get("Type") or row.get("type") or _guess_type(value)).strip().lower()
            yield {"value": value, "type": ioc_type}


# Public API ───────────────────────────────────────────────────────────────────

def load_iocs(path: Path) -> List[Dict[str, str]]:
    """Return list of IOC dicts extracted from *path*.

    Supported formats: ``.txt`` and ``.csv``.  Raises *ValueError* for
    unsupported suffixes.
    """
    if not path.exists():
        raise FileNotFoundError(path)

    suffix = path.suffix.lower()
    if suffix == ".txt":
        return _load_txt(path)
    if suffix == ".csv":
        return list(_load_csv(path))  # Convert generator to list for backward compatibility

    raise ValueError(f"Unsupported IOC file format: {path.suffix}")


def stream_iocs(path: Path):
    """Stream IOC dicts from *path* as a generator for memory-efficient processing.

    Supported formats: ``.txt`` and ``.csv``.  Raises *ValueError* for
    unsupported suffixes.
    """
    if not path.exists():
        raise FileNotFoundError(path)

    suffix = path.suffix.lower()
    if suffix == ".txt":
        # Convert txt loading to generator
        with path.open(encoding="utf-8-sig") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                yield {"value": line, "type": _guess_type(line)}
    elif suffix == ".csv":
        yield from _load_csv(path)
    else:
        raise ValueError(f"Unsupported IOC file format: {path.suffix}") 