from __future__ import annotations

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

from pathlib import Path
import csv
import re
from typing import Dict, List

__all__ = ["load_iocs"]


# ──────────────────────────────────────────────────────────────────────────────
def _guess_type(indicator: str) -> str:
    """Very small heuristic that guesses an IOC type from its value."""
    indicator = indicator.strip()
    if re.match(r"^(https?://|ftp://)", indicator, flags=re.I):
        return "url"

    ip_pat = r"^(?:\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pat, indicator):
        return "ip"

    sha256_pat = r"^[a-f0-9]{64}$"
    if re.match(sha256_pat, indicator, flags=re.I):
        return "hash"

    return "domain"


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


def _load_csv(path: Path) -> List[Dict[str, str]]:
    """Load IOC rows from a CSV file.

    The function is liberal regarding the column names.  It accepts the first
    column as *value* if no well-known column names are found.
    """
    data: List[Dict[str, str]] = []
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
            data.append({"value": value, "type": ioc_type})
    return data


# Public API ───────────────────────────────────────────────────────────────────

def load_iocs(path: Path) -> List[Dict[str, str]]:  # noqa: WPS231 (simple func)
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
        return _load_csv(path)

    raise ValueError(f"Unsupported IOC file format: {path.suffix}") 