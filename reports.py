"""
Report writers: CSV (always), JSON, Excel, HTML with robust error handling.
• UTF-8 encoding • Exception handling • Graceful fallbacks
"""
from __future__ import annotations
import csv, json, pathlib, logging
from typing import List, Dict, Any

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

log = logging.getLogger("reports")

def write_csv(path: pathlib.Path, rows: List[Dict[str, Any]]) -> None:
    """Write CSV report with UTF-8 encoding."""
    if not rows:
        log.warning("No data to write to CSV")
        return
    try:
        with path.open("w", newline="", encoding="utf-8") as fh:
            fieldnames = list(rows[0].keys()) if rows else []
            w = csv.DictWriter(fh, fieldnames=fieldnames)
            w.writeheader()
            w.writerows(rows)
        log.info(f"CSV report written: {path}")
    except Exception as e:
        log.error(f"Failed to write CSV report: {e}")

def write_json(path: pathlib.Path, rows: List[Dict[str, Any]]) -> None:
    """Write JSON report with UTF-8 encoding."""
    try:
        path.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info(f"JSON report written: {path}")
    except Exception as e:
        log.error(f"Failed to write JSON report: {e}")

def write_excel(path: pathlib.Path, rows: List[Dict[str, Any]]) -> None:
    """Write Excel report if pandas is available."""
    if not PANDAS_AVAILABLE:
        log.warning("Pandas not available, skipping Excel report")
        return
    if not rows:
        log.warning("No data to write to Excel")
        return
    try:
        pd.DataFrame(rows).to_excel(path, index=False)
        log.info(f"Excel report written: {path}")
    except Exception as e:
        log.error(f"Failed to write Excel report: {e}")

def write_html(path: pathlib.Path, rows: List[Dict[str, Any]]) -> None:
    """Write HTML report with proper encoding."""
    if not rows:
        log.warning("No data to write to HTML")
        return
    try:
        if PANDAS_AVAILABLE:
            head = "<meta charset='utf-8'><style>table{border-collapse:collapse}td,th{border:1px solid #999;padding:4px}</style>"
            html_content = head + pd.DataFrame(rows).to_html(index=False, escape=False)
        else:
            # Fallback HTML generation without pandas
            head = "<meta charset='utf-8'><style>table{border-collapse:collapse}td,th{border:1px solid #999;padding:4px}</style>"
            if rows:
                table_rows = []
                headers = list(rows[0].keys())
                header_row = "<tr>" + "".join(f"<th>{h}</th>" for h in headers) + "</tr>"
                table_rows.append(header_row)
                for row in rows:
                    data_row = "<tr>" + "".join(f"<td>{str(row.get(h, ''))}</td>" for h in headers) + "</tr>"
                    table_rows.append(data_row)
                html_content = head + "<table>" + "".join(table_rows) + "</table>"
            else:
                html_content = head + "<p>No data</p>"
        
        path.write_text(html_content, encoding="utf-8")
        log.info(f"HTML report written: {path}")
    except Exception as e:
        log.error(f"Failed to write HTML report: {e}")

WRITERS = {"csv": write_csv, "json": write_json, "xlsx": write_excel, "html": write_html}
