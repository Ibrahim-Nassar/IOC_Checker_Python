from pathlib import Path
import csv, os
from reports import write_clean_csv


def test_write_clean_csv(tmp_path):
    out = tmp_path / "out.csv"
    sample = [{
        "value": "1.1.1.1",
        "type":  "ip",
        "results": {
            "virustotal":   {"status": "clean"},
            "abuseipdb":    {"status": "malicious"},
        }
    }]
    write_clean_csv(out, sample)

    assert out.exists() and out.stat().st_size > 0

    # Validate header & first data row
    with out.open(encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    header = rows[0]
    assert "ioc" in header and "overall" in header
    data   = rows[1]
    assert data[header.index("ioc")] == "1.1.1.1" 