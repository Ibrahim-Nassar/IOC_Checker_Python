import csv
from reports import write_csv


def test_write_csv(tmp_path):
    rows = [
        {"ioc": "1.1.1.1", "verdict": "malicious", "flagged_by": "DummyTrue"},
        {"ioc": "good.com", "verdict": "clean", "flagged_by": ""},
    ]
    out_path = tmp_path / "results.csv"
    write_csv(out_path, rows)

    assert out_path.exists() and out_path.stat().st_size > 0
    with out_path.open(encoding="utf-8") as fh:
        data = list(csv.reader(fh))
    # Header should match dynamic keys
    header = data[0]
    assert header == ["ioc", "verdict", "flagged_by"]
    # No blank lines (Windows \r\n edge-case)
    assert len(data) == len(rows) + 1
