# Minimal Test for CSV export
import os
import csv
import sys
import pathlib

# Add the project directory to sys.path to import modules
project_dir = pathlib.Path(__file__).parent
sys.path.insert(0, str(project_dir))

from reports import write_csv

def test_csv_export():
    """Test the CSV export functionality with dummy data."""
    print("Testing CSV export functionality...")
    
    # Prepare dummy results
    dummy_results = [
        {"Indicator": "1.2.3.4", "Verdict": "malicious", "Provider": "TestProv"},
        {"Indicator": "5.6.7.8", "Verdict": "clean", "Provider": "TestProv"}
    ]
    
    # Remove old CSV if exists
    if os.path.exists("results.csv"):
        os.remove("results.csv")
        print("Removed existing results.csv")
    
    # Write CSV
    csv_path = write_csv(dummy_results)
    print(f"CSV written to: {csv_path}")
    
    # Verify the CSV was created
    assert csv_path.endswith("results.csv"), "CSV path should be results.csv"
    assert os.path.exists(csv_path), "CSV file was not created"
      # Read and verify CSV content (handle UTF-8 BOM)
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        data = list(csv.reader(f))
    
    print(f"CSV contains {len(data)} rows:")
    for i, row in enumerate(data):
        print(f"  Row {i}: {row}")
    
    # Verify header and content (BOM is handled by utf-8-sig encoding)
    assert data[0] == ["Indicator", "Verdict", "Provider"], f"CSV header mismatch: {data[0]}"
    assert data[1][0] == "1.2.3.4" and data[2][0] == "5.6.7.8", f"CSV content mismatch: {data[1:]}"
    
    print("✓ CSV export test passed.")

if __name__ == "__main__":
    test_csv_export()
