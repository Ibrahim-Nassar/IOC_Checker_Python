#!/usr/bin/env python3
"""Test script to see what IOCs are being detected from the CSV file."""

from loader import load_iocs
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)

def test_csv_detection():
    iocs = load_iocs(Path('tests/csv_test/full_urls.csv'))
    print(f'Total IOCs found: {len(iocs)}')
    
    type_counts = {}
    for ioc in iocs:
        t = ioc['type']
        type_counts[t] = type_counts.get(t, 0) + 1
    
    print('\nIOC types found:')
    for t, count in type_counts.items():
        print(f'  {t}: {count}')
    
    print('\nFirst 20 IOCs:')
    for i, ioc in enumerate(iocs[:20]):
        print(f'  {ioc["type"]}: {ioc["value"]} (from {ioc["source"]})')

if __name__ == "__main__":
    test_csv_detection()
