"""
Test format-agnostic IOC loader functionality.
"""
import pytest
import tempfile
import pandas as pd
from pathlib import Path
from loader import load_iocs


class TestFormatAgnosticLoader:
    """Test suite for format-agnostic IOC loading."""
    
    def test_csv_with_extra_columns(self):
        """Test CSV file with extra columns - should extract IOCs from all cells."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("name,url,ip,notes\n")
            f.write("Evil Corp,http://malicious.com,192.168.1.1,Known bad\n")
            f.write("Bad Site,https://phishing.net,10.0.0.1,Phishing site\n")
            f.write("Hash Entry,not-a-url,5d41402abc4b2a76b9719d911017c592,MD5 hash\n")
            temp_path = Path(f.name)
        
        try:
            iocs = load_iocs(temp_path)
            assert len(iocs) >= 5  # URLs, IPs, hash
            
            # Check we got expected types
            types_found = {ioc['type'] for ioc in iocs}
            assert 'url' in types_found
            assert 'ip' in types_found
            assert 'hash' in types_found
            
            # Check specific values
            values = [ioc['value'] for ioc in iocs]
            assert 'http://malicious.com' in values
            assert '192.168.1.1' in values
            assert '5d41402abc4b2a76b9719d911017c592' in values
            
        finally:
            temp_path.unlink()
    
    def test_messy_tsv(self):
        """Test TSV file with inconsistent spacing and mixed data."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tsv', delete=False) as f:
            f.write("indicator\ttype\tconfidence\n")
            f.write("google.com\tdomain\thigh\n")
            f.write("  198.51.100.1  \tip\tmedium\n")  # Extra spaces
            f.write("malware.exe\tfilename\tlow\n")
            f.write("a1b2c3d4e5f6\thash\thigh\n")
            temp_path = Path(f.name)
        
        try:
            iocs = load_iocs(temp_path)
            assert len(iocs) >= 3  # domain, ip, hash
            
            # Check trimming worked
            values = [ioc['value'] for ioc in iocs]
            assert '198.51.100.1' in values  # Should be trimmed
            assert 'google.com' in values
            
        finally:
            temp_path.unlink()
    
    def test_txt_list(self):
        """Test plain text file with one IOC per line."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("# IOC List\n")  # Comment
            f.write("malicious.example.com\n")
            f.write("\n")  # Empty line
            f.write("203.0.113.1\n")
            f.write("https://bad-site.net/path\n")
            f.write("not-an-ioc-just-text\n")  # Should be ignored
            f.write("d41d8cd98f00b204e9800998ecf8427e\n")  # MD5
            temp_path = Path(f.name)
        
        try:
            iocs = load_iocs(temp_path)
            assert len(iocs) >= 4  # domain, ip, url, hash
            
            types_found = {ioc['type'] for ioc in iocs}
            assert 'domain' in types_found
            assert 'ip' in types_found
            assert 'url' in types_found
            assert 'hash' in types_found
            
            # Should ignore comments and non-IOCs
            values = [ioc['value'] for ioc in iocs]
            assert '# IOC List' not in values
            assert 'not-an-ioc-just-text' not in values
            
        finally:
            temp_path.unlink()
    
    def test_xlsx_spreadsheet(self):
        """Test Excel file with multiple sheets and columns."""
        with tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            # Create Excel file with pandas
            data = {
                'Domain': ['evil.com', 'phishing.net'],
                'IP Address': ['1.2.3.4', '5.6.7.8'],
                'Hash': ['5d41402abc4b2a76b9719d911017c592', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'],  # Valid hashes
                'Notes': ['Malware C2', 'Phishing kit']
            }
            df = pd.DataFrame(data)
            df.to_excel(temp_path, index=False)
            
            iocs = load_iocs(temp_path)
            assert len(iocs) >= 6  # 2 domains + 2 IPs + 2 hashes
            
            values = [ioc['value'] for ioc in iocs]
            assert 'evil.com' in values
            assert '1.2.3.4' in values
            assert '5d41402abc4b2a76b9719d911017c592' in values
            
        finally:
            temp_path.unlink()
    
    def test_duplicate_removal(self):
        """Test that duplicates are removed while preserving order."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("ioc\n")
            f.write("malicious.com\n")
            f.write("192.168.1.1\n")
            f.write("malicious.com\n")  # Duplicate
            f.write("10.0.0.1\n")
            f.write("192.168.1.1\n")  # Duplicate
            temp_path = Path(f.name)
        
        try:
            iocs = load_iocs(temp_path)
            
            # Should have only unique values
            values = [ioc['value'] for ioc in iocs]
            assert len(values) == len(set(values))  # No duplicates
            
            # Should preserve order of first occurrence
            assert values.index('malicious.com') < values.index('192.168.1.1')
            assert values.index('192.168.1.1') < values.index('10.0.0.1')
            
        finally:
            temp_path.unlink()
    
    def test_empty_file_error(self):
        """Test that empty files raise appropriate error."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("")  # Empty file
            temp_path = Path(f.name)
        
        try:
            with pytest.raises(ValueError, match="No IOCs found"):
                load_iocs(temp_path)
        finally:
            temp_path.unlink()
    
    def test_no_iocs_found_error(self):
        """Test error when file has data but no valid IOCs."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("name,description\n")
            f.write("Test,Just some text\n")
            f.write("Another,More text here\n")
            temp_path = Path(f.name)
        
        try:
            with pytest.raises(ValueError, match="No IOCs found"):
                load_iocs(temp_path)
        finally:
            temp_path.unlink()
    
    def test_nonexistent_file(self):
        """Test error handling for nonexistent files."""
        fake_path = Path("nonexistent_file.csv")
        
        with pytest.raises(FileNotFoundError):
            load_iocs(fake_path)
    
    def test_unsupported_format(self):
        """Test error for unsupported file formats."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.doc', delete=False) as f:
            f.write("Some content")
            temp_path = Path(f.name)
        
        try:
            with pytest.raises(ValueError, match="Unsupported file format"):
                load_iocs(temp_path)
        finally:
            temp_path.unlink()
    
    def test_mixed_ioc_types(self):
        """Test file with many different IOC types."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("indicator,type\n")
            f.write("evil.com,domain\n")
            f.write("192.168.1.1,ip\n")
            f.write("http://malicious.net,url\n")
            f.write("5d41402abc4b2a76b9719d911017c592,md5\n")
            f.write("malware@evil.com,email\n")
            temp_path = Path(f.name)
        
        try:
            iocs = load_iocs(temp_path)
            assert len(iocs) >= 5
            
            # Check all expected types are found
            types_found = {ioc['type'] for ioc in iocs}
            expected_types = {'domain', 'ip', 'url', 'hash', 'email'}
            assert expected_types.issubset(types_found)
            
        finally:
            temp_path.unlink()
    
    def test_case_insensitive_extensions(self):
        """Test that file extensions are handled case-insensitively."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.CSV', delete=False) as f:
            f.write("ioc\n")
            f.write("test.com\n")
            temp_path = Path(f.name)
        
        try:
            iocs = load_iocs(temp_path)
            assert len(iocs) >= 1
            assert any(ioc['value'] == 'test.com' for ioc in iocs)
        finally:
            temp_path.unlink()