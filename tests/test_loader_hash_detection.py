"""Test that loader correctly detects 32-char and 40-char hashes."""
import sys
import os
from pathlib import Path
import tempfile

# Add the parent directory to the path so we can import from IOC_Checker_Python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from loader import _guess_type, load_iocs, stream_iocs


class TestLoaderHashDetection:
    """Test hash detection functionality in loader."""
    
    def test_guess_type_md5_hash(self):
        """Test that 32-char MD5 hashes are correctly detected."""
        md5_hash = "5d41402abc4b2a76b9719d911017c592"
        assert len(md5_hash) == 32
        assert _guess_type(md5_hash) == "hash"
    
    def test_guess_type_sha1_hash(self):
        """Test that 40-char SHA1 hashes are correctly detected."""
        sha1_hash = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        assert len(sha1_hash) == 40
        assert _guess_type(sha1_hash) == "hash"
    
    def test_guess_type_sha256_hash(self):
        """Test that 64-char SHA256 hashes are correctly detected."""
        sha256_hash = "2cf24dba4f21d4288094c6b92b0c3482f1c0b20a8b1d6ba5b5c8b15b4c9c6b1d"
        assert len(sha256_hash) == 64
        assert _guess_type(sha256_hash) == "hash"
    
    def test_guess_type_various_hash_cases(self):
        """Test hash detection with various cases."""
        # MD5 uppercase
        md5_upper = "5D41402ABC4B2A76B9719D911017C592"
        assert _guess_type(md5_upper) == "hash"
        
        # SHA1 mixed case
        sha1_mixed = "Aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        assert _guess_type(sha1_mixed) == "hash"
        
        # SHA256 with mixed case
        sha256_mixed = "2CF24DBA4F21D4288094C6B92B0C3482F1c0b20A8B1D6BA5B5C8B15B4C9C6B1D"
        assert _guess_type(sha256_mixed) == "hash"
    
    def test_guess_type_non_hash_strings(self):
        """Test that non-hash strings are not detected as hashes."""
        # Wrong length
        assert _guess_type("1234567890") != "hash"
        
        # Contains non-hex characters
        assert _guess_type("5d41402abc4b2a76b9719d911017c59g") != "hash"  # 'g' is not hex
        
        # Too short
        assert _guess_type("5d41402abc4b2a76b9719d911017c59") != "hash"  # 31 chars
        
        # Too long (between SHA1 and SHA256)
        assert _guess_type("5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c59") != "hash"  # 63 chars
    
    def test_load_txt_with_hashes(self):
        """Test loading text file with various hash types."""
        # Create temporary file with hashes
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("5d41402abc4b2a76b9719d911017c592\n")  # MD5
            f.write("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d\n")  # SHA1
            f.write("2cf24dba4f21d4288094c6b92b0c3482f1c0b20a8b1d6ba5b5c8b15b4c9c6b1d\n")  # SHA256
            f.write("example.com\n")  # Domain for comparison
            temp_path = f.name
        
        try:
            # Load IOCs
            iocs = load_iocs(Path(temp_path))
            
            # Check results
            assert len(iocs) == 4
            
            # MD5 hash
            assert iocs[0]['value'] == "5d41402abc4b2a76b9719d911017c592"
            assert iocs[0]['type'] == "hash"
            
            # SHA1 hash
            assert iocs[1]['value'] == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
            assert iocs[1]['type'] == "hash"
            
            # SHA256 hash
            assert iocs[2]['value'] == "2cf24dba4f21d4288094c6b92b0c3482f1c0b20a8b1d6ba5b5c8b15b4c9c6b1d"
            assert iocs[2]['type'] == "hash"
            
            # Domain
            assert iocs[3]['value'] == "example.com"
            assert iocs[3]['type'] == "domain"
            
        finally:
            os.unlink(temp_path)
    
    def test_stream_iocs_with_hashes(self):
        """Test streaming IOCs with hash detection."""
        # Create temporary CSV file with hashes
        with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
            f.write("Indicator,Type\n")
            f.write("5d41402abc4b2a76b9719d911017c592,\n")  # MD5, no type specified
            f.write("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d,\n")  # SHA1, no type specified
            f.write("example.com,domain\n")  # Domain with explicit type
            temp_path = f.name
        
        try:
            # Stream IOCs
            iocs = list(stream_iocs(Path(temp_path)))
            
            # Check results
            assert len(iocs) == 3
            
            # MD5 hash (type auto-detected)
            assert iocs[0]['value'] == "5d41402abc4b2a76b9719d911017c592"
            assert iocs[0]['type'] == "hash"
            
            # SHA1 hash (type auto-detected)
            assert iocs[1]['value'] == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
            assert iocs[1]['type'] == "hash"
            
            # Domain (explicit type)
            assert iocs[2]['value'] == "example.com"
            assert iocs[2]['type'] == "domain"
            
        finally:
            os.unlink(temp_path)
    
    def test_fallback_to_domain_for_unknown(self):
        """Test that unknown IOC types fall back to domain."""
        # Test with something that detect_ioc_type might not recognize
        unknown_value = "some.unknown.format.123"
        result = _guess_type(unknown_value)
        
        # Should either be detected as something valid or fall back to domain
        assert result in ["domain", "ip", "url", "hash"]  # Valid types
        
        # Test with clearly invalid IOC that should fall back to domain
        clearly_invalid = "not_a_valid_ioc_format_at_all"
        result = _guess_type(clearly_invalid)
        assert result == "domain"  # Should fallback to domain 