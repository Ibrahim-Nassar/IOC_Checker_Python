"""
Comprehensive tests for ioc_types.py module.
Tests all IOC detection, validation, and normalization functions.
"""
from ioc_types import (
    detect_ioc_type, VALIDATORS, _normalise, _strip_port,
    _valid_ip, _valid_domain, _valid_url, _valid_hash, _valid_email,
    _valid_file, _valid_reg, _valid_wallet, _valid_asn, _valid_attck
)
from providers import _extract_ip


class TestIOCDetection:
    """Test IOC type detection and normalization."""
    
    def test_detect_ip_addresses(self, sample_iocs):
        """Test IP address detection and normalization."""
        # Valid IPv4
        typ, norm = detect_ioc_type(sample_iocs["valid_ip"])
        assert typ == "ip"
        assert norm == "8.8.8.8"
        
        # IPv4 with port
        typ, norm = detect_ioc_type(sample_iocs["valid_ip_with_port"])
        assert typ == "ip"
        assert norm == "8.8.8.8"  # Port stripped
        
        # Valid IPv6
        typ, norm = detect_ioc_type(sample_iocs["valid_ipv6"])
        assert typ == "ip"
        assert norm == "2001:db8::1"
        
        # IPv6 with port
        typ, norm = detect_ioc_type("[2001:db8::1]:8080")
        assert typ == "ip"
        assert norm == "2001:db8::1"
        
        # Invalid IP
        typ, norm = detect_ioc_type(sample_iocs["invalid_ip"])
        assert typ == "unknown"
    
    def test_detect_domains(self, sample_iocs):
        """Test domain detection and normalization."""
        typ, norm = detect_ioc_type(sample_iocs["valid_domain"])
        assert typ == "domain"
        assert norm == "example.com"
        
        # Domain with uppercase - should be normalized to lowercase
        typ, norm = detect_ioc_type("EXAMPLE.COM")
        assert typ == "domain"
        assert norm == "example.com"
        
        # Subdomain
        typ, norm = detect_ioc_type("subdomain.example.com")
        assert typ == "domain"
        assert norm == "subdomain.example.com"
        
        # Invalid domain
        typ, norm = detect_ioc_type(sample_iocs["invalid_domain"])
        assert typ == "unknown"
    
    def test_detect_urls(self, sample_iocs):
        """Test URL detection and normalization."""
        typ, norm = detect_ioc_type(sample_iocs["valid_url"])
        assert typ == "url"
        assert "https://example.com" in norm
        
        # URL with query parameters - should be stripped
        typ, norm = detect_ioc_type("https://example.com/path?param=value#fragment")
        assert typ == "url"
        assert "param" not in norm
        assert "fragment" not in norm
        
        # HTTP URL
        typ, norm = detect_ioc_type("http://example.com")
        assert typ == "url"
        
        # FTP URL
        typ, norm = detect_ioc_type("ftp://example.com")
        assert typ == "url"
        
        # Invalid URL
        typ, norm = detect_ioc_type(sample_iocs["invalid_url"])
        assert typ == "unknown"
    
    def test_detect_hashes(self, sample_iocs):
        """Test hash detection and normalization."""
        # MD5
        typ, norm = detect_ioc_type(sample_iocs["valid_hash_md5"])
        assert typ == "hash"
        assert norm == sample_iocs["valid_hash_md5"].lower()
        
        # SHA256
        typ, norm = detect_ioc_type(sample_iocs["valid_hash_sha256"])
        assert typ == "hash"
        assert norm == sample_iocs["valid_hash_sha256"].lower()
        
        # SHA1
        typ, norm = detect_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert typ == "hash"
        
        # Uppercase hash - should be normalized to lowercase
        typ, norm = detect_ioc_type("D41D8CD98F00B204E9800998ECF8427E")
        assert typ == "hash"
        assert norm == "d41d8cd98f00b204e9800998ecf8427e"
        
        # Invalid hash
        typ, norm = detect_ioc_type(sample_iocs["invalid_hash"])
        assert typ == "unknown"
    
    def test_detect_emails(self, sample_iocs):
        """Test email detection."""
        typ, norm = detect_ioc_type(sample_iocs["valid_email"])
        assert typ == "email"
        assert norm == "test@example.com"
        
        # Complex email
        typ, norm = detect_ioc_type("user.name+tag@subdomain.example.com")
        assert typ == "email"
        
        # Invalid email - this will be detected as domain due to priority order
        typ, norm = detect_ioc_type("invalid.email")
        assert typ == "domain"  # "invalid.email" matches domain pattern
    
    def test_detect_file_paths(self):
        """Test file path detection."""
        # Windows path
        typ, norm = detect_ioc_type("C:\\Windows\\System32\\calc.exe")
        assert typ == "filepath"
        
        # Unix path
        typ, norm = detect_ioc_type("/usr/bin/bash")
        assert typ == "filepath"
        
        # Relative path - the regex matches any path with / or \
        typ, norm = detect_ioc_type("../malware.exe")
        assert typ == "filepath"  # Actually matches filepath pattern
    
    def test_detect_registry_keys(self):
        """Test Windows registry key detection."""
        typ, norm = detect_ioc_type("HKLM\\Software\\Microsoft")
        assert typ == "registry"
        
        typ, norm = detect_ioc_type("HKCU\\Software\\Test")
        assert typ == "registry"
        
        typ, norm = detect_ioc_type("InvalidRegistry")
        assert typ == "unknown"
    
    def test_detect_wallets(self):
        """Test cryptocurrency wallet detection."""
        typ, norm = detect_ioc_type("0x1234567890abcdef1234567890abcdef12345678")
        assert typ == "wallet"
        
        # Invalid wallet (wrong length)
        typ, norm = detect_ioc_type("0x123")
        assert typ == "unknown"
    
    def test_detect_asn(self):
        """Test ASN detection."""
        typ, norm = detect_ioc_type("AS12345")
        assert typ == "asn"
        
        # IP network - this actually gets detected as filepath due to the slash
        typ, norm = detect_ioc_type("192.168.0.0/24")
        assert typ == "filepath"  # The "/" makes it match filepath pattern first
        
        typ, norm = detect_ioc_type("InvalidASN")
        assert typ == "unknown"
    
    def test_detect_attack_patterns(self):
        """Test MITRE ATT&CK pattern detection."""
        typ, norm = detect_ioc_type("T1055")
        assert typ == "attack"
        
        typ, norm = detect_ioc_type("T1055.001")
        assert typ == "attack"
        
        typ, norm = detect_ioc_type("T999999")
        assert typ == "unknown"
    
    def test_priority_order(self):
        """Test that IOC detection follows priority order."""
        # A string that could be both hash and something else
        # Hash should take priority
        test_hash = "d41d8cd98f00b204e9800998ecf8427e"
        typ, norm = detect_ioc_type(test_hash)
        assert typ == "hash"
    
    def test_unknown_iocs(self):
        """Test handling of unknown IOC types."""
        typ, norm = detect_ioc_type("completely_unknown_format")
        assert typ == "unknown"
        assert norm == "completely_unknown_format"
        
        typ, norm = detect_ioc_type("")
        assert typ == "unknown"
        
        typ, norm = detect_ioc_type("   ")
        assert typ == "unknown"


class TestValidators:
    """Test individual validator functions."""
    
    def test_ip_validator(self):
        """Test IP address validation."""
        assert _valid_ip("8.8.8.8") is True
        assert _valid_ip("8.8.8.8:53") is True  # With port
        assert _valid_ip("2001:db8::1") is True  # IPv6
        assert _valid_ip("[2001:db8::1]:8080") is True  # IPv6 with port
        assert _valid_ip("999.999.999.999") is False
        assert _valid_ip("not_an_ip") is False
    
    def test_domain_validator(self):
        """Test domain validation."""
        assert _valid_domain("example.com") is True
        assert _valid_domain("subdomain.example.com") is True
        assert _valid_domain("a.co") is True  # Short TLD
        assert _valid_domain("not_a_domain") is False
        assert _valid_domain("") is False
        assert _valid_domain(".com") is False
    
    def test_url_validator(self):
        """Test URL validation."""
        assert _valid_url("https://example.com") is True
        assert _valid_url("http://example.com") is True
        assert _valid_url("ftp://example.com") is True
        assert _valid_url("ftps://example.com") is True
        assert _valid_url("not_a_url") is False
        assert _valid_url("javascript:alert(1)") is False
    
    def test_hash_validator(self):
        """Test hash validation."""
        assert _valid_hash("d41d8cd98f00b204e9800998ecf8427e") is True  # MD5
        assert _valid_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709") is True  # SHA1
        assert _valid_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True  # SHA256
        assert _valid_hash("not_a_hash") is False
        assert _valid_hash("123") is False
    
    def test_email_validator(self):
        """Test email validation."""
        assert _valid_email("test@example.com") is True
        assert _valid_email("user.name@subdomain.example.com") is True
        assert _valid_email("invalid.email") is False
        assert _valid_email("@example.com") is False
        assert _valid_email("test@") is False
    
    def test_file_validator(self):
        """Test file path validation."""
        assert _valid_file("C:\\Windows\\System32") is True
        assert _valid_file("/usr/bin/bash") is True
        assert _valid_file("relative/path") is True  # The regex matches any path with / or \
        assert _valid_file("just_filename") is False
    
    def test_registry_validator(self):
        """Test registry key validation."""
        assert _valid_reg("HKLM\\Software") is True
        assert _valid_reg("HKCU\\Software") is True
        assert _valid_reg("HKU\\Software") is True
        assert _valid_reg("HKCR\\Software") is True
        assert _valid_reg("InvalidReg\\Software") is False
    
    def test_wallet_validator(self):
        """Test wallet validation."""
        assert _valid_wallet("0x1234567890abcdef1234567890abcdef12345678") is True
        assert _valid_wallet("0x1234567890ABCDEF1234567890ABCDEF12345678") is True
        assert _valid_wallet("0x123") is False
        assert _valid_wallet("1234567890abcdef1234567890abcdef12345678") is False
    
    def test_asn_validator(self):
        """Test ASN validation."""
        assert _valid_asn("AS12345") is True
        assert _valid_asn("192.168.0.0/24") is True
        assert _valid_asn("10.0.0.0/8") is True
        assert _valid_asn("InvalidASN") is False
        assert _valid_asn("AS") is False
    
    def test_attack_validator(self):
        """Test MITRE ATT&CK validation."""
        assert _valid_attck("T1055") is True
        assert _valid_attck("T1055.001") is True
        assert _valid_attck("T9999") is True  # Valid format even if not real technique
        assert _valid_attck("T999999") is False  # Too many digits
        assert _valid_attck("InvalidTechnique") is False


class TestUtilityFunctions:
    """Test utility functions."""
    
    def test_strip_port(self):
        """Test port stripping functionality."""
        assert _strip_port("8.8.8.8:53") == "8.8.8.8"
        assert _strip_port("8.8.8.8") == "8.8.8.8"
        assert _strip_port("[2001:db8::1]:8080") == "2001:db8::1"
        assert _strip_port("2001:db8::1") == "2001:db8::1"
        assert _strip_port("example.com:80") == "example.com"
    
    def test_extract_ip(self):
        """Test IP extraction (alias for _strip_port)."""
        assert _extract_ip("8.8.8.8:53") == "8.8.8.8"
        assert _extract_ip("[2001:db8::1]:8080") == "2001:db8::1"
    
    def test_normalise(self):
        """Test IOC normalization."""
        # URL normalization
        url_norm = _normalise("url", "https://example.com/path?param=value#fragment")
        assert "param" not in url_norm
        assert "fragment" not in url_norm
        
        # IP normalization (port stripping)
        ip_norm = _normalise("ip", "8.8.8.8:53")
        assert ip_norm == "8.8.8.8"
        
        # Domain normalization (lowercase)
        domain_norm = _normalise("domain", "EXAMPLE.COM")
        assert domain_norm == "example.com"
        
        # Hash normalization (lowercase)
        hash_norm = _normalise("hash", "D41D8CD98F00B204E9800998ECF8427E")
        assert hash_norm == "d41d8cd98f00b204e9800998ecf8427e"
        
        # No normalization for other types
        email_norm = _normalise("email", "Test@Example.Com")
        assert email_norm == "Test@Example.Com"


class TestValidatorsDict:
    """Test the VALIDATORS dictionary."""
    
    def test_validators_dict_completeness(self):
        """Test that all IOC types have validators."""
        expected_types = {
            "ip", "domain", "url", "hash", "email", 
            "filepath", "registry", "wallet", "asn", "attack"
        }
        assert set(VALIDATORS.keys()) == expected_types
    
    def test_validators_are_callable(self):
        """Test that all validators are callable."""
        for validator in VALIDATORS.values():
            assert callable(validator)
    
    def test_validators_return_bool(self):
        """Test that all validators return boolean values."""
        test_value = "test"
        for validator in VALIDATORS.values():
            result = validator(test_value)
            assert isinstance(result, bool)