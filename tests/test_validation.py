#!/usr/bin/env python3
"""Unit tests for IOC validation functionality."""

import pytest
from ioc_types import validate_ioc


class TestIOCValidation:
    """Test cases for IOC validation."""
    
    def test_valid_ips(self):
        """Test valid IP addresses."""
        valid_ips = [
            "8.8.8.8",
            "192.168.1.1", 
            "127.0.0.1",
            "2001:db8::1"
        ]
        for ip in valid_ips:
            is_valid, ioc_type, normalized, error = validate_ioc(ip)
            assert is_valid, f"Valid IP {ip} should be accepted"
            assert ioc_type == "ip"
    
    def test_invalid_ips(self):
        """Test invalid IP addresses."""
        invalid_ips = [
            "8.8.8.8.8",  # Too many octets
            "192.168.1.999",  # Octet > 255
            "192.168.1",  # Too few octets
            "256.256.256.256"  # All octets > 255
        ]
        for ip in invalid_ips:
            is_valid, _, _, error = validate_ioc(ip)
            assert not is_valid, f"Invalid IP {ip} should be rejected"
            assert error, "Error message should be provided"
    
    def test_valid_domains(self):
        """Test valid domain names."""
        valid_domains = [
            "google.com",
            "subdomain.example.org",
            "test.co.uk"
        ]
        for domain in valid_domains:
            is_valid, ioc_type, normalized, error = validate_ioc(domain)
            assert is_valid, f"Valid domain {domain} should be accepted"
            assert ioc_type == "domain"
    
    def test_invalid_domains(self):
        """Test invalid domain names."""
        invalid_domains = [
            "domain.",  # Ending with dot
            "example..com",  # Consecutive dots
            "win.malware",  # Malware family pattern
        ]
        for domain in invalid_domains:
            is_valid, _, _, error = validate_ioc(domain)
            assert not is_valid, f"Invalid domain {domain} should be rejected"
            assert error, "Error message should be provided"
    
    def test_valid_urls(self):
        """Test valid URLs."""
        valid_urls = [
            "https://www.google.com",
            "http://example.com/path",
            "https://subdomain.example.org/page.html",
            "ftp://files.example.com"
        ]
        for url in valid_urls:
            is_valid, ioc_type, normalized, error = validate_ioc(url)
            assert is_valid, f"Valid URL {url} should be accepted"
            assert ioc_type == "url"
    
    def test_invalid_urls(self):
        """Test invalid URLs."""
        invalid_urls = [
            "https://www.bbc.co.uk/news./",  # Path ending with dot
            "https://www.bbc.co.uk/news../",  # Consecutive dots in path
            "https://example..com",  # Consecutive dots in domain
            "https://",  # Incomplete URL
            "not-a-url",  # Missing scheme
            "http://example",  # No TLD
        ]
        for url in invalid_urls:
            is_valid, _, _, error = validate_ioc(url)
            assert not is_valid, f"Invalid URL {url} should be rejected"
            assert error, "Error message should be provided"
    
    def test_valid_hashes(self):
        """Test valid hash values."""
        valid_hashes = [
            "d41d8cd98f00b204e9800998ecf8427e",  # MD5
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # SHA1
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
        ]
        for hash_val in valid_hashes:
            is_valid, ioc_type, normalized, error = validate_ioc(hash_val)
            assert is_valid, f"Valid hash {hash_val} should be accepted"
            assert ioc_type == "hash"
    
    def test_invalid_hashes(self):
        """Test invalid hash values."""
        invalid_hashes = [
            "notahash123",  # Invalid length and characters
            "d41d8cd98f00b204e9800998ecf8427",  # 31 characters (too short)
            "abcdefg",  # Too short
            "gggggggggggggggggggggggggggggggg",  # Invalid hex characters
        ]
        for hash_val in invalid_hashes:
            is_valid, _, _, error = validate_ioc(hash_val)
            assert not is_valid, f"Invalid hash {hash_val} should be rejected"
            assert error, "Error message should be provided"
    
    def test_type_specific_validation(self):
        """Test validation with specific expected types."""
        # Valid cases
        is_valid, _, _, _ = validate_ioc("192.168.1.1", "ip")
        assert is_valid, "Valid IP with explicit type should pass"
        
        is_valid, _, _, _ = validate_ioc("google.com", "domain")
        assert is_valid, "Valid domain with explicit type should pass"
        
        is_valid, _, _, _ = validate_ioc("https://example.com", "url")
        assert is_valid, "Valid URL with explicit type should pass"
        
        # Invalid type mismatches
        is_valid, _, _, error = validate_ioc("google.com", "url")
        assert not is_valid, "Domain validated as URL should fail"
        assert "URLs must start with http" in error
        
        is_valid, _, _, error = validate_ioc("https://google.com", "domain")
        assert not is_valid, "URL validated as domain should fail"
        
        is_valid, _, _, error = validate_ioc("8.8.8.8", "hash")
        assert not is_valid, "IP validated as hash should fail"
    
    def test_edge_cases(self):
        """Test edge cases and boundary conditions."""
        # Empty string
        is_valid, _, _, error = validate_ioc("")
        assert not is_valid, "Empty string should be rejected"
        assert "cannot be empty" in error
        
        # Extremely long input
        long_string = "a" * 2049
        is_valid, _, _, error = validate_ioc(long_string)
        assert not is_valid, "Extremely long input should be rejected"
        assert "too long" in error
        
        # Whitespace handling
        is_valid, ioc_type, normalized, _ = validate_ioc("  8.8.8.8  ")
        assert is_valid, "Whitespace should be stripped"
        assert normalized == "8.8.8.8"
    
    def test_auto_detection(self):
        """Test automatic IOC type detection."""
        test_cases = [
            ("8.8.8.8", "ip"),
            ("google.com", "domain"),
            ("https://example.com", "url"),
            ("d41d8cd98f00b204e9800998ecf8427e", "hash"),
        ]
        
        for ioc_value, expected_type in test_cases:
            is_valid, detected_type, _, _ = validate_ioc(ioc_value)
            assert is_valid, f"Valid IOC {ioc_value} should be accepted"
            assert detected_type == expected_type, f"IOC {ioc_value} should be detected as {expected_type}" 