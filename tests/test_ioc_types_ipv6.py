"""
Tests for IPv6 address detection with ports in IOC type classification.
"""

import pytest
from ioc_types import detect_ioc_type, validate_ioc, _strip_port


class TestIPv6WithPorts:
    """Test IPv6 address handling with ports."""
    
    def test_ipv6_with_bracketed_port(self):
        """Test IPv6 address with bracketed port notation."""
        test_cases = [
            "[2001:db8::1]:443",
            "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:80",
            "[::1]:8080",
            "[fe80::1%lo0]:22",
        ]
        
        for ipv6_with_port in test_cases:
            ioc_type, normalized = detect_ioc_type(ipv6_with_port)
            assert ioc_type == "ip", f"Expected 'ip' for {ipv6_with_port}, got {ioc_type}"
            # Normalized should strip the port
            assert "]:" not in normalized, f"Port not stripped from {ipv6_with_port}: {normalized}"
    
    def test_ipv6_with_raw_port(self):
        """Test IPv6 address with raw port notation (without brackets)."""
        test_cases = [
            "2001:db8::1:443",
            "2001:0db8:85a3::8a2e:7334:80",
            "::1:8080",
            "fe80::1:22",
        ]
        
        for ipv6_with_port in test_cases:
            ioc_type, normalized = detect_ioc_type(ipv6_with_port)
            assert ioc_type == "ip", f"Expected 'ip' for {ipv6_with_port}, got {ioc_type}"
            # Normalized should strip the port (last colon segment)
            assert normalized.count(':') < ipv6_with_port.count(':'), f"Port not stripped from {ipv6_with_port}: {normalized}"
    
    def test_ipv6_without_port(self):
        """Test IPv6 address without port is still classified as IP."""
        test_cases = [
            "2001:db8::1",
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
            "::1",
            "fe80::1%lo0",
        ]
        
        for ipv6_addr in test_cases:
            ioc_type, normalized = detect_ioc_type(ipv6_addr)
            assert ioc_type == "ip", f"Expected 'ip' for {ipv6_addr}, got {ioc_type}"
            assert normalized == ipv6_addr, f"IPv6 without port should not be modified: {ipv6_addr} -> {normalized}"
    
    def test_strip_port_ipv6(self):
        """Test _strip_port function handles IPv6 correctly."""
        test_cases = [
            ("[2001:db8::1]:443", "2001:db8::1"),
            ("2001:db8::1:443", "2001:db8::1"),
            ("2001:db8::1", "2001:db8::1"),  # No port
            ("192.168.1.1:80", "192.168.1.1"),  # IPv4 for comparison
            ("::1:8080", "::1"),  # IPv6 localhost with port
        ]
        
        for input_addr, expected in test_cases:
            result = _strip_port(input_addr)
            assert result == expected, f"_strip_port({input_addr}) = {result}, expected {expected}"
    
    def test_validate_ioc_ipv6_with_port(self):
        """Test validate_ioc function with IPv6 addresses with ports."""
        test_cases = [
            "[2001:db8::1]:443",
            "2001:db8::1:443",
        ]
        
        for ipv6_with_port in test_cases:
            is_valid, ioc_type, normalized, error_msg = validate_ioc(ipv6_with_port)
            assert is_valid, f"IPv6 with port should be valid: {ipv6_with_port}, error: {error_msg}"
            assert ioc_type == "ip", f"Expected 'ip' for {ipv6_with_port}, got {ioc_type}"
            assert "]:" not in normalized and normalized.count(':') < ipv6_with_port.count(':'), \
                f"Port not stripped from {ipv6_with_port}: {normalized}"
    
    def test_edge_cases(self):
        """Test edge cases for IPv6 port detection."""
        # These should not be classified as IP due to ambiguous colon count
        ambiguous_cases = [
            "host:port",  # Only one colon, could be hostname:port
            "a:b",        # Too short to be IPv6
        ]
        
        for case in ambiguous_cases:
            ioc_type, _ = detect_ioc_type(case)
            assert ioc_type != "ip", f"Ambiguous case should not be IP: {case}"
        
        # These should be classified as IP
        clear_ipv6_cases = [
            "2001:db8:85a3::8a2e:7334:80",  # 6 colons, clear IPv6 with port
            "::1:22",                       # 3 colons, clear IPv6 with port
        ]
        
        for case in clear_ipv6_cases:
            ioc_type, _ = detect_ioc_type(case)
            assert ioc_type == "ip", f"Clear IPv6 case should be IP: {case}"


if __name__ == "__main__":
    pytest.main([__file__]) 