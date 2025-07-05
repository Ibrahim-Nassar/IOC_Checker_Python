"""Tests for analyze_ioc_types functionality with SUPPORTED_TYPES."""
import pytest
from unittest.mock import Mock, patch

from services import IOCProcessingService


class TestAnalyzeIOCTypes:
    """Test analyze_ioc_types method with dynamic SUPPORTED_TYPES."""
    
    def test_analyze_ioc_types_with_supported_types(self):
        """Test analyze_ioc_types using provider SUPPORTED_TYPES."""
        # Mock providers with SUPPORTED_TYPES
        mock_provider1 = Mock()
        mock_provider1.NAME = "VirusTotal"
        mock_provider1.SUPPORTED_TYPES = {"ip", "domain", "url", "hash"}
        
        mock_provider2 = Mock()
        mock_provider2.NAME = "AbuseIPDB"
        mock_provider2.SUPPORTED_TYPES = {"ip"}
        
        service = IOCProcessingService()
        
        # Mock IOCs
        test_iocs = [
            {'value': '1.1.1.1'},
            {'value': 'example.com'},
            {'value': 'http://example.com'}
        ]
        
        with patch('services.get_providers', return_value=[mock_provider1, mock_provider2]), \
             patch('services.validate_ioc') as mock_validate:
            
            # Setup validate_ioc to return valid results
            mock_validate.side_effect = [
                (True, 'ip', '1.1.1.1', None),
                (True, 'domain', 'example.com', None),
                (True, 'url', 'http://example.com', None)
            ]
            
            ioc_types_found, unsupported_iocs, provider_type_map = service.analyze_ioc_types(test_iocs)
            
            # Check results
            assert ioc_types_found == {'ip', 'domain', 'url'}
            assert len(unsupported_iocs) == 0  # All types supported by at least one provider
            assert provider_type_map['virustotal'] == ['ip', 'domain', 'url', 'hash']
            assert provider_type_map['abuseipdb'] == ['ip']
    
    def test_analyze_ioc_types_unsupported_type(self):
        """Test analyze_ioc_types with unsupported IOC type."""
        # Mock provider that doesn't support certain types
        mock_provider = Mock()
        mock_provider.NAME = "LimitedProvider"
        mock_provider.SUPPORTED_TYPES = {"ip"}  # Only supports IP
        
        service = IOCProcessingService()
        
        test_iocs = [
            {'value': '1.1.1.1'},
            {'value': 'example.com'}  # Domain not supported
        ]
        
        with patch('services.get_providers', return_value=[mock_provider]), \
             patch('services.validate_ioc') as mock_validate:
            
            mock_validate.side_effect = [
                (True, 'ip', '1.1.1.1', None),
                (True, 'domain', 'example.com', None)
            ]
            
            ioc_types_found, unsupported_iocs, provider_type_map = service.analyze_ioc_types(test_iocs)
            
            # Domain should be unsupported
            assert len(unsupported_iocs) == 1
            assert unsupported_iocs[0]['type'] == 'domain'
            assert unsupported_iocs[0]['original'] == 'example.com'
            assert 'No active providers support domain IOCs' in unsupported_iocs[0]['reason']
    
    def test_analyze_ioc_types_no_supported_types_attribute(self):
        """Test analyze_ioc_types with provider missing SUPPORTED_TYPES attribute."""
        # Mock provider without SUPPORTED_TYPES
        mock_provider = Mock()
        mock_provider.NAME = "LegacyProvider"
        # Don't set SUPPORTED_TYPES attribute
        
        service = IOCProcessingService()
        
        test_iocs = [{'value': '1.1.1.1'}]
        
        with patch('services.get_providers', return_value=[mock_provider]), \
             patch('services.validate_ioc') as mock_validate:
            
            mock_validate.return_value = (True, 'ip', '1.1.1.1', None)
            
            ioc_types_found, unsupported_iocs, provider_type_map = service.analyze_ioc_types(test_iocs)
            
            # Should fallback to empty set
            assert provider_type_map['legacyprovider'] == []
            # IP should be unsupported since provider has no supported types
            assert len(unsupported_iocs) == 1
    
    def test_analyze_ioc_types_invalid_ioc(self):
        """Test analyze_ioc_types with invalid IOC."""
        mock_provider = Mock()
        mock_provider.NAME = "TestProvider"
        mock_provider.SUPPORTED_TYPES = {"ip"}
        
        service = IOCProcessingService()
        
        test_iocs = [{'value': 'invalid_ioc'}]
        
        with patch('services.get_providers', return_value=[mock_provider]), \
             patch('services.validate_ioc') as mock_validate:
            
            mock_validate.return_value = (False, 'unknown', 'invalid_ioc', 'Invalid format')
            
            ioc_types_found, unsupported_iocs, provider_type_map = service.analyze_ioc_types(test_iocs)
            
            # Invalid IOCs should not be added to unsupported_iocs
            assert len(unsupported_iocs) == 0
            assert len(ioc_types_found) == 0
    
    def test_analyze_ioc_types_mixed_support(self):
        """Test analyze_ioc_types with mixed provider support."""
        # Provider 1 supports IP and domain
        mock_provider1 = Mock()
        mock_provider1.NAME = "Provider1"
        mock_provider1.SUPPORTED_TYPES = {"ip", "domain"}
        
        # Provider 2 supports hash only
        mock_provider2 = Mock()
        mock_provider2.NAME = "Provider2"
        mock_provider2.SUPPORTED_TYPES = {"hash"}
        
        service = IOCProcessingService()
        
        test_iocs = [
            {'value': '1.1.1.1'},      # Supported by Provider1
            {'value': 'example.com'},   # Supported by Provider1
            {'value': 'abc123'},        # Supported by Provider2
            {'value': 'http://test.com'} # Not supported by any
        ]
        
        with patch('services.get_providers', return_value=[mock_provider1, mock_provider2]), \
             patch('services.validate_ioc') as mock_validate:
            
            mock_validate.side_effect = [
                (True, 'ip', '1.1.1.1', None),
                (True, 'domain', 'example.com', None),
                (True, 'hash', 'abc123', None),
                (True, 'url', 'http://test.com', None)
            ]
            
            ioc_types_found, unsupported_iocs, provider_type_map = service.analyze_ioc_types(test_iocs)
            
            # Only URL should be unsupported
            assert len(unsupported_iocs) == 1
            assert unsupported_iocs[0]['type'] == 'url'
            assert ioc_types_found == {'ip', 'domain', 'hash', 'url'} 