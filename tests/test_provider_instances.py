"""Tests for provider instantiation and management."""

from unittest.mock import patch
import threading

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import providers
from ioc_types import IOCResult, IOCStatus


class TestProviderManagement:
    """Test cases for provider management functionality."""
    
    def test_provider_classes_tuple(self):
        """Test that PROV_CLASSES is a tuple."""
        assert isinstance(providers.PROV_CLASSES, tuple)
        # Should be immutable
        try:
            providers.PROV_CLASSES.append(None)
            assert False, "Should not be able to modify PROV_CLASSES"
        except AttributeError:
            pass  # Expected - tuples don't have append
    
    def test_providers_backward_compatibility(self):
        """Test that PROVIDERS alias exists for backward compatibility."""
        assert providers.PROVIDERS is providers.PROV_CLASSES
    
    def test_get_providers_caching(self):
        """Test that get_providers() returns cached instances."""
        # Clear cache first
        providers.refresh()
        
        # First call
        instances1 = providers.get_providers()
        
        # Second call should return same instances
        instances2 = providers.get_providers()
        
        assert instances1 is instances2
        assert len(instances1) == len(instances2)
    
    def test_get_providers_thread_safety(self):
        """Test that get_providers() is thread-safe."""
        providers.refresh()  # Clear cache
        
        results = []
        
        def get_providers_thread():
            instances = providers.get_providers()
            results.append(instances)
        
        # Start multiple threads simultaneously
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=get_providers_thread)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # All should return the same instances
        assert len(results) == 5
        first_result = results[0]
        for result in results[1:]:
            assert result is first_result
    
    def test_refresh_clears_cache(self):
        """Test that refresh() clears the provider cache."""
        # Get initial instances
        instances1 = providers.get_providers()
        
        # Refresh cache
        providers.refresh()
        
        # Get new instances
        instances2 = providers.get_providers()
        
        # Should be different objects (new instances)
        assert instances1 is not instances2
    
    def test_provider_instantiation_failure_handling(self):
        """Test handling when provider instantiation fails."""
        class FailingProvider:
            def __init__(self):
                raise RuntimeError("Provider initialization failed")
        
        # Mock the provider classes to include a failing one
        with patch('providers.PROV_CLASSES', (FailingProvider,)):
            providers.refresh()  # Clear cache
            
            with patch('logging.warning') as mock_warning:
                instances = providers.get_providers()
                
                # Should return empty list and log warning
                assert len(instances) == 0
                mock_warning.assert_called()
    
    def test_mixed_success_failure_instantiation(self):
        """Test provider instantiation with mixed success/failure."""
        class WorkingProvider:
            NAME = "working"
            def __init__(self):
                pass
        
        class FailingProvider:
            def __init__(self):
                raise ValueError("Failed to initialize")
        
        with patch('providers.PROV_CLASSES', (WorkingProvider, FailingProvider)):
            providers.refresh()  # Clear cache
            
            with patch('logging.warning') as mock_warning:
                instances = providers.get_providers()
                
                # Should have one working instance
                assert len(instances) == 1
                assert instances[0].NAME == "working"
                
                # Should log warning about failing provider
                mock_warning.assert_called()
    
    def test_provider_interface_compliance(self):
        """Test that instantiated providers comply with expected interface."""
        instances = providers.get_providers()
        
        for instance in instances:
            # Each provider should have a NAME attribute
            assert hasattr(instance, 'NAME')
            assert isinstance(instance.NAME, str)
            assert len(instance.NAME) > 0
            
            # Each provider should have query_ioc method (real providers will have this)
            # Skip this check if we have test providers in the mix
            if not instance.NAME.startswith("test_") and instance.NAME != "working":
                assert hasattr(instance, 'query_ioc')
                assert callable(instance.query_ioc)
    
    def test_provider_import_handling(self):
        """Test that ImportError is handled gracefully during provider loading."""
        # This test verifies the try/except blocks in the provider imports
        # We can't easily mock the imports, but we can verify the structure
        
        # The module should load without errors even if some providers fail to import
        assert hasattr(providers, 'PROV_CLASSES')
        assert hasattr(providers, 'get_providers')
        assert callable(providers.get_providers)
    
    def test_provider_names_unique(self):
        """Test that provider names are unique."""
        instances = providers.get_providers()
        names = [instance.NAME for instance in instances]
        
        # All names should be unique
        assert len(names) == len(set(names))
    
    def test_provider_attributes_exist(self):
        """Test that all expected provider attributes exist."""
        instances = providers.get_providers()
        
        for instance in instances:
            # Required attributes
            assert hasattr(instance, 'NAME')
            
            # query_ioc method (skip for test providers)
            if not instance.NAME.startswith("test_") and instance.NAME != "working":
                assert hasattr(instance, 'query_ioc')
            
            # Optional but common attributes
            if hasattr(instance, 'TIMEOUT'):
                assert isinstance(instance.TIMEOUT, (int, float))
                assert instance.TIMEOUT > 0


class TestProviderDummyImplementation:
    """Test with dummy provider implementations for comprehensive testing."""
    
    def test_dummy_provider_query_interface(self):
        """Test the provider query interface with a dummy implementation."""
        class DummyProvider:
            NAME = "dummy"
            TIMEOUT = 5
            
            async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
                return IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.SUCCESS,
                    malicious_engines=0,
                    total_engines=1,
                    message="Dummy result"
                )
        
        dummy = DummyProvider()
        
        # Test basic attributes
        assert dummy.NAME == "dummy"
        assert dummy.TIMEOUT == 5
        assert hasattr(dummy, 'query_ioc')
        assert callable(dummy.query_ioc)
    
    def test_provider_registration_workflow(self):
        """Test the full provider registration and usage workflow."""
        class TestProvider:
            NAME = "test_provider"
            TIMEOUT = 10
            
            def __init__(self):
                self.initialized = True
            
            async def query_ioc(self, ioc: str, ioc_type: str) -> IOCResult:
                return IOCResult(
                    ioc=ioc,
                    ioc_type=ioc_type,
                    status=IOCStatus.SUCCESS,
                    malicious_engines=0,
                    total_engines=1,
                    message="Test provider result"
                )
        
        # Mock provider classes to include our test provider
        with patch('providers.PROV_CLASSES', (TestProvider,)):
            providers.refresh()  # Clear cache
            
            instances = providers.get_providers()
            
            assert len(instances) == 1
            assert instances[0].NAME == "test_provider"
            assert instances[0].initialized
    
    def test_empty_provider_list(self):
        """Test behavior with no providers available."""
        with patch('providers.PROV_CLASSES', () ):
            providers.refresh()  # Clear cache
            
            instances = providers.get_providers()
            
            assert len(instances) == 0
            assert isinstance(instances, list)
    
    def test_provider_class_vs_instance(self):
        """Test that get_providers returns instances, not classes."""
        instances = providers.get_providers()
        
        # Should be instances, not classes
        for instance in instances:
            assert not isinstance(instance, type)  # Not a class
            assert hasattr(instance, '__class__')  # But has a class
    
    def test_concurrent_refresh_calls(self):
        """Test that concurrent refresh calls don't cause issues."""
        def refresh_thread():
            providers.refresh()
            import time as _t
            _t.sleep(0.01)  # Small delay
            providers.get_providers()
        
        threads = []
        for _ in range(3):
            thread = threading.Thread(target=refresh_thread)
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        # Should still work normally after concurrent operations
        instances = providers.get_providers()
        assert isinstance(instances, list) 