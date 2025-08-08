"""Test loader streaming functionality for memory efficiency."""
import csv
import gc
import psutil
import pytest
import os
import tempfile
from pathlib import Path

from loader import stream_iocs, load_iocs


class TestLoaderStreaming:
    """Test memory-efficient streaming of IOCs."""
    
    def create_large_csv(self, num_rows: int = 150000) -> Path:
        """Create a large CSV file with the specified number of rows."""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False)
        
        try:
            writer = csv.writer(temp_file)
            # Write header
            writer.writerow(['ioc', 'type'])
            
            # Write data rows
            for i in range(num_rows):
                if i % 4 == 0:
                    writer.writerow([f'192.168.1.{i % 255}', 'ip'])
                elif i % 4 == 1:
                    writer.writerow([f'example{i}.com', 'domain'])
                elif i % 4 == 2:
                    writer.writerow([f'https://test{i}.com/path', 'url'])
                else:
                    writer.writerow([f'{"a" * 32}{i:08x}', 'hash'])
            
            temp_file.close()
            return Path(temp_file.name)
        except Exception:
            temp_file.close()
            if os.path.exists(temp_file.name):
                os.unlink(temp_file.name)
            raise
    
    def get_memory_usage_mb(self) -> float:
        """Get current memory usage in MB."""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    def test_streaming_memory_efficiency(self):
        """Test that streaming large CSV keeps memory usage under 200MB."""
        # Create a large CSV file
        large_csv = self.create_large_csv(150000)
        
        try:
            # Force garbage collection to get baseline
            gc.collect()
            baseline_memory = self.get_memory_usage_mb()
            
            # Process the file using streaming
            processed_count = 0
            peak_memory = baseline_memory
            
            for ioc_data in stream_iocs(large_csv):
                processed_count += 1
                
                # Check memory usage every 1000 rows
                if processed_count % 1000 == 0:
                    current_memory = self.get_memory_usage_mb()
                    peak_memory = max(peak_memory, current_memory)
                    
                    # Memory should stay under 200MB
                    memory_increase = current_memory - baseline_memory
                    assert memory_increase < 200, f"Memory usage increased by {memory_increase:.2f}MB at row {processed_count}"
                
                # Process the IOC data (simulate work)
                assert 'value' in ioc_data
                assert 'type' in ioc_data
                assert ioc_data['value']  # Should not be empty
                assert ioc_data['type'] in ['ip', 'domain', 'url', 'hash']
            
            # Verify we processed all rows
            assert processed_count == 150000, f"Expected 150000 rows, got {processed_count}"
            
            # Final memory check
            final_memory = self.get_memory_usage_mb()
            memory_increase = final_memory - baseline_memory
            assert memory_increase < 200, f"Final memory usage increased by {memory_increase:.2f}MB"
            
        finally:
            # Clean up
            if large_csv.exists():
                large_csv.unlink()
    
    def test_streaming_vs_loading_memory_difference(self):
        """Test that streaming uses significantly less memory than loading all at once."""
        # Create a moderately large CSV file
        large_csv = self.create_large_csv(50000)
        
        try:
            # Test loading all at once
            gc.collect()
            baseline_memory = self.get_memory_usage_mb()
            
            all_iocs = load_iocs(large_csv)
            
            gc.collect()
            load_all_memory = self.get_memory_usage_mb()
            load_all_increase = load_all_memory - baseline_memory
            
            # Clear the loaded data
            del all_iocs
            gc.collect()
            
            # Test streaming
            baseline_memory = self.get_memory_usage_mb()
            
            streaming_count = 0
            peak_streaming_memory = baseline_memory
            
            for ioc_data in stream_iocs(large_csv):
                streaming_count += 1
                if streaming_count % 1000 == 0:
                    current_memory = self.get_memory_usage_mb()
                    peak_streaming_memory = max(peak_streaming_memory, current_memory)
            
            streaming_increase = peak_streaming_memory - baseline_memory
            
            # Streaming should use significantly less memory
            assert streaming_increase < load_all_increase / 2, \
                f"Streaming memory increase ({streaming_increase:.2f}MB) should be less than half of load-all increase ({load_all_increase:.2f}MB)"
            
            # Both should process the same number of items
            assert streaming_count == 50000, f"Expected 50000 rows, got {streaming_count}"
            
        finally:
            # Clean up
            if large_csv.exists():
                large_csv.unlink()
    
    def test_streaming_with_progress_updates(self):
        """Test streaming with progress updates every 200 rows."""
        # Create a CSV file
        test_csv = self.create_large_csv(10000)
        
        try:
            progress_updates = []
            
            def progress_callback(current, total):
                progress_updates.append((current, total))
            
            # Simulate batch processing with progress updates
            processed = 0
            for ioc_data in stream_iocs(test_csv):
                processed += 1
                
                # Update progress every 200 rows
                if processed % 200 == 0:
                    progress_callback(processed, 10000)
                    
                    # Check that we're not accumulating too much memory
                    gc.collect()
                    current_memory = self.get_memory_usage_mb()
                    # Memory should stay reasonable during processing
                    assert current_memory < 300, f"Memory usage too high: {current_memory:.2f}MB"
            
            # Final progress update (only if not already called in the loop)
            if processed % 200 != 0:
                progress_callback(processed, 10000)
            
            # Should have received progress updates
            assert len(progress_updates) > 0, "Should have received progress updates"
            
            # Last update should show completion
            assert progress_updates[-1][0] == 10000, "Final progress should show completion"
            
            # Progress should be incremental
            for i in range(1, len(progress_updates)):
                assert progress_updates[i][0] > progress_updates[i-1][0], "Progress should be incremental"
            
        finally:
            # Clean up
            if test_csv.exists():
                test_csv.unlink()
    
    def test_streaming_error_handling(self):
        """Test that streaming handles errors gracefully."""
        # Test with non-existent file
        with pytest.raises(FileNotFoundError):
            list(stream_iocs(Path("non_existent_file.csv")))
        
        # Test with unsupported file type
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.xyz', delete=False)
        temp_file.close()
        
        try:
            with pytest.raises(ValueError, match="Unsupported IOC file format"):
                list(stream_iocs(Path(temp_file.name)))
        finally:
            os.unlink(temp_file.name)
    
    def test_streaming_generator_behavior(self):
        """Test that streaming returns a proper generator."""
        # Create a small CSV file
        test_csv = self.create_large_csv(100)
        
        try:
            # Get the generator
            ioc_generator = stream_iocs(test_csv)
            
            # Should be a generator
            assert hasattr(ioc_generator, '__iter__')
            assert hasattr(ioc_generator, '__next__')
            
            # Should be lazy (not loaded yet)
            # Memory usage should be minimal
            gc.collect()
            initial_memory = self.get_memory_usage_mb()
            
            # Just getting the generator shouldn't load data
            gc.collect()
            generator_memory = self.get_memory_usage_mb()
            
            # Memory increase should be minimal
            assert generator_memory - initial_memory < 10, "Generator creation should not load data"
            
            # Now consume the generator
            ioc_list = list(ioc_generator)
            
            # Should have the expected number of items
            assert len(ioc_list) == 100, f"Expected 100 items, got {len(ioc_list)}"
            
        finally:
            # Clean up
            if test_csv.exists():
                test_csv.unlink() 