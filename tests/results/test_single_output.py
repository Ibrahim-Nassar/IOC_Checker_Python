"""
Test that only CSV files are generated, no JSON/XLSX/HTML side files.
"""
import pytest
import tempfile
import os
import subprocess
from pathlib import Path
from unittest.mock import patch, Mock


def test_single_csv_output_only():
    """Test that CSV processing generates only one CSV file."""
    # Create a minimal test CSV
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ioc\n127.0.0.1\nexample.com\n")
        input_csv = f.name
    
    output_csv = input_csv.replace('.csv', '_results.csv')
    
    try:
        # Mock providers to avoid network calls
        with patch('ioc_checker.ALWAYS_ON') as mock_always:
            with patch('ioc_checker.RATE_LIMIT', []):
                # Mock provider that returns structured data
                mock_provider = Mock()
                mock_provider.name = "test_provider"
                mock_provider.ioc_kinds = ("ip", "domain")
                mock_provider.query.return_value = {"status": "clean", "score": 0, "raw": {}}
                mock_always.__iter__.return_value = [mock_provider]
                
                # Import and test process_csv
                from ioc_checker import process_csv
                import asyncio
                
                # Run the CSV processing
                asyncio.run(process_csv(input_csv, output_csv, False))
        
        # Verify only CSV file exists
        assert Path(output_csv).exists(), "CSV output file should exist"
        
        # Verify no extra files were created
        base_path = Path(output_csv).with_suffix('')
        assert not Path(f"{base_path}.json").exists(), "JSON file should NOT be created"
        assert not Path(f"{base_path}.xlsx").exists(), "XLSX file should NOT be created" 
        assert not Path(f"{base_path}.html").exists(), "HTML file should NOT be created"
        
        # Verify CSV content has clean structure
        with open(output_csv, 'r', encoding='utf-8') as f:
            content = f.read()
            # Should have clean column headers
            assert "ioc,ioc_type,vt_status,otx_status,abuseipdb_status,threatfox_status,urlhaus_status,overall" in content
            assert "127.0.0.1" in content
            assert "example.com" in content
        
    finally:
        # Clean up
        for file_path in [input_csv, output_csv]:
            if os.path.exists(file_path):
                os.unlink(file_path)
        
        # Clean up any potential side files
        base_path = Path(output_csv).with_suffix('')
        for ext in ['.json', '.xlsx', '.html']:
            side_file = f"{base_path}{ext}"
            if os.path.exists(side_file):
                os.unlink(side_file)


def test_reports_writers_only_csv():
    """Test that WRITERS dict only contains CSV writer."""
    from reports import WRITERS
    
    # Should only have CSV writer
    assert len(WRITERS) == 1, f"Expected only 1 writer, got {len(WRITERS)}"
    assert "csv" in WRITERS, "CSV writer should be present"
    
    # Should NOT have other writers
    assert "json" not in WRITERS, "JSON writer should be removed"
    assert "xlsx" not in WRITERS, "XLSX writer should be removed"
    assert "html" not in WRITERS, "HTML writer should be removed"


def test_cli_csv_processing_single_output():
    """Test CLI CSV processing creates only CSV output."""
    # Create test CSV
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ioc\n8.8.8.8\n")
        input_csv = f.name
    
    output_csv = "test_single_output.csv"
    
    try:
        # Mock the providers to avoid real network calls
        with patch('ioc_checker.ALWAYS_ON') as mock_always:
            with patch('ioc_checker.RATE_LIMIT', []):
                mock_provider = Mock()
                mock_provider.name = "mock_provider"
                mock_provider.ioc_kinds = ("ip",)
                mock_provider.query.return_value = {"status": "clean", "score": 0, "raw": {}}
                mock_always.__iter__.return_value = [mock_provider]
                
                # Run CLI command
                subprocess.run([
                    "python", "ioc_checker.py", "--csv", input_csv, "-o", output_csv
                ], capture_output=True, text=True, cwd="d:/KAS/python_scripts/Python_IOC_Checker")
        
        # Verify only CSV file was created
        assert os.path.exists(output_csv), "CSV output should exist"
        
        # Check for unwanted side files
        base_name = output_csv.replace('.csv', '')
        side_files = [
            f"{base_name}.json",
            f"{base_name}.xlsx", 
            f"{base_name}.html"
        ]
        
        for side_file in side_files:
            assert not os.path.exists(side_file), f"Side file {side_file} should NOT exist"
        
        # Verify CSV has clean structure
        with open(output_csv, 'r', encoding='utf-8') as f:
            content = f.read()
            assert "ioc,ioc_type" in content, "Should have clean CSV headers"
            assert "8.8.8.8" in content, "Should contain the test IOC"
            
    finally:
        # Clean up all possible output files
        cleanup_files = [input_csv, output_csv, "test_single_output.json", "test_single_output.xlsx", "test_single_output.html"]
        for file_path in cleanup_files:
            if os.path.exists(file_path):
                os.unlink(file_path)


def test_gui_csv_processing_single_output():
    """Test GUI CSV processing creates only CSV output."""
    # Create test CSV
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ioc\ndomain.com\n")
        input_csv = f.name
    
    input_csv.replace('.csv', '_results')
    
    try:
        # Mock GUI subprocess call
        with patch('ioc_gui_tk.subprocess.Popen') as mock_popen:
            # Mock process that simulates our enhanced CLI
            mock_process = Mock()
            mock_process.poll.return_value = 0  # Completed
            mock_process.stdout.readline.side_effect = [
                "Processing IOC: domain.com\n",
                "Result: domain.com (domain)\n",
                "  test_provider: clean\n",
                "CSV processing complete! Clean report saved to results.csv\n",
                ""  # End
            ]
            mock_process.stdout.read.return_value = ""
            mock_popen.return_value = mock_process
            
            # Simulate GUI batch call
            from ioc_gui_tk import App
            app = object.__new__(App)
            app.cfg = {}
            app.proc = None
            app.auto_clear = Mock()
            app.auto_clear.get.return_value = False
            app.path = Mock()
            app.path.get.return_value = input_csv
            app.out = Mock()
            app.out.config = Mock()
            app.out.insert = Mock()
            app.out.see = Mock()
            
            # Apply the batch method
            app.batch = App.batch.__get__(app, type(app))
            app._start = App._start.__get__(app, type(app))
            app.after = Mock()
            app.update_idletasks = Mock()
            
            app.batch()
            
            # Verify command was constructed correctly for single CSV output
            mock_popen.assert_called_once()
            args, kwargs = mock_popen.call_args
            command = args[0]
            
            # Should include --csv and -o for single CSV output
            assert "--csv" in command
            assert "-o" in command
            
            # Should not include any flags that would create multiple files
            command_str = " ".join(command)
            assert "json" not in command_str.lower()
            assert "xlsx" not in command_str.lower()
            assert "html" not in command_str.lower()
            
    finally:
        # Clean up
        if os.path.exists(input_csv):
            os.unlink(input_csv)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])