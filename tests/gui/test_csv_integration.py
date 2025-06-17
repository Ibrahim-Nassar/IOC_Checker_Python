"""
Test CSV integration in GUI - reproduce and verify fix for "CSV → no output" bug.
"""
import pytest
import tempfile
import os
import time
import subprocess
from unittest.mock import Mock


def test_csv_integration_shows_results():
    """Test that CSV processing now shows individual IOC results."""
    # Create a test CSV file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False) as f:
        f.write("ioc\n")
        f.write("127.0.0.1\n")
        f.write("example.com\n") 
        csv_path = f.name
    
    try:
        # Test the CLI directly to ensure our enhancements work
        result = subprocess.run([
            "python", "ioc_checker.py", "--csv", csv_path, "-o", "test_output.csv"
        ], capture_output=True, text=True, cwd="d:/KAS/python_scripts/Python_IOC_Checker")
        
        print(f"CLI stdout: {result.stdout}")
        print(f"CLI stderr: {result.stderr}")
        
        # Verify the CLI now outputs individual IOC results
        assert "Processing IOC:" in result.stdout, "Should show processing status"
        assert "Result:" in result.stdout, "Should show individual results"
        assert "127.0.0.1" in result.stdout, "Should show the actual IOC"
        assert "CSV processing complete!" in result.stdout, "Should show completion"
        
        # Now test the GUI subprocess approach with our enhanced polling
        from ioc_gui_tk import App
        
        # Create minimal app instance to test the batch method
        app_instance = type('MockApp', (), {})()
        app_instance.cfg = {}
        app_instance.proc = None
        app_instance.auto_clear = Mock()
        app_instance.auto_clear.get.return_value = False
        app_instance.path = Mock()
        app_instance.path.get.return_value = csv_path
        
        # Mock the text widget to capture output
        output_lines = []
        text_widget = Mock()
        def capture_insert(pos, text):
            output_lines.append(text)
            print(f"GUI captured: {repr(text)}")
        text_widget.insert = capture_insert
        text_widget.config = Mock()
        text_widget.see = Mock()
        app_instance.out = text_widget
        
        # Apply the actual batch method from App
        app_instance.batch = App.batch.__get__(app_instance, type(app_instance))
        app_instance._start = App._start.__get__(app_instance, type(app_instance))
        app_instance._poll = App._poll.__get__(app_instance, type(app_instance))
        app_instance.after = Mock()  # Mock tkinter's after method
        app_instance.update_idletasks = Mock()  # Mock GUI update
        
        # Start the batch process
        app_instance.batch()
        
        # Verify initial status messages are added
        assert len(output_lines) >= 4, "Should have initial status messages"
        assert any("Starting CSV processing" in line for line in output_lines)
        assert any("Command:" in line for line in output_lines)
        
        # Wait for subprocess to start and process
        time.sleep(0.1)
        
        # Poll for output multiple times to simulate the GUI loop
        for i in range(100):  # Poll for up to 10 seconds
            if app_instance.proc:
                app_instance._poll()
                if app_instance.proc is None:  # Process completed
                    break
            time.sleep(0.1)
        
        print(f"Total output lines captured: {len(output_lines)}")
        for i, line in enumerate(output_lines):
            print(f"Line {i}: {repr(line)}")
        
        # Verify we now capture the enhanced output
        all_output = ''.join(output_lines)
        assert "Processing IOC:" in all_output, "Should show IOC processing status"
        assert "Result:" in all_output, "Should show individual IOC results"
        assert "CSV processing complete!" in all_output, "Should show completion message"
        
    finally:
        if os.path.exists(csv_path):
            os.unlink(csv_path)
        # Clean up any created output files
        for ext in [".csv", ".json", ".xlsx", ".html"]:
            output_file = csv_path.replace(".csv", f"_results{ext}")
            if os.path.exists(output_file):
                os.unlink(output_file)


def test_gui_polling_captures_real_time_output():
    """Test that the enhanced polling mechanism captures real-time output."""
    from ioc_gui_tk import App
    
    # Create a mock app with the enhanced _poll method
    app_instance = type('MockApp', (), {})()
    app_instance.proc = None
    
    # Mock text widget
    output_content = []
    text_widget = Mock()
    text_widget.insert = lambda pos, text: output_content.append(text)
    text_widget.config = Mock()
    text_widget.see = Mock()
    app_instance.out = text_widget
    app_instance.update_idletasks = Mock()
    
    # Mock a subprocess with our enhanced output format
    mock_proc = Mock()
    mock_proc.poll.side_effect = [None, None, None, 0]  # Running, then finished
    mock_proc.stdout.readline.side_effect = [
        "Processing IOC: 8.8.8.8\n",
        "Result: 8.8.8.8 (ip)\n",
        "  abuseipdb: Clean\n",
        "Processing IOC: example.com\n", 
        "Result: example.com (domain)\n",
        "  abuseipdb: Clean\n",
        "CSV processing complete! Reports saved to results.csv*\n",
        ""  # End of output
    ]
    mock_proc.stdout.read.return_value = ""  # No remaining output
    
    app_instance.proc = mock_proc
    
    # Apply the actual _poll method from App
    app_instance._poll = App._poll.__get__(app_instance, type(app_instance))
    app_instance.after = Mock()  # Mock tkinter's after method
    
    # Call _poll multiple times to simulate the polling loop
    app_instance._poll()
    app_instance._poll() 
    app_instance._poll()
    app_instance._poll()  # This one should complete the process
    
    print(f"Enhanced output captured: {output_content}")
    
    # Should have captured the enhanced subprocess output
    assert len(output_content) >= 7, "Should capture all subprocess output lines"
    assert any("Processing IOC:" in line for line in output_content)
    assert any("Result:" in line for line in output_content)
    assert any("Clean" in line for line in output_content)
    assert any("CSV processing complete!" in line for line in output_content)
    assert app_instance.proc is None, "Process should be cleared when finished"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])