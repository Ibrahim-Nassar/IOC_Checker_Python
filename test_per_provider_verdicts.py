#!/usr/bin/env python3
"""
Test for per-provider verdict functionality.
Tests the aggregation of provider results and the display of which providers flagged an IOC.
"""
import sys
import os

# Add the project directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_provider_verdict_aggregation():
    """Test the aggregation of provider verdicts."""
    from ioc_checker import aggregate_provider_verdicts, format_verdict_summary
    
    # Test case 1: Malicious IOC flagged by multiple providers
    provider_results_malicious = {
        "virustotal": {"status": "malicious", "score": 90},
        "abuseipdb": {"status": "malicious", "score": 75},
        "shodan": {"status": "clean", "score": 0},
        "greynoise": {"status": "suspicious", "score": 60}
    }
    
    verdict_info = aggregate_provider_verdicts(provider_results_malicious)
    
    assert verdict_info["overall_verdict"] == "malicious", "Should be malicious when providers flag it"
    assert "virustotal" in verdict_info["flagged_by"], "VirusTotal should be in flagged_by"
    assert "abuseipdb" in verdict_info["flagged_by"], "AbuseIPDB should be in flagged_by"
    assert "greynoise" in verdict_info["flagged_by"], "GreyNoise should be in flagged_by (suspicious counts as flagged)"
    assert "shodan" not in verdict_info["flagged_by"], "Shodan should not be in flagged_by"
    assert verdict_info["flagged_count"] == 3, "Should have 3 providers flagging"
    
    summary = format_verdict_summary(verdict_info)
    assert "Malicious" in summary, "Summary should indicate malicious"
    assert "virustotal" in summary.lower() or "abuseipdb" in summary.lower(), "Summary should mention flagging providers"
    
    print("✓ Test 1 passed: Malicious IOC aggregation")
    
    # Test case 2: Clean IOC
    provider_results_clean = {
        "virustotal": {"status": "clean", "score": 0},
        "abuseipdb": {"status": "clean", "score": 0},
        "shodan": {"status": "clean", "score": 0}
    }
    
    verdict_info_clean = aggregate_provider_verdicts(provider_results_clean)
    
    assert verdict_info_clean["overall_verdict"] == "clean", "Should be clean when no providers flag it"
    assert len(verdict_info_clean["flagged_by"]) == 0, "No providers should flag clean IOC"
    assert verdict_info_clean["flagged_count"] == 0, "Should have 0 providers flagging"
    
    summary_clean = format_verdict_summary(verdict_info_clean)
    assert "Clean" in summary_clean, "Summary should indicate clean"
    
    print("✓ Test 2 passed: Clean IOC aggregation")
    
    # Test case 3: Error cases
    provider_results_error = {
        "virustotal": {"status": "error", "score": 0},
        "abuseipdb": {"status": "n/a", "score": 0},
        "shodan": {"status": "error", "score": 0}
    }
    
    verdict_info_error = aggregate_provider_verdicts(provider_results_error)
    
    assert verdict_info_error["overall_verdict"] == "error", "Should be error when all providers fail"
    assert len(verdict_info_error["error_providers"]) == 3, "All providers should be in error list"
    
    print("✓ Test 3 passed: Error case aggregation")
    
    # Test case 4: Mixed results (some flag, some clean, some error)
    provider_results_mixed = {
        "virustotal": {"status": "malicious", "score": 85},
        "abuseipdb": {"status": "clean", "score": 0},
        "shodan": {"status": "error", "score": 0},
        "greynoise": {"status": "clean", "score": 0}
    }
    
    verdict_info_mixed = aggregate_provider_verdicts(provider_results_mixed)
    
    assert verdict_info_mixed["overall_verdict"] == "malicious", "Should be malicious when at least one provider flags it"
    assert verdict_info_mixed["flagged_count"] == 1, "Should have 1 provider flagging"
    assert "virustotal" in verdict_info_mixed["flagged_by"], "VirusTotal should be the flagging provider"
    
    print("✓ Test 4 passed: Mixed results aggregation")

def test_gui_integration():
    """Test that the GUI can display per-provider results."""
    import tkinter as tk
    from ioc_gui_tk import IOCCheckerGUI
    
    # Create a test GUI instance
    root = tk.Tk()
    root.withdraw()  # Hide during testing
    
    try:
        gui = IOCCheckerGUI()
        
        # Test that the results table has the correct columns
        columns = gui.out.cget('columns')
        expected_columns = ('Type', 'IOC', 'Status', 'Flagged By', 'Details')
        
        assert columns == expected_columns, f"Expected columns {expected_columns}, got {columns}"
        
        # Test the _show_result method with flagged_by parameter
        gui._show_result("ip", "1.2.3.4", "Malicious", "Test details", "VirusTotal, AbuseIPDB")
        
        # Verify the result was added correctly
        children = gui.out.get_children()
        assert len(children) == 1, "Should have one result"
        
        values = gui.out.item(children[0])['values']
        assert values[0] == "ip", "Type should be 'ip'"
        assert values[1] == "1.2.3.4", "IOC should be '1.2.3.4'"
        assert values[2] == "Malicious", "Status should be 'Malicious'"
        assert values[3] == "VirusTotal, AbuseIPDB", "Flagged By should show provider names"
        assert values[4] == "Test details", "Details should be preserved"
        
        print("✓ GUI integration test passed")
        
    finally:
        root.quit()
        root.destroy()

def test_mock_provider_checking():
    """Test provider checking with mocked providers (similar to the prompt example)."""
    
    # Mock provider results for testing
    mock_results = {
        "virustotal": {"status": "malicious", "score": 95},
        "shodan": {"status": "clean", "score": 0},
        "greynoise": {"status": "malicious", "score": 80},
        "abuseipdb": {"status": "clean", "score": 5}
    }
    
    from ioc_checker import aggregate_provider_verdicts, format_verdict_summary
    
    verdict_info = aggregate_provider_verdicts(mock_results)
    
    # Check that the correct providers flagged the IOC
    flagged_providers = set(verdict_info["flagged_by"])
    expected_flagged = {"virustotal", "greynoise"}
    
    assert flagged_providers == expected_flagged, f"Expected {expected_flagged}, got {flagged_providers}"
    assert verdict_info["overall_verdict"] == "malicious", "Should be malicious"
    
    # Test the summary format
    summary = format_verdict_summary(verdict_info)
    assert "Malicious" in summary, "Summary should indicate malicious"
    assert "virustotal" in summary.lower(), "Summary should mention VirusTotal"
    assert "greynoise" in summary.lower(), "Summary should mention GreyNoise"
    assert "shodan" not in summary.lower(), "Summary should not mention Shodan (clean result)"
    
    print("✓ Mock provider checking test passed")

def main():
    """Run all tests for per-provider verdict functionality."""
    print("Testing Per-Provider Verdict Functionality...")
    print("=" * 50)
    
    try:
        test_provider_verdict_aggregation()
        test_gui_integration()
        test_mock_provider_checking()
        
        print("=" * 50)
        print("✓ All per-provider verdict tests passed!")
        print("\nPer-provider verdict functionality has been successfully implemented:")
        print("- Provider results are aggregated to show overall verdict")
        print("- Individual providers that flag IOCs are tracked")
        print("- GUI displays which providers flagged each IOC")
        print("- Results table includes 'Flagged By' column")
        print("- Clean, malicious, and error cases are handled properly")
        print("- Summary messages clearly indicate detection results")
        
    except Exception as e:
        print(f"✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
