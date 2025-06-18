# Quick GUI test script
import sys
import pathlib

# Add the project directory to sys.path to import modules
project_dir = pathlib.Path(__file__).parent
sys.path.insert(0, str(project_dir))

print("🧪 Testing GUI Batch Processing")
print("=" * 35)

try:
    from ioc_gui_tk import IOCCheckerGUI
    print("✓ GUI module imported successfully")
    
    # Check if test file exists
    import os
    test_file = "test_urls.txt"
    if os.path.exists(test_file):
        print(f"✓ Test file {test_file} exists")
        
        # Read test file content
        with open(test_file, 'r') as f:
            content = f.read().strip()
            lines = [line.strip() for line in content.split('\n') if line.strip()]
            print(f"✓ Test file contains {len(lines)} URLs:")
            for url in lines:
                print(f"  - {url}")
    else:
        print(f"❌ Test file {test_file} not found")
    
    print(f"\n📋 Instructions for testing:")
    print(f"1. The GUI should be able to start without errors")
    print(f"2. Use the 'Browse' button to select {test_file}")
    print(f"3. Click 'Start Batch Check' to process the URLs")
    print(f"4. Results should be saved to results.csv")
    print(f"5. A dialog should offer to open the CSV file")
    
    print(f"\n🚀 Starting GUI...")
    
    # Uncomment the next two lines to actually start the GUI
    # app = IOCCheckerGUI()
    # app.run()
    
    print("GUI test preparation complete!")
    print("Uncomment the app.run() line in this script to actually start the GUI")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
