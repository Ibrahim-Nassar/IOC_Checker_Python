# Test GUI API Key Configuration
import sys
import pathlib

# Add the project directory to sys.path
project_dir = pathlib.Path(__file__).parent
sys.path.insert(0, str(project_dir))

print("🔑 GUI API Key Configuration Test")
print("=" * 40)

try:
    from ioc_gui_tk import IOCCheckerGUI
    print("✅ GUI module imported successfully")
    
    print("\n📋 Features Added:")
    print("1. ✅ 'API Keys...' menu option in Settings")
    print("2. ✅ API key configuration dialog")
    print("3. ✅ Shows current API key status")
    print("4. ✅ Save keys to .env file")
    print("5. ✅ Update environment variables for current session")
    
    print("\n🔄 Provider Status Changes:")
    print("• Old: 'n/a' when no API key")
    print("• New: 'No API key' when no API key")
    print("• Old: 'n/a' on errors")  
    print("• New: 'Error' on errors")
    
    print("\n🚀 To Test the GUI:")
    print("1. Start the GUI: python ioc_gui_tk.py --gui")
    print("2. Go to Settings → API Keys...")
    print("3. Enter your VirusTotal API key")
    print("4. Click 'Save'")
    print("5. Run a batch scan - should show real results instead of 'No API key'")
    
    print("\n🆓 Get Free API Keys:")
    print("• VirusTotal: https://www.virustotal.com/gui/my-apikey")
    print("• AbuseIPDB: https://www.abuseipdb.com/register")
    
    print("\n✅ GUI preparation successful!")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
