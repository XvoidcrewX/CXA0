#CXA - Test Runner One-click test execution with detailed reporting

import sys
import os
import time
from datetime import datetime

def main():
    print("CXA CRYPTO SYSTEM - TEST RUNNER")
    print("=" * 50)
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, current_dir)
    
    try:
        from comprehensive_test import run_comprehensive_tests
    except ImportError as e:
        print(f"❌ Error importing test module: {e}")
        print("💡 Make sure comprehensive_test.py is in the same directory")
        return False
    
    start_time = time.time()
    start_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    print(f"📅 Test started at: {start_datetime}")
    print("⏳ Running comprehensive test suite...")
    print()
    
    try:
        success = run_comprehensive_tests()
        
        duration = time.time() - start_time
        minutes, seconds = divmod(duration, 60)
        
        print()
        print("=" * 50)
        print("📋 TEST EXECUTION COMPLETE")
        print(f"⏱️  Total duration: {int(minutes)}m {seconds:.2f}s")
        
        if success:
            print("✅ ALL TESTS PASSED - System is ready!")
            return True
        else:
            print("❌ TESTS FAILED - Review errors above")
            return False
            
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
