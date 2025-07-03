#!/usr/bin/env python3
"""
Simple test to verify the Network Traffic Analyzer in Streamlit
"""

import time
import threading
import requests
from datetime import datetime

def generate_test_traffic():
    """Generate simple test traffic"""
    print("🌐 Generating test traffic...")
    
    urls = [
        "http://httpbin.org/ip",
        "https://httpbin.org/json",
        "http://httpbin.org/headers"
    ]
    
    for url in urls:
        try:
            print(f"📞 Requesting: {url}")
            response = requests.get(url, timeout=5)
            print(f"✅ Response: {response.status_code}")
            time.sleep(2)
        except Exception as e:
            print(f"❌ Error: {e}")

def test_streamlit_app():
    """Test the Streamlit app with generated traffic"""
    print("=" * 50)
    print("STREAMLIT APP TEST")
    print("=" * 50)
    
    # Start the traffic generator in background
    traffic_thread = threading.Thread(target=generate_test_traffic)
    traffic_thread.daemon = True
    traffic_thread.start()
    
    print("🚀 Starting Streamlit app...")
    print("👉 After the app starts:")
    print("   1. Click 'Start Continuous Monitoring'")
    print("   2. Select fields to display in sidebar")
    print("   3. Check 'Show All Packets' to see all captured data")
    print("   4. Use the debug buttons to troubleshoot")
    print("   5. Look for the packet count increasing")
    
    # Start Streamlit
    import subprocess
    import os
    
    env = os.environ.copy()
    venv_python = "c:/Users/raksh/Music/Projects/Network-Traffic-Analyzer-/venv/Scripts/python.exe"
    streamlit_cmd = "c:/Users/raksh/Music/Projects/Network-Traffic-Analyzer-/venv/Scripts/streamlit.exe"
    
    cmd = [streamlit_cmd, "run", "app_ui.py"]
    
    try:
        subprocess.run(cmd, cwd="c:/Users/raksh/Music/Projects/Network-Traffic-Analyzer-")
    except KeyboardInterrupt:
        print("\n👋 Streamlit app stopped by user")

if __name__ == "__main__":
    test_streamlit_app()
