#!/usr/bin/env python3
"""
Simple test to verify browser traffic detection
"""
import time
import webbrowser
import requests
from datetime import datetime

def test_browser_traffic():
    """Test various types of web traffic"""
    print("🧪 Testing browser traffic detection...")
    print("=" * 50)
    
    # Test 1: HTTP request
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Test 1: Making HTTP request to httpbin.org")
    try:
        response = requests.get("http://httpbin.org/get", timeout=5)
        print(f"✅ HTTP request successful: {response.status_code}")
    except Exception as e:
        print(f"❌ HTTP request failed: {e}")
    
    time.sleep(2)
    
    # Test 2: HTTPS request
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Test 2: Making HTTPS request to httpbin.org")
    try:
        response = requests.get("https://httpbin.org/get", timeout=5)
        print(f"✅ HTTPS request successful: {response.status_code}")
    except Exception as e:
        print(f"❌ HTTPS request failed: {e}")
    
    time.sleep(2)
    
    # Test 3: DNS heavy request
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Test 3: Making request to generate DNS traffic")
    try:
        response = requests.get("https://api.github.com/users/octocat", timeout=5)
        print(f"✅ GitHub API request successful: {response.status_code}")
    except Exception as e:
        print(f"❌ GitHub API request failed: {e}")
    
    time.sleep(2)
    
    # Test 4: Multiple requests to different domains
    test_urls = [
        "https://www.google.com",
        "https://www.microsoft.com",
        "https://www.github.com",
        "https://stackoverflow.com"
    ]
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Test 4: Making requests to multiple domains")
    for url in test_urls:
        try:
            response = requests.get(url, timeout=5)
            print(f"✅ {url}: {response.status_code}")
        except Exception as e:
            print(f"❌ {url}: {e}")
        time.sleep(1)
    
    print("=" * 50)
    print("🧪 Browser traffic test completed!")
    print("📊 Check the monitor output for detected traffic")

if __name__ == "__main__":
    test_browser_traffic()
