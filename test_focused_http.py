#!/usr/bin/env python3
"""
Focused HTTP Test - Specifically test HTTP host header capture
"""

import threading
import time
import socket
import requests
from datetime import datetime

def create_manual_http_request(host, path="/"):
    """Create a manual HTTP request to ensure we capture the Host header"""
    try:
        print(f"📞 Making manual HTTP request to {host}{path}")
        
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        # Connect to server
        sock.connect((host, 80))
        
        # Send HTTP request with explicit Host header
        request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: NetworkTrafficAnalyzer/1.0\r\nConnection: close\r\n\r\n"
        sock.send(request.encode())
        
        # Receive response
        response = sock.recv(4096)
        sock.close()
        
        print(f"✅ Manual HTTP request successful: {len(response)} bytes received")
        return True
        
    except Exception as e:
        print(f"❌ Manual HTTP request failed: {e}")
        return False

def test_focused_http_capture():
    """Test HTTP capture with focused approach"""
    print("=" * 60)
    print("FOCUSED HTTP WEBSITE DETECTION TEST")
    print("=" * 60)
    
    try:
        from packet_sniffer import continuous_sniffing, continuous_packets, get_capture_stats, stop_sniffing
        
        # Clear packets
        continuous_packets.clear()
        
        # Start capture
        print("🚀 Starting packet capture...")
        continuous_sniffing(terminal_live=True)
        time.sleep(2)
        
        # Test 1: Simple DNS lookup
        print("\n🔍 Test 1: DNS Lookup")
        try:
            ip = socket.gethostbyname('httpbin.org')
            print(f"✅ httpbin.org -> {ip}")
        except Exception as e:
            print(f"❌ DNS lookup failed: {e}")
        
        time.sleep(2)
        
        # Test 2: Manual HTTP request
        print("\n📡 Test 2: Manual HTTP Request")
        create_manual_http_request('httpbin.org', '/ip')
        
        time.sleep(2)
        
        # Test 3: Simple HTTP request with requests library
        print("\n🌐 Test 3: Requests Library HTTP")
        try:
            response = requests.get('http://httpbin.org/headers', timeout=10)
            print(f"✅ HTTP request successful: {response.status_code}")
        except Exception as e:
            print(f"❌ HTTP request failed: {e}")
        
        time.sleep(3)
        
        # Analyze results
        print("\n📊 ANALYSIS:")
        total_packets = len(continuous_packets)
        print(f"Total packets: {total_packets}")
        
        websites_found = []
        dns_queries = []
        http_requests = []
        
        for i, pkt in enumerate(continuous_packets):
            if pkt.get('website_visited') and pkt['website_visited'] != "N/A":
                websites_found.append(pkt['website_visited'])
            
            if pkt.get('dns_query') and pkt['dns_query'] != "N/A":
                dns_queries.append(pkt['dns_query'])
                
            if pkt.get('protocol') == 'HTTP':
                http_requests.append(pkt.get('http_payload', 'N/A'))
            
            # Show details of first 5 packets
            if i < 5:
                print(f"  Packet {i+1}: {pkt['protocol']} | {pkt.get('website_visited', 'N/A')} | {pkt.get('src_ip')} -> {pkt.get('dst_ip')}")
        
        print(f"\n🌐 Websites detected: {set(websites_found)}")
        print(f"🔍 DNS queries: {set(dns_queries)}")
        print(f"📡 HTTP requests: {len(http_requests)}")
        
        for req in http_requests[:3]:  # Show first 3 HTTP requests
            print(f"  • {req}")
        
        # Check if httpbin.org was detected
        httpbin_detected = any('httpbin' in str(site).lower() for site in websites_found + dns_queries)
        
        stop_sniffing()
        
        if httpbin_detected:
            print(f"\n🎉 SUCCESS: httpbin.org was detected!")
        else:
            print(f"\n💔 ISSUE: httpbin.org was not detected in website fields")
            print("This suggests the HTTP Host header extraction needs more work")
        
        return httpbin_detected
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_focused_http_capture()
    
    if success:
        print("\n✅ HTTP website detection is working!")
    else:
        print("\n🔧 HTTP website detection needs debugging")
        print("\nNext steps:")
        print("1. Check if HTTP packets are being captured")
        print("2. Verify Host header extraction logic")
        print("3. Test with different HTTP requests")
