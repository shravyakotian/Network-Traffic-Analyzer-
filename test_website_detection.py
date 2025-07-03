#!/usr/bin/env python3
"""
Enhanced Network Traffic Test - Focus on Website Detection
This script generates specific HTTP/HTTPS requests and checks if they're properly captured.
"""

import threading
import time
import requests
import socket
from datetime import datetime
import sys
import subprocess

def test_dns_resolution():
    """Test DNS resolution to generate DNS packets"""
    print("\n🔍 Testing DNS Resolution...")
    
    domains = [
        "httpbin.org",
        "jsonplaceholder.typicode.com", 
        "api.github.com",
        "google.com",
        "stackoverflow.com"
    ]
    
    resolved = []
    for domain in domains:
        try:
            ip = socket.gethostbyname(domain)
            print(f"  ✅ {domain} -> {ip}")
            resolved.append((domain, ip))
            time.sleep(0.5)
        except Exception as e:
            print(f"  ❌ {domain} -> Error: {e}")
    
    return resolved

def test_http_requests():
    """Test HTTP requests to generate HTTP packets"""
    print("\n📡 Testing HTTP Requests...")
    
    # HTTP requests (unencrypted - easier to capture)
    http_urls = [
        "http://httpbin.org/ip",
        "http://httpbin.org/headers", 
        "http://httpbin.org/user-agent",
        "http://httpbin.org/get"
    ]
    
    # HTTPS requests 
    https_urls = [
        "https://httpbin.org/json",
        "https://jsonplaceholder.typicode.com/posts/1",
        "https://api.github.com/users/octocat"
    ]
    
    results = []
    
    print("  📞 Making HTTP requests (should show Host headers)...")
    for url in http_urls:
        try:
            print(f"    Requesting: {url}")
            response = requests.get(url, timeout=10)
            print(f"    ✅ HTTP {response.status_code}: {len(response.content)} bytes")
            results.append(('HTTP', url, response.status_code))
            time.sleep(2)  # Allow time for packet capture
        except Exception as e:
            print(f"    ❌ Error: {e}")
    
    print("  🔒 Making HTTPS requests (should show SNI)...")
    for url in https_urls:
        try:
            print(f"    Requesting: {url}")
            response = requests.get(url, timeout=10)
            print(f"    ✅ HTTPS {response.status_code}: {len(response.content)} bytes")
            results.append(('HTTPS', url, response.status_code))
            time.sleep(2)  # Allow time for packet capture
        except Exception as e:
            print(f"    ❌ Error: {e}")
    
    return results

def run_enhanced_packet_test():
    """Run enhanced packet capture test with website detection"""
    print("=" * 70)
    print("ENHANCED NETWORK TRAFFIC TEST - WEBSITE DETECTION")
    print("=" * 70)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Import the packet sniffer
        from packet_sniffer import continuous_sniffing, continuous_packets, get_capture_stats, stop_sniffing
        
        # Clear any existing packets
        continuous_packets.clear()
        
        # Start packet capture with terminal output
        print("\n🚀 Starting enhanced packet capture...")
        continuous_sniffing(terminal_live=True)  # Enable terminal output
        
        # Wait for capture to start
        time.sleep(2)
        
        # Test DNS resolution
        resolved_domains = test_dns_resolution()
        
        # Test HTTP/HTTPS requests
        http_results = test_http_requests()
        
        # Wait for packets to be processed
        print("\n⏰ Waiting 5 seconds for packet processing...")
        time.sleep(5)
        
        # Analyze results
        stats = get_capture_stats()
        total_packets = len(continuous_packets)
        
        print(f"\n📊 CAPTURE RESULTS:")
        print(f"   Total packets captured: {total_packets}")
        print(f"   Stats total: {stats['total_packets']}")
        print(f"   Capture errors: {len(stats.get('errors', []))}")
        
        if stats.get('errors'):
            print("   ❌ Errors:")
            for error in stats['errors'][-3:]:
                print(f"     • {error}")
        
        # Analyze website detection
        websites_detected = set()
        dns_queries_detected = set()
        http_hosts_detected = set()
        
        for pkt in continuous_packets:
            if pkt.get('website_visited') and pkt['website_visited'] != "N/A":
                websites_detected.add(pkt['website_visited'])
            
            if pkt.get('dns_query') and pkt['dns_query'] != "N/A":
                dns_queries_detected.add(pkt['dns_query'])
            
            if pkt.get('http_payload') and 'httpbin.org' in pkt.get('http_payload', ''):
                http_hosts_detected.add(pkt['http_payload'][:100])
        
        print(f"\n🌐 WEBSITE DETECTION ANALYSIS:")
        print(f"   Websites detected: {len(websites_detected)}")
        for site in sorted(websites_detected):
            print(f"     • {site}")
        
        print(f"   DNS queries detected: {len(dns_queries_detected)}")
        for query in sorted(dns_queries_detected):
            print(f"     • {query}")
        
        print(f"   HTTP traffic detected: {len(http_hosts_detected)}")
        for http in sorted(http_hosts_detected):
            print(f"     • {http}")
        
        # Check if we detected the expected websites
        expected_sites = {'httpbin.org', 'jsonplaceholder.typicode.com', 'api.github.com'}
        detected_expected = expected_sites.intersection(websites_detected)
        
        print(f"\n🎯 EXPECTED WEBSITE DETECTION:")
        print(f"   Expected: {expected_sites}")
        print(f"   Detected: {detected_expected}")
        print(f"   Success rate: {len(detected_expected)}/{len(expected_sites)} ({len(detected_expected)/len(expected_sites)*100:.1f}%)")
        
        # Show protocol distribution
        protocols = {}
        for pkt in continuous_packets:
            proto = pkt.get('protocol', 'Unknown')
            protocols[proto] = protocols.get(proto, 0) + 1
        
        print(f"\n📈 PROTOCOL DISTRIBUTION:")
        for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
            print(f"   {proto}: {count}")
        
        # Stop capture
        stop_sniffing()
        
        # Determine success
        success = (
            total_packets > 10 and  # Captured packets
            len(websites_detected) > 0 and  # Detected websites
            len(detected_expected) > 0  # Detected expected sites
        )
        
        if success:
            print(f"\n🎉 TEST PASSED: Website detection is working!")
            print(f"   ✅ Captured {total_packets} packets")
            print(f"   ✅ Detected {len(websites_detected)} websites")
            print(f"   ✅ Found {len(detected_expected)} expected sites")
        else:
            print(f"\n💔 TEST FAILED: Website detection needs improvement")
            print(f"   📦 Packets: {total_packets}")
            print(f"   🌐 Websites: {len(websites_detected)}")
            print(f"   🎯 Expected: {len(detected_expected)}")
        
        return success
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    try:
        success = run_enhanced_packet_test()
        
        if success:
            print(f"\n✅ CONCLUSION: The enhanced packet sniffer is working correctly!")
            print(f"   Now try the Streamlit app and you should see websites being detected.")
        else:
            print(f"\n❌ CONCLUSION: Further debugging needed for website detection.")
            
    except KeyboardInterrupt:
        print(f"\n\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()
