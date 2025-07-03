#!/usr/bin/env python3
"""
Network Traffic Analyzer - Web Request Test
This script generates web requests while monitoring packet capture to verify the sniffer works.
"""

import threading
import time
import requests
import socket
from datetime import datetime
import sys

def generate_web_traffic():
    """Generate various types of web traffic for testing"""
    print("\n🌐 Generating web traffic for testing...")
    
    # List of websites to visit
    test_urls = [
        "http://httpbin.org/ip",
        "https://httpbin.org/user-agent", 
        "http://httpbin.org/headers",
        "https://jsonplaceholder.typicode.com/posts/1",
        "http://httpbin.org/delay/1",
        "https://httpbin.org/json",
        "http://httpbin.org/xml",
        "https://api.github.com/users/octocat",
    ]
    
    dns_lookups = [
        "google.com",
        "stackoverflow.com",
        "github.com",
        "python.org",
        "microsoft.com"
    ]
    
    total_requests = 0
    successful_requests = 0
    
    # Perform DNS lookups
    print("🔍 Performing DNS lookups...")
    for domain in dns_lookups:
        try:
            ip = socket.gethostbyname(domain)
            print(f"  ✅ {domain} -> {ip}")
            total_requests += 1
            successful_requests += 1
            time.sleep(0.5)  # Small delay between requests
        except Exception as e:
            print(f"  ❌ {domain} -> Error: {e}")
            total_requests += 1
    
    # Perform HTTP requests
    print("\n📡 Making HTTP requests...")
    for url in test_urls:
        try:
            print(f"  📞 Requesting: {url}")
            response = requests.get(url, timeout=10)
            print(f"  ✅ Status: {response.status_code}, Size: {len(response.content)} bytes")
            total_requests += 1
            successful_requests += 1
            time.sleep(1)  # Delay between requests
        except Exception as e:
            print(f"  ❌ Error: {e}")
            total_requests += 1
    
    print(f"\n📊 Traffic generation complete!")
    print(f"   Total requests: {total_requests}")
    print(f"   Successful: {successful_requests}")
    print(f"   Failed: {total_requests - successful_requests}")
    
    return total_requests, successful_requests

def test_packet_capture_with_traffic():
    """Test packet capture while generating web traffic"""
    print("=" * 60)
    print("NETWORK TRAFFIC ANALYZER - WEB REQUEST TEST")
    print("=" * 60)
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # Import the packet sniffer
        from packet_sniffer import continuous_sniffing, continuous_packets, get_capture_stats, stop_sniffing
        
        # Clear any existing packets
        continuous_packets.clear()
        
        # Start packet capture
        print("\n🚀 Starting packet capture...")
        continuous_sniffing()
        
        # Wait a moment for capture to start
        time.sleep(2)
        
        # Check initial stats
        initial_stats = get_capture_stats()
        print(f"📊 Initial packet count: {initial_stats['total_packets']}")
        
        # Generate web traffic in a separate thread
        traffic_thread = threading.Thread(target=generate_web_traffic)
        traffic_thread.start()
        
        # Monitor packet capture for 30 seconds
        print("\n👀 Monitoring packet capture for 30 seconds...")
        monitoring_start = time.time()
        last_count = 0
        
        while time.time() - monitoring_start < 30 and traffic_thread.is_alive():
            current_stats = get_capture_stats()
            current_count = len(continuous_packets)
            
            if current_count != last_count:
                print(f"  📦 Packets captured: {current_count} (Stats: {current_stats['total_packets']})")
                last_count = current_count
            
            # Show some recent packets
            if len(continuous_packets) > 0:
                recent_packets = continuous_packets[-3:]  # Last 3 packets
                for i, pkt in enumerate(recent_packets):
                    print(f"    [{i+1}] {pkt['timestamp']} | {pkt['protocol']} | "
                          f"{pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
            
            time.sleep(2)
        
        # Wait for traffic generation to complete
        traffic_thread.join(timeout=10)
        
        # Final statistics
        time.sleep(3)  # Give time for last packets to be processed
        final_stats = get_capture_stats()
        final_count = len(continuous_packets)
        
        print(f"\n📊 FINAL RESULTS:")
        print(f"   Total packets captured: {final_count}")
        print(f"   Stats total: {final_stats['total_packets']}")
        print(f"   Capture errors: {len(final_stats['errors'])}")
        
        if final_stats['errors']:
            print("   ❌ Errors encountered:")
            for error in final_stats['errors'][-5:]:  # Show last 5 errors
                print(f"     • {error}")
        
        # Analyze captured packets
        if continuous_packets:
            print(f"\n🔍 PACKET ANALYSIS:")
            
            # Count protocols
            protocols = {}
            domains_seen = set()
            ips_seen = set()
            
            for pkt in continuous_packets:
                proto = pkt['protocol']
                protocols[proto] = protocols.get(proto, 0) + 1
                
                if pkt['src_domain'] and pkt['src_domain'] != "N/A":
                    domains_seen.add(pkt['src_domain'])
                if pkt['dst_domain'] and pkt['dst_domain'] != "N/A":
                    domains_seen.add(pkt['dst_domain'])
                    
                if pkt['src_ip'] and pkt['src_ip'] != "N/A":
                    ips_seen.add(pkt['src_ip'])
                if pkt['dst_ip'] and pkt['dst_ip'] != "N/A":
                    ips_seen.add(pkt['dst_ip'])
            
            print(f"   📈 Protocol distribution:")
            for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                print(f"     {proto}: {count}")
            
            print(f"   🌐 Domains seen: {len(domains_seen)}")
            for domain in sorted(domains_seen)[:10]:  # Show first 10
                print(f"     • {domain}")
            
            print(f"   🖥️  IP addresses seen: {len(ips_seen)}")
            for ip in sorted(ips_seen)[:10]:  # Show first 10
                print(f"     • {ip}")
                
            # Show some HTTP traffic
            http_packets = [pkt for pkt in continuous_packets if 'HTTP' in pkt['protocol']]
            if http_packets:
                print(f"   🌍 HTTP packets captured: {len(http_packets)}")
                for pkt in http_packets[:3]:  # Show first 3
                    print(f"     • {pkt['timestamp']} | {pkt['src_ip']} -> {pkt['dst_ip']}")
            
            # Show DNS queries
            dns_packets = [pkt for pkt in continuous_packets if pkt['dns_query'] != "N/A"]
            if dns_packets:
                print(f"   🔍 DNS queries captured: {len(dns_packets)}")
                for pkt in dns_packets[:5]:  # Show first 5
                    print(f"     • {pkt['dns_query']}")
            
            print(f"\n✅ SUCCESS: Packet capture is working!")
            print(f"   📊 Captured {final_count} packets during web traffic generation")
            
        else:
            print(f"\n❌ FAILURE: No packets captured!")
            print("   Possible issues:")
            print("   • Insufficient permissions (try running as Administrator)")
            print("   • Wrong network interface selected")
            print("   • Firewall blocking packet capture")
            print("   • No network traffic generated")
        
        # Stop capture
        print(f"\n🛑 Stopping packet capture...")
        stop_sniffing()
        
        return final_count > 0
        
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

def quick_packet_test():
    """Quick test to see if basic packet capture works"""
    print("\n🔧 Quick packet capture test...")
    
    try:
        from scapy.all import sniff
        print("   Testing 5-second packet capture...")
        
        captured = []
        def packet_handler(pkt):
            captured.append(pkt)
            if len(captured) <= 5:  # Show first 5
                print(f"   📦 Packet {len(captured)}: {pkt.summary()}")
        
        sniff(prn=packet_handler, timeout=5, count=20)
        
        print(f"   ✅ Captured {len(captured)} packets in 5 seconds")
        return len(captured) > 0
        
    except Exception as e:
        print(f"   ❌ Quick test failed: {e}")
        return False

if __name__ == "__main__":
    try:
        # Run quick test first
        if quick_packet_test():
            print("✅ Basic packet capture works, proceeding with full test...")
            success = test_packet_capture_with_traffic()
        else:
            print("❌ Basic packet capture failed, skipping full test")
            success = False
            
        if success:
            print(f"\n🎉 TEST PASSED: Network traffic analyzer is working correctly!")
        else:
            print(f"\n💔 TEST FAILED: Network traffic analyzer needs debugging")
            
    except KeyboardInterrupt:
        print(f"\n\n⏹️  Test interrupted by user")
    except Exception as e:
        print(f"\n💥 Unexpected error: {e}")
        import traceback
        traceback.print_exc()
