#!/usr/bin/env python3
"""
Test the Streamlit app directly with HTTP requests
"""
import time
import requests
import threading
from packet_sniffer import continuous_sniffing, continuous_packets, stop_sniffing, get_capture_stats

def test_streamlit_sniffer():
    """Test the packet sniffer as used by Streamlit"""
    print("🔍 Testing Streamlit packet sniffer...")
    
    # Clear any existing packets
    continuous_packets.clear()
    
    # Start the sniffer (same as Streamlit does)
    print("🚀 Starting continuous sniffing...")
    continuous_sniffing(interface=None)
    
    # Wait for initialization
    time.sleep(2)
    
    print(f"📊 Initial packets: {len(continuous_packets)}")
    
    # Make HTTP requests
    print("\n🌐 Making HTTP requests...")
    test_urls = [
        'http://httpbin.org/json',
        'http://jsonplaceholder.typicode.com/posts/1',
        'http://httpbin.org/get'
    ]
    
    for url in test_urls:
        try:
            print(f"📡 Requesting {url}...")
            response = requests.get(url, timeout=10)
            print(f"✅ {url} responded with {response.status_code}")
            
            # Wait for packets to be captured
            time.sleep(3)
            current_count = len(continuous_packets)
            print(f"📊 Packets after request: {current_count}")
            
        except Exception as e:
            print(f"❌ Error with {url}: {e}")
    
    # Wait for all processing to complete
    print("\n⏳ Waiting for all packets to be processed...")
    time.sleep(5)
    
    # Stop the sniffer
    print("\n🛑 Stopping sniffer...")
    stop_sniffing()
    time.sleep(2)
    
    # Analyze results
    final_count = len(continuous_packets)
    print(f"\n📊 Final packet count: {final_count}")
    
    if final_count == 0:
        print("❌ No packets captured!")
        return
    
    # Check capture stats
    stats = get_capture_stats()
    print(f"📈 Capture stats: {stats}")
    
    # Analyze packets
    print("\n🔍 Analyzing captured packets...")
    
    protocols = {}
    websites = set()
    dns_queries = set()
    http_packets = []
    
    for i, pkt in enumerate(continuous_packets):
        protocol = pkt.get('protocol', 'Unknown')
        protocols[protocol] = protocols.get(protocol, 0) + 1
        
        website = pkt.get('website_visited', 'N/A')
        if website != 'N/A':
            websites.add(website)
        
        dns_query = pkt.get('dns_query', 'N/A')
        if dns_query != 'N/A':
            dns_queries.add(dns_query)
        
        http_payload = pkt.get('http_payload', 'N/A')
        if protocol == 'HTTP' and http_payload != 'N/A':
            http_packets.append(pkt)
        
        # Show first 10 packets
        if i < 10:
            print(f"  {i+1}. {pkt['timestamp']} | {protocol} | {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
            print(f"      Website: {website}")
            print(f"      DNS: {dns_query}")
            print(f"      HTTP: {http_payload}")
    
    print(f"\n📊 Results Summary:")
    print(f"   Total packets: {final_count}")
    print(f"   Protocol distribution: {protocols}")
    print(f"   Websites detected: {len(websites)}")
    print(f"   DNS queries: {len(dns_queries)}")
    print(f"   HTTP packets with payload: {len(http_packets)}")
    
    if websites:
        print(f"\n🌐 Websites found:")
        for website in sorted(websites):
            print(f"   - {website}")
    
    if http_packets:
        print(f"\n📡 HTTP packets found:")
        for pkt in http_packets:
            print(f"   - {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
            print(f"     Website: {pkt['website_visited']}")
            print(f"     Payload: {pkt['http_payload']}")
    
    # Check for expected domains
    expected_domains = ['httpbin.org', 'jsonplaceholder.typicode.com']
    found_domains = [w for w in websites if any(domain in w for domain in expected_domains)]
    
    print(f"\n✅ Expected domains found: {len(found_domains)}/{len(expected_domains)}")
    for domain in found_domains:
        print(f"   ✅ {domain}")
    
    missing = [d for d in expected_domains if not any(d in w for w in websites)]
    if missing:
        print(f"❌ Missing domains: {missing}")
    
    # Success criteria
    success = len(http_packets) > 0 and len(found_domains) > 0
    print(f"\n🎯 Test {'PASSED' if success else 'FAILED'}")
    
    return success

if __name__ == "__main__":
    success = test_streamlit_sniffer()
    print(f"\n{'='*60}")
    print(f"🎯 Overall test result: {'✅ PASSED' if success else '❌ FAILED'}")
    print(f"{'='*60}")
