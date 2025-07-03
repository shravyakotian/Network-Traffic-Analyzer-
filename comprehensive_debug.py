import requests
import time
import subprocess
import sys
from packet_sniffer import continuous_sniffing, continuous_packets, stop_sniffing, get_capture_stats

def run_debug_test():
    """Run a comprehensive debug test to check packet capture and website detection."""
    print("🔍 Starting comprehensive debug test...")
    
    # Clear any previous packets
    continuous_packets.clear()
    
    # Start packet capture
    print("🚀 Starting packet capture...")
    continuous_sniffing(interface=None)
    
    # Wait for capture to initialize
    time.sleep(2)
    
    # Check initial state
    print(f"📊 Initial state: {len(continuous_packets)} packets captured")
    
    # Test 1: DNS Resolution (should generate DNS packets)
    print("\n🧪 Test 1: DNS Resolution")
    try:
        import socket
        socket.gethostbyname('httpbin.org')
        socket.gethostbyname('jsonplaceholder.typicode.com')
        socket.gethostbyname('api.github.com')
        time.sleep(2)
        print(f"✅ DNS test complete. Packets: {len(continuous_packets)}")
    except Exception as e:
        print(f"❌ DNS test failed: {e}")
    
    # Test 2: HTTP Requests
    print("\n🧪 Test 2: HTTP Requests")
    try:
        # Use requests to make HTTP calls
        websites = [
            'http://httpbin.org/json',
            'http://jsonplaceholder.typicode.com/posts/1',
            'http://api.github.com/user'
        ]
        
        for site in websites:
            try:
                print(f"📡 Requesting {site}...")
                response = requests.get(site, timeout=5)
                print(f"✅ {site} responded with status {response.status_code}")
                time.sleep(1)
            except Exception as e:
                print(f"❌ Failed to request {site}: {e}")
        
        time.sleep(3)
        print(f"✅ HTTP test complete. Packets: {len(continuous_packets)}")
    except Exception as e:
        print(f"❌ HTTP test failed: {e}")
    
    # Test 3: HTTPS Requests
    print("\n🧪 Test 3: HTTPS Requests")
    try:
        https_sites = [
            'https://httpbin.org/json',
            'https://jsonplaceholder.typicode.com/posts/1',
            'https://api.github.com/user'
        ]
        
        for site in https_sites:
            try:
                print(f"🔒 Requesting {site}...")
                response = requests.get(site, timeout=5)
                print(f"✅ {site} responded with status {response.status_code}")
                time.sleep(1)
            except Exception as e:
                print(f"❌ Failed to request {site}: {e}")
        
        time.sleep(3)
        print(f"✅ HTTPS test complete. Packets: {len(continuous_packets)}")
    except Exception as e:
        print(f"❌ HTTPS test failed: {e}")
    
    # Wait for all packets to be processed
    time.sleep(5)
    
    # Stop capture
    print("\n🛑 Stopping packet capture...")
    stop_sniffing()
    time.sleep(2)
    
    # Analyze results
    print(f"\n📊 FINAL RESULTS: {len(continuous_packets)} packets captured")
    
    if len(continuous_packets) == 0:
        print("❌ No packets captured! Check:")
        print("   - Run as Administrator")
        print("   - Check network interfaces")
        print("   - Verify WinPcap/Npcap installation")
        return
    
    # Show statistics
    stats = get_capture_stats()
    print(f"📈 Capture stats: {stats}")
    
    # Analyze captured packets
    print("\n🔍 Analyzing captured packets...")
    
    # Count by protocol
    protocols = {}
    websites_detected = set()
    dns_queries = set()
    http_requests = set()
    
    for i, pkt in enumerate(continuous_packets):
        protocol = pkt.get('protocol', 'Unknown')
        protocols[protocol] = protocols.get(protocol, 0) + 1
        
        # Check website detection
        website = pkt.get('website_visited', 'N/A')
        if website != 'N/A':
            websites_detected.add(website)
        
        # Check DNS queries
        dns_query = pkt.get('dns_query', 'N/A')
        if dns_query != 'N/A':
            dns_queries.add(dns_query)
        
        # Check HTTP payloads
        http_payload = pkt.get('http_payload', 'N/A')
        if http_payload != 'N/A' and 'GET' in http_payload:
            http_requests.add(http_payload)
        
        # Show first few packets for debugging
        if i < 10:
            print(f"  {i+1}. {pkt['timestamp']} | {protocol} | {pkt['src_ip']} -> {pkt['dst_ip']} | Website: {website}")
    
    print(f"\n📊 Protocol distribution:")
    for proto, count in protocols.items():
        print(f"   {proto}: {count} packets")
    
    print(f"\n🌐 Websites detected ({len(websites_detected)}):")
    for website in sorted(websites_detected):
        print(f"   - {website}")
    
    print(f"\n🔍 DNS queries detected ({len(dns_queries)}):")
    for query in sorted(dns_queries):
        print(f"   - {query}")
    
    print(f"\n📡 HTTP requests detected ({len(http_requests)}):")
    for req in sorted(http_requests):
        print(f"   - {req}")
    
    # Expected results check
    expected_domains = ['httpbin.org', 'jsonplaceholder.typicode.com', 'api.github.com']
    detected_domains = [w for w in websites_detected if any(domain in w for domain in expected_domains)]
    
    print(f"\n✅ Expected domains detected: {len(detected_domains)}/{len(expected_domains)}")
    for domain in detected_domains:
        print(f"   ✅ {domain}")
    
    missing = [d for d in expected_domains if not any(d in w for w in websites_detected)]
    if missing:
        print(f"❌ Missing domains: {missing}")
    
    return len(continuous_packets), websites_detected, dns_queries, http_requests

if __name__ == "__main__":
    run_debug_test()
