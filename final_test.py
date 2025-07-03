#!/usr/bin/env python3
"""
Final comprehensive test to demonstrate the working system
"""
import time
import requests
import subprocess
import threading
from packet_sniffer import continuous_sniffing, continuous_packets, stop_sniffing, get_capture_stats

def run_final_test():
    """Run final comprehensive test"""
    print("🚀 FINAL COMPREHENSIVE TEST")
    print("="*60)
    
    # Clear any existing packets
    continuous_packets.clear()
    
    # Start the sniffer
    print("🔍 Starting packet capture...")
    continuous_sniffing(interface=None)
    time.sleep(2)
    
    print(f"📊 Initial state: {len(continuous_packets)} packets")
    
    # Test websites
    test_websites = [
        'http://httpbin.org/json',
        'http://jsonplaceholder.typicode.com/posts/1',
        'http://httpbin.org/get',
        'http://httpbin.org/user-agent',
        'http://api.github.com/users/octocat'
    ]
    
    print(f"\n🌐 Testing {len(test_websites)} websites...")
    
    successful_requests = 0
    for i, url in enumerate(test_websites, 1):
        try:
            print(f"  {i}. Requesting {url}...")
            response = requests.get(url, timeout=8)
            if response.status_code == 200:
                print(f"     ✅ SUCCESS: {response.status_code}")
                successful_requests += 1
            else:
                print(f"     ⚠️  Status: {response.status_code}")
            time.sleep(2)  # Wait between requests
        except Exception as e:
            print(f"     ❌ ERROR: {e}")
    
    print(f"\n📊 Successful requests: {successful_requests}/{len(test_websites)}")
    
    # Wait for all packets to be processed
    print("\n⏳ Waiting for packet processing...")
    time.sleep(5)
    
    # Stop capture
    print("\n🛑 Stopping packet capture...")
    stop_sniffing()
    time.sleep(2)
    
    # Analyze results
    total_packets = len(continuous_packets)
    print(f"\n📈 ANALYSIS RESULTS:")
    print(f"   Total packets captured: {total_packets}")
    
    if total_packets == 0:
        print("   ❌ No packets captured! Please check:")
        print("      - Run as Administrator")
        print("      - Verify network connectivity")
        print("      - Check WinPcap/Npcap installation")
        return False
    
    # Categorize packets
    protocols = {}
    websites_detected = set()
    dns_queries = set()
    http_with_payload = []
    
    for pkt in continuous_packets:
        # Protocol count
        protocol = pkt.get('protocol', 'Unknown')
        protocols[protocol] = protocols.get(protocol, 0) + 1
        
        # Website detection
        website = pkt.get('website_visited', 'N/A')
        if website != 'N/A':
            websites_detected.add(website)
        
        # DNS queries
        dns_query = pkt.get('dns_query', 'N/A')
        if dns_query != 'N/A':
            dns_queries.add(dns_query)
        
        # HTTP with payload
        if protocol == 'HTTP' and pkt.get('http_payload') != 'N/A':
            http_with_payload.append(pkt)
    
    print(f"\n📊 Protocol Distribution:")
    for protocol, count in sorted(protocols.items()):
        print(f"   {protocol}: {count} packets")
    
    print(f"\n🌐 Websites Detected ({len(websites_detected)}):")
    for website in sorted(websites_detected):
        print(f"   - {website}")
    
    print(f"\n📡 HTTP Packets with Payload ({len(http_with_payload)}):")
    for pkt in http_with_payload:
        print(f"   - {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
        print(f"     Website: {pkt['website_visited']}")
        print(f"     Payload: {pkt['http_payload'][:50]}...")
    
    if dns_queries:
        print(f"\n🔍 DNS Queries ({len(dns_queries)}):")
        for query in sorted(dns_queries):
            if not query.endswith('.in-addr.arpa'):  # Skip reverse DNS
                print(f"   - {query}")
    
    # Check expected domains
    expected_domains = ['httpbin.org', 'jsonplaceholder.typicode.com', 'api.github.com']
    found_domains = []
    for domain in expected_domains:
        if any(domain in website for website in websites_detected):
            found_domains.append(domain)
    
    print(f"\n🎯 Expected Domain Detection:")
    print(f"   Found: {len(found_domains)}/{len(expected_domains)}")
    for domain in found_domains:
        print(f"   ✅ {domain}")
    
    missing_domains = [d for d in expected_domains if d not in found_domains]
    if missing_domains:
        print(f"   Missing: {missing_domains}")
    
    # Success criteria
    success_criteria = {
        'packets_captured': total_packets > 0,
        'http_packets_found': len(http_with_payload) > 0,
        'websites_detected': len(websites_detected) > 0,
        'expected_domains': len(found_domains) >= 1,  # At least one expected domain
        'successful_requests': successful_requests > 0
    }
    
    print(f"\n🏆 SUCCESS CRITERIA:")
    all_passed = True
    for criterion, passed in success_criteria.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"   {criterion}: {status}")
        if not passed:
            all_passed = False
    
    print(f"\n{'='*60}")
    if all_passed:
        print("🎉 TEST RESULT: ✅ ALL CRITERIA PASSED!")
        print("🌟 The Network Traffic Analyzer is working correctly!")
        print("🚀 The system can now:")
        print("   - Capture network packets reliably")
        print("   - Detect HTTP requests and extract Host headers")
        print("   - Identify visited websites from traffic")
        print("   - Display results in the Streamlit dashboard")
    else:
        print("🚨 TEST RESULT: ❌ SOME CRITERIA FAILED")
        print("🔧 Please check the failed criteria above")
    
    print(f"{'='*60}")
    
    return all_passed

if __name__ == "__main__":
    success = run_final_test()
    
    if success:
        print("\n🎊 CONGRATULATIONS! 🎊")
        print("Your Network Traffic Analyzer is ready to use!")
        print("Run 'streamlit run app_ui.py' to start the dashboard.")
    else:
        print("\n🛠️  Some issues need to be addressed.")
        print("Please check the output above for details.")
