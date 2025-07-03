import requests
import time
import threading
from packet_sniffer import continuous_sniffing, continuous_packets, stop_sniffing, get_capture_stats
from scapy.all import sniff, Raw, IP, TCP

def manual_http_capture():
    """Manually capture HTTP packets using Scapy to debug the issue."""
    print("🔍 Starting manual HTTP capture debug...")
    
    http_packets = []
    
    def packet_handler(pkt):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            # Check for HTTP traffic on port 80
            if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if 'HTTP' in payload_str or 'GET' in payload_str or 'POST' in payload_str:
                            http_packets.append({
                                'src_ip': pkt[IP].src,
                                'dst_ip': pkt[IP].dst,
                                'src_port': pkt[TCP].sport,
                                'dst_port': pkt[TCP].dport,
                                'payload': payload_str[:500]  # First 500 chars
                            })
                            print(f"📡 HTTP packet: {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport}")
                            print(f"    Payload preview: {payload_str[:100]}")
                    except Exception as e:
                        print(f"❌ Error parsing HTTP payload: {e}")
    
    # Start capture in background
    def start_capture():
        try:
            sniff(prn=packet_handler, filter="tcp port 80", timeout=30, store=False)
        except Exception as e:
            print(f"❌ Capture error: {e}")
    
    capture_thread = threading.Thread(target=start_capture, daemon=True)
    capture_thread.start()
    
    # Wait for capture to start
    time.sleep(2)
    
    # Make HTTP requests
    print("🚀 Making HTTP requests...")
    try:
        # Make HTTP request to a server that supports plain HTTP
        response = requests.get('http://httpbin.org/json', timeout=10)
        print(f"✅ HTTP request completed: {response.status_code}")
        time.sleep(2)
        
        response = requests.get('http://jsonplaceholder.typicode.com/posts/1', timeout=10)
        print(f"✅ HTTP request completed: {response.status_code}")
        time.sleep(2)
        
    except Exception as e:
        print(f"❌ HTTP request failed: {e}")
    
    # Wait for packets to be captured
    time.sleep(5)
    
    print(f"\n📊 Captured {len(http_packets)} HTTP packets")
    for i, pkt in enumerate(http_packets):
        print(f"  {i+1}. {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
        print(f"     Payload: {pkt['payload'][:100]}")
    
    return http_packets

def enhanced_debug_test():
    """Enhanced debug test with better packet capture."""
    print("🔍 Starting enhanced debug test...")
    
    # Clear any previous packets
    continuous_packets.clear()
    
    # Start our packet capture
    print("🚀 Starting enhanced packet capture...")
    continuous_sniffing(interface=None)
    
    # Wait for capture to initialize
    time.sleep(3)
    
    print(f"📊 Initial state: {len(continuous_packets)} packets captured")
    
    # Make requests with longer delays to ensure capture
    print("\n🧪 Making HTTP requests with delays...")
    
    websites = [
        'http://httpbin.org/json',
        'http://jsonplaceholder.typicode.com/posts/1',
    ]
    
    for site in websites:
        try:
            print(f"\n📡 About to request {site}...")
            time.sleep(2)  # Wait before request
            
            response = requests.get(site, timeout=10)
            print(f"✅ {site} responded with status {response.status_code}")
            
            time.sleep(5)  # Wait after request for packets to be captured
            print(f"📊 Packets now: {len(continuous_packets)}")
            
        except Exception as e:
            print(f"❌ Failed to request {site}: {e}")
    
    # Wait longer for all packets to be processed
    print("\n⏳ Waiting for all packets to be processed...")
    time.sleep(10)
    
    # Stop capture
    print("\n🛑 Stopping packet capture...")
    stop_sniffing()
    time.sleep(2)
    
    # Analyze results
    print(f"\n📊 FINAL RESULTS: {len(continuous_packets)} packets captured")
    
    if len(continuous_packets) == 0:
        print("❌ No packets captured! This suggests a capture issue.")
        return []
    
    # Show all packets for debugging
    print("\n🔍 All captured packets:")
    for i, pkt in enumerate(continuous_packets):
        protocol = pkt.get('protocol', 'Unknown')
        website = pkt.get('website_visited', 'N/A')
        dns_query = pkt.get('dns_query', 'N/A')
        http_payload = pkt.get('http_payload', 'N/A')
        
        print(f"  {i+1}. {pkt['timestamp']} | {protocol} | {pkt['src_ip']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
        print(f"      Website: {website}")
        print(f"      DNS: {dns_query}")
        print(f"      HTTP: {http_payload}")
        print()
    
    # Check for specific patterns
    http_packets = [pkt for pkt in continuous_packets if pkt.get('protocol') == 'HTTP']
    dns_packets = [pkt for pkt in continuous_packets if pkt.get('protocol') == 'DNS']
    
    print(f"\n📈 Summary:")
    print(f"   Total packets: {len(continuous_packets)}")
    print(f"   HTTP packets: {len(http_packets)}")
    print(f"   DNS packets: {len(dns_packets)}")
    
    return continuous_packets

if __name__ == "__main__":
    print("🔧 Running enhanced debug test...")
    packets = enhanced_debug_test()
    
    print("\n" + "="*50)
    print("🔧 Running manual HTTP capture test...")
    http_packets = manual_http_capture()
    
    print(f"\n📊 Debug Summary:")
    print(f"   Enhanced capture: {len(packets)} packets")
    print(f"   Manual HTTP capture: {len(http_packets)} packets")
