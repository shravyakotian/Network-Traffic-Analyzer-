import time
from packet_sniffer import continuous_sniffing, continuous_packets, stop_sniffing, process_packet
from scapy.all import sniff, Raw, IP, TCP
import requests
import threading

def debug_http_data_packets():
    """Debug to capture actual HTTP data packets with payload."""
    print("🔍 Debugging HTTP data packets...")
    
    # Capture HTTP packets with payload
    http_data_packets = []
    
    def packet_handler(pkt):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            # Check for HTTP traffic on port 80
            if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                # Check if it has payload
                if pkt.haslayer(Raw):
                    payload = pkt[Raw].load
                    try:
                        payload_str = payload.decode('utf-8', errors='ignore')
                        if ('HTTP' in payload_str or 
                            'GET' in payload_str or 
                            'POST' in payload_str or 
                            'Host:' in payload_str):
                            http_data_packets.append(pkt)
                            print(f"📦 HTTP data packet captured: {pkt.summary()}")
                            print(f"    Payload preview: {payload_str[:100]}")
                            
                            # Process using our function
                            result = process_packet(pkt)
                            print(f"    Our processing result:")
                            print(f"      Protocol: {result['protocol']}")
                            print(f"      Website: {result['website_visited']}")
                            print(f"      HTTP Payload: {result['http_payload']}")
                            print()
                    except Exception as e:
                        print(f"❌ Error processing HTTP packet: {e}")
    
    # Start capture
    def start_capture():
        try:
            print("🚀 Starting HTTP data packet capture...")
            sniff(prn=packet_handler, filter="tcp port 80", timeout=20, store=False)
        except Exception as e:
            print(f"❌ Capture error: {e}")
    
    capture_thread = threading.Thread(target=start_capture, daemon=True)
    capture_thread.start()
    
    # Wait for capture to start
    time.sleep(2)
    
    print("🌐 Making HTTP requests...")
    
    # Test different HTTP sites
    test_sites = [
        'http://httpbin.org/json',
        'http://jsonplaceholder.typicode.com/posts/1',
        'http://httpbin.org/get',
    ]
    
    for site in test_sites:
        try:
            print(f"📡 Requesting {site}...")
            response = requests.get(site, timeout=10)
            print(f"✅ {site} responded with {response.status_code}")
            time.sleep(2)  # Wait between requests
        except Exception as e:
            print(f"❌ Failed to request {site}: {e}")
    
    # Wait for all packets to be captured
    time.sleep(5)
    
    print(f"\n📊 Total HTTP data packets captured: {len(http_data_packets)}")
    
    # Now test our continuous sniffer
    print("\n🔄 Testing with our continuous sniffer...")
    
    # Clear previous packets
    continuous_packets.clear()
    
    # Start our sniffer
    continuous_sniffing(interface=None)
    time.sleep(2)
    
    print("🌐 Making HTTP requests with our sniffer...")
    
    try:
        response = requests.get('http://httpbin.org/json', timeout=10)
        print(f"✅ HTTP request successful: {response.status_code}")
    except Exception as e:
        print(f"❌ HTTP request failed: {e}")
    
    # Wait for packets to be captured
    time.sleep(5)
    
    # Stop our sniffer
    stop_sniffing()
    time.sleep(2)
    
    print(f"\n📊 Our sniffer captured {len(continuous_packets)} packets")
    
    # Show packets that contain HTTP data
    http_packets_found = []
    for pkt in continuous_packets:
        if pkt.get('protocol') == 'HTTP' and pkt.get('http_payload') != 'N/A':
            http_packets_found.append(pkt)
            print(f"✅ Found HTTP packet: {pkt['src_ip']}:{pkt['src_port']} -> {pkt['dst_ip']}:{pkt['dst_port']}")
            print(f"   Website: {pkt['website_visited']}")
            print(f"   HTTP Payload: {pkt['http_payload']}")
    
    print(f"\n📈 Summary:")
    print(f"   Manual capture found {len(http_data_packets)} HTTP data packets")
    print(f"   Our sniffer captured {len(continuous_packets)} total packets")
    print(f"   Our sniffer found {len(http_packets_found)} HTTP packets with payload")

if __name__ == "__main__":
    debug_http_data_packets()
