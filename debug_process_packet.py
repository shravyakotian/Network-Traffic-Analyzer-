import time
from packet_sniffer import continuous_sniffing, continuous_packets, stop_sniffing, process_packet
from scapy.all import sniff, Raw, IP, TCP
import requests
import threading

def debug_process_packet():
    """Debug the process_packet function specifically."""
    print("🔍 Testing process_packet function directly...")
    
    # Capture some packets manually and process them
    captured_packets = []
    
    def packet_handler(pkt):
        if len(captured_packets) < 10:  # Capture first 10 packets
            captured_packets.append(pkt)
            print(f"📦 Captured packet {len(captured_packets)}: {pkt.summary()}")
    
    # Start manual capture
    def start_capture():
        try:
            # Capture any TCP traffic
            sniff(prn=packet_handler, filter="tcp", timeout=15, store=False)
        except Exception as e:
            print(f"❌ Manual capture error: {e}")
    
    capture_thread = threading.Thread(target=start_capture, daemon=True)
    capture_thread.start()
    
    # Wait a bit then make HTTP requests
    time.sleep(2)
    print("🚀 Making HTTP requests...")
    
    try:
        response = requests.get('http://httpbin.org/json', timeout=5)
        print(f"✅ HTTP request successful: {response.status_code}")
    except Exception as e:
        print(f"❌ HTTP request failed: {e}")
    
    # Wait for capture to complete
    time.sleep(8)
    
    print(f"\n📊 Captured {len(captured_packets)} packets")
    
    # Now process each packet using our process_packet function
    for i, pkt in enumerate(captured_packets):
        print(f"\n🔍 Processing packet {i+1}:")
        print(f"   Raw summary: {pkt.summary()}")
        
        # Process using our function
        result = process_packet(pkt)
        print(f"   Processed result:")
        print(f"     Protocol: {result['protocol']}")
        print(f"     Source: {result['src_ip']}:{result['src_port']}")
        print(f"     Destination: {result['dst_ip']}:{result['dst_port']}")
        print(f"     Website: {result['website_visited']}")
        print(f"     HTTP Payload: {result['http_payload']}")
        
        # Check if it has raw data
        if pkt.haslayer(Raw):
            try:
                raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
                print(f"     Raw data preview: {raw_data[:100]}")
            except:
                print(f"     Raw data: (binary/non-UTF8)")
        else:
            print(f"     No raw data layer")

if __name__ == "__main__":
    debug_process_packet()
