#!/usr/bin/env python3
"""
Debug HTTP Packet Processing
"""

from scapy.all import sniff, Raw, TCP, IP
import requests
import time
import threading

def debug_packet_processing():
    """Debug what's happening with HTTP packet processing"""
    print("=" * 60)
    print("DEBUG HTTP PACKET PROCESSING")
    print("=" * 60)
    
    def analyze_packet(pkt):
        print(f"\n📦 Packet: {pkt.summary()}")
        
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            print(f"   TCP ports: {tcp_layer.sport} -> {tcp_layer.dport}")
            
            if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                print("   ✅ This is HTTP traffic (port 80)")
                
                if pkt.haslayer(Raw):
                    raw_data = pkt[Raw].load
                    print(f"   Raw data length: {len(raw_data)} bytes")
                    
                    try:
                        # Try different decodings
                        decoded_utf8 = raw_data.decode('utf-8', errors='ignore')
                        print(f"   UTF-8 decoded (first 200 chars): {repr(decoded_utf8[:200])}")
                        
                        if decoded_utf8.startswith(('GET ', 'POST ', 'HEAD ', 'PUT ')):
                            print("   🎯 HTTP REQUEST DETECTED!")
                            lines = decoded_utf8.split('\r\n')
                            for line in lines[:10]:  # First 10 lines
                                if line.lower().startswith('host:'):
                                    host = line.split(':', 1)[1].strip()
                                    print(f"   🌐 HOST HEADER FOUND: {host}")
                                    break
                        elif decoded_utf8.startswith('HTTP/'):
                            print("   📨 HTTP RESPONSE DETECTED!")
                            
                    except Exception as e:
                        print(f"   ❌ Decoding error: {e}")
                        print(f"   Raw bytes (first 50): {raw_data[:50]}")
                else:
                    print("   ⚠️ No Raw layer in HTTP packet")
            else:
                print(f"   ℹ️ Not HTTP traffic (ports: {tcp_layer.sport} -> {tcp_layer.dport})")
    
    # Generate HTTP traffic in background
    def generate_traffic():
        time.sleep(2)
        print("\n🌐 Generating HTTP traffic...")
        try:
            response = requests.get('http://httpbin.org/headers', timeout=10)
            print(f"✅ HTTP request completed: {response.status_code}")
        except Exception as e:
            print(f"❌ HTTP request failed: {e}")
    
    traffic_thread = threading.Thread(target=generate_traffic)
    traffic_thread.start()
    
    # Capture packets
    print("🚀 Starting packet capture (looking for port 80 traffic)...")
    packets = sniff(filter="port 80", timeout=15, prn=analyze_packet, count=10)
    
    print(f"\n📊 Total HTTP packets captured: {len(packets)}")
    
    traffic_thread.join(timeout=5)

if __name__ == "__main__":
    debug_packet_processing()
