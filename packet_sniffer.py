from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from datetime import datetime

captured_packets = []

def process_packet(packet):
    proto = "Unknown"
    src_ip = "N/A"
    dst_ip = "N/A"

    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                proto = 'TCP'
            elif UDP in packet:
                proto = 'UDP'
            elif ICMP in packet:
                proto = 'ICMP'
            else:
                proto = 'Other-IP'
        elif ARP in packet:
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            proto = 'ARP'
        elif Ether in packet:
            src_ip = packet[Ether].src
            dst_ip = packet[Ether].dst
            proto = 'Ethernet'
        else:
            proto = packet.name
    except Exception:
        proto = "Malformed"
        src_ip = "N/A"
        dst_ip = "N/A"

    packet_data = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'protocol': proto,
        'length': len(packet)
    }

    captured_packets.append(packet_data)

def start_sniffing(packet_count=1000):
    print(f"\n[INFO] Starting packet capture for {packet_count} packets...\n")
    sniff(count=packet_count, prn=process_packet, iface=conf.iface)
    print("[INFO] Packet capture complete.\n")
    return captured_packets
