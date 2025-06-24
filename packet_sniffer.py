from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from datetime import datetime

captured_packets = []

def process_packet(packet):
    proto = "Unknown"
    src_ip = "N/A"
    dst_ip = "N/A"
    src_port = "N/A"
    dst_port = "N/A"
    src_mac = "N/A"
    dst_mac = "N/A"

    try:
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                proto = 'TCP'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif UDP in packet:
                proto = 'UDP'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
            elif ICMP in packet:
                proto = 'ICMP'
            else:
                proto = 'Other-IP'

        elif ARP in packet:
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            proto = 'ARP'

        elif Ether in packet:
            proto = 'Ethernet'

        else:
            proto = packet.name

    except Exception:
        proto = "Malformed"
        src_ip = "N/A"
        dst_ip = "N/A"

    packet_data = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'src_mac': src_mac,
        'dst_mac': dst_mac,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': proto,
        'length': len(packet)
    }

    captured_packets.append(packet_data)


def start_sniffing(packet_count=1000, protocol_filter=None, ip_filter=None):
    """
    Starts packet capture with optional protocol or IP filtering.

    :param packet_count: Number of packets to capture
    :param protocol_filter: Example - 'tcp', 'udp', 'icmp', 'arp' (Optional)
    :param ip_filter: Specific IP to filter (Optional)
    """
    print(f"\n[INFO] Starting packet capture for {packet_count} packets...\n")

    capture_filter = ""

    if protocol_filter:
        capture_filter += protocol_filter.lower()

    if ip_filter:
        if capture_filter:
            capture_filter += " and "
        capture_filter += f"host {ip_filter}"

    sniff(count=packet_count, prn=process_packet, iface=conf.iface, filter=capture_filter if capture_filter else None)

    print("[INFO] Packet capture complete.\n")
    return captured_packets
