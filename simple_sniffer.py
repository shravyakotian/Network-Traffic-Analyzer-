from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS
from datetime import datetime

def process_packet(packet):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    proto = "Unknown"
    src_ip = dst_ip = src_mac = dst_mac = "-"
    src_port = dst_port = "-"
    length = len(packet)
    dns_query = "-"
    raw_data = "-"

    if Ether in packet:
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if TCP in packet:
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif ICMP in packet:
            proto = "ICMP"
    elif ARP in packet:
        proto = "ARP"
        src_ip = packet[ARP].psrc
        dst_ip = packet[ARP].pdst

    if packet.haslayer(DNS) and packet[DNS].qd is not None:
        dns_query = packet[DNS].qd.qname.decode(errors="ignore")

    if packet.haslayer(Raw):
        try:
            raw_data = packet[Raw].load.decode(errors="ignore")
        except:
            raw_data = "(non-decodable)"

    print(f"[{timestamp}] {proto} | {src_ip}:{src_port} -> {dst_ip}:{dst_port} | "
          f"MAC: {src_mac} -> {dst_mac} | Size: {length} bytes | DNS: {dns_query} | Raw: {raw_data[:50]}")

print("🔍 Starting packet capture... Press Ctrl+C to stop.\n")
sniff(prn=process_packet, store=False)


