from scapy.all import sniff, conf, Raw
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS
from datetime import datetime
import threading

continuous_packets = []  # Global packet storage
_lock = threading.Lock()  # Thread safety
stop_sniffing_flag = False  # Control flag

# Known port mappings for protocol identification
PORT_PROTOCOLS = {
    80: "HTTP",
    443: "HTTPS",
    53: "DNS",
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    123: "NTP",
    445: "SMB",
    3306: "MySQL",
    5432: "PostgreSQL"
}

def process_packet(packet, live_callback=None, terminal_live=False, pkt_index=None):
    proto = "Unknown"
    src_ip = "N/A"
    dst_ip = "N/A"
    src_port = "N/A"
    dst_port = "N/A"
    src_mac = "N/A"
    dst_mac = "N/A"
    dns_query = "N/A"
    http_payload = "N/A"

    try:
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if TCP in packet:
                src_port = str(packet[TCP].sport)
                dst_port = str(packet[TCP].dport)
                proto = PORT_PROTOCOLS.get(int(dst_port)) or PORT_PROTOCOLS.get(int(src_port)) or "TCP"

            elif UDP in packet:
                src_port = str(packet[UDP].sport)
                dst_port = str(packet[UDP].dport)
                proto = PORT_PROTOCOLS.get(int(dst_port)) or PORT_PROTOCOLS.get(int(src_port)) or "UDP"

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

        # DNS Query Extraction
        if packet.haslayer(DNS) and packet[DNS].qd is not None:
            dns_query = packet[DNS].qd.qname.decode(errors="ignore")

        # HTTP Payload preview (basic, not full reconstruction)
        if packet.haslayer(Raw) and (proto == "HTTP" or int(dst_port) == 80 or int(src_port) == 80):
            raw_data = packet[Raw].load
            try:
                http_payload = raw_data.decode(errors="ignore")[:50] + "..." if len(raw_data) > 50 else raw_data.decode(errors="ignore")
            except:
                http_payload = "Binary/Undecodable Payload"

    except Exception:
        proto = "Malformed"

    packet_data = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'src_mac': src_mac,
        'dst_mac': dst_mac,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': proto,
        'dns_query': dns_query,
        'http_payload': http_payload,
        'length': len(packet)
    }

    if terminal_live and pkt_index is not None:
        print(f"{pkt_index}. [{packet_data['timestamp']}] {proto} | "
              f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
              f"MAC: {src_mac} → {dst_mac} | Size: {packet_data['length']} bytes | "
              f"DNS: {dns_query} | HTTP: {http_payload}")

    if live_callback:
        live_callback(packet_data)

    return packet_data


def continuous_sniffing(protocol_filter=None, ip_filter=None, terminal_live=False):
    global stop_sniffing_flag
    stop_sniffing_flag = False

    capture_filter = ""
    if protocol_filter:
        capture_filter += protocol_filter.lower()
    if ip_filter:
        if capture_filter:
            capture_filter += " and "
        capture_filter += f"host {ip_filter}"

    def handle_packet(pkt):
        with _lock:
            pkt_index = len(continuous_packets) + 1
            data = process_packet(pkt, terminal_live=terminal_live, pkt_index=pkt_index)
            continuous_packets.append(data)

    def stop_condition(pkt):
        return stop_sniffing_flag

    thread = threading.Thread(target=sniff, kwargs={
        'prn': handle_packet,
        'iface': conf.iface,
        'filter': capture_filter if capture_filter else None,
        'store': False,
        'stop_filter': stop_condition
    }, daemon=True)

    thread.start()
    print("[INFO] Continuous background sniffing started.")


def stop_sniffing():
    global stop_sniffing_flag
    stop_sniffing_flag = True
    print("[INFO] Sniffing stop requested.")
