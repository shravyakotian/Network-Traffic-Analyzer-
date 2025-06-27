from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from datetime import datetime
import threading

continuous_packets = []  # Global packet storage
_lock = threading.Lock()  # Thread safety
stop_sniffing_flag = False  # Control flag


def process_packet(packet, live_callback=None, terminal_live=False, pkt_index=None):
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

    if terminal_live and pkt_index is not None:
        print(f"{pkt_index}. [{packet_data['timestamp']}] {proto} | "
              f"{src_ip}:{src_port} → {dst_ip}:{dst_port} | "
              f"MAC: {src_mac} → {dst_mac} | Size: {packet_data['length']} bytes")

    if live_callback:
        live_callback(packet_data)

    return packet_data


def continuous_sniffing(protocol_filter=None, ip_filter=None, terminal_live=False):
    """
    Threaded continuous packet capture for Terminal/App with safe stop.
    """
    global stop_sniffing_flag
    stop_sniffing_flag = False  # Reset stop flag

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
    """
    Safely stop packet capture.
    """
    global stop_sniffing_flag
    stop_sniffing_flag = True
    print("[INFO] Sniffing stop requested.")
