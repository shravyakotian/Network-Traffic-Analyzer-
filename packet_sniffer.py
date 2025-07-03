from scapy.all import sniff, conf, Raw, get_if_list
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS
from scapy.layers.tls.all import TLSClientHello, TLS_Ext_ServerName
from datetime import datetime
import threading
import socket
import platform
import time

continuous_packets = []
_lock = threading.Lock()
stop_sniffing_flag = False

# Add debugging and error tracking
capture_stats = {
    'total_packets': 0,
    'last_packet_time': None,
    'errors': []
}

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


def get_capture_stats():
    """Get current capture statistics"""
    with _lock:
        return capture_stats.copy()


def resolve_domain(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip  # Fallback to IP if domain unknown


def process_packet(packet, live_callback=None, terminal_live=False, pkt_index=None):
    proto = "Unknown"
    src_ip = "N/A"
    dst_ip = "N/A"
    src_domain = "N/A"
    dst_domain = "N/A"
    src_port = "N/A"
    dst_port = "N/A"
    src_mac = "N/A"
    dst_mac = "N/A"
    dns_query = "N/A"
    http_payload = "N/A"
    website_visited = "N/A"

    try:
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_domain = resolve_domain(src_ip)
            dst_domain = resolve_domain(dst_ip)

            if TCP in packet:
                src_port = str(packet[TCP].sport)
                dst_port = str(packet[TCP].dport)
                
                # Determine protocol based on ports
                if int(dst_port) == 80 or int(src_port) == 80:
                    proto = "HTTP"
                elif int(dst_port) == 443 or int(src_port) == 443:
                    proto = "HTTPS"
                elif int(dst_port) == 53 or int(src_port) == 53:
                    proto = "DNS"
                else:
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

        # Enhanced DNS Query Extraction
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qd is not None:
                try:
                    dns_query = dns_layer.qd.qname.decode(errors="ignore").rstrip('.')
                    website_visited = dns_query
                    proto = "DNS"
                except:
                    dns_query = "DNS_PARSE_ERROR"
            
            # Also check DNS responses for additional info
            if dns_layer.an is not None:
                try:
                    for i in range(dns_layer.ancount):
                        if hasattr(dns_layer.an[i], 'rrname'):
                            response_name = dns_layer.an[i].rrname.decode(errors="ignore").rstrip('.')
                            if response_name and response_name != dns_query:
                                dns_query = f"{dns_query} -> {response_name}"
                except:
                    pass

        # Enhanced TLS/HTTPS SNI Detection
        try:
            if packet.haslayer(TCP) and packet[TCP].dport == 443:  # HTTPS traffic
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    # Look for TLS Client Hello (0x16 = handshake, 0x01 = client hello)
                    if len(payload) > 5 and payload[0] == 0x16:  # TLS Handshake
                        try:
                            # Simple SNI extraction - look for server name pattern
                            payload_str = payload.hex()
                            # SNI extension pattern: look for 00 00 (server name list) followed by domain
                            if '0000' in payload_str:
                                # Try to extract readable domain names from the payload
                                readable_parts = []
                                for i in range(len(payload)):
                                    if i + 10 < len(payload):  # Need at least 10 bytes for domain
                                        try:
                                            # Look for patterns that might be domain names
                                            test_str = payload[i:i+50].decode('ascii', errors='ignore')
                                            # Check if it looks like a domain
                                            if ('.' in test_str and 
                                                any(domain in test_str.lower() for domain in ['httpbin', 'github', 'typicode', 'com', 'org', 'net']) and
                                                len([c for c in test_str if c.isalnum() or c in '.-']) > len(test_str) * 0.8):
                                                # Extract the domain part
                                                domain_match = ""
                                                for char in test_str:
                                                    if char.isalnum() or char in '.-':
                                                        domain_match += char
                                                    else:
                                                        break
                                                if '.' in domain_match and len(domain_match) > 3:
                                                    readable_parts.append(domain_match)
                                        except:
                                            continue
                                
                                if readable_parts:
                                    # Pick the most likely domain (longest one with common TLDs)
                                    best_domain = max(readable_parts, key=len, default="")
                                    if best_domain:
                                        proto = "HTTPS"
                                        website_visited = best_domain
                                        dst_domain = best_domain
                        except:
                            pass
        except:
            pass

        # Enhanced HTTP payload analysis
        raw_data = None
        if packet.haslayer(Raw):
            try:
                raw_data = packet[Raw].load.decode('utf-8', errors="ignore")
            except:
                try:
                    raw_data = packet[Raw].load.decode('latin-1', errors="ignore")
                except:
                    try:
                        raw_data = packet[Raw].load.decode('ascii', errors="ignore")
                    except:
                        # Try to extract at least some readable text
                        try:
                            raw_data = ''.join(chr(b) if 32 <= b <= 126 else '?' for b in packet[Raw].load[:500])
                        except:
                            raw_data = None

        if raw_data:
            # Check for HTTP requests (more specific detection)
            if (raw_data.startswith(("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ")) 
                and "HTTP/" in raw_data):
                proto = "HTTP"
                
                # Extract Host header more robustly
                lines = raw_data.replace('\r\n', '\n').replace('\r', '\n').split('\n')
                for line in lines:
                    line_clean = line.strip()
                    line_lower = line_clean.lower()
                    if line_lower.startswith('host:'):
                        host = line_clean[5:].strip()  # Remove 'host:' and strip
                        website_visited = host
                        dst_domain = host
                        break
                
                # Extract the requested path and method
                if lines:
                    first_line = lines[0].strip()
                    if ' HTTP/' in first_line:  # Ensure it's a valid HTTP request line
                        parts = first_line.split(' ')
                        if len(parts) >= 2:
                            method = parts[0]
                            path = parts[1]
                            # Combine with host if available
                            if website_visited != "N/A":
                                http_payload = f"{method} {website_visited}{path}"
                            else:
                                http_payload = f"{method} {path}"
                        else:
                            http_payload = first_line
                    else:
                        http_payload = first_line
                
            elif raw_data.startswith("HTTP/") and " " in raw_data:
                proto = "HTTP_RESPONSE"
                # Extract response code and status
                lines = raw_data.replace('\r\n', '\n').replace('\r', '\n').split('\n')
                if lines:
                    status_line = lines[0].strip()
                    http_payload = status_line
                    
            elif "USER " in raw_data or "PASS " in raw_data:
                proto = "FTP"
                http_payload = raw_data[:100]  # First 100 chars
                
            elif raw_data.startswith("SSH-"):
                proto = "SSH"
                http_payload = raw_data[:50]  # First 50 chars
            
            else:
                # For other protocols, try to extract meaningful text
                if len(raw_data) > 10:
                    # Look for domain-like patterns in the data
                    import re
                    try:
                        domain_pattern = r'[a-zA-Z0-9.-]+\.(com|org|net|edu|gov|mil|int|co|io|ly|me|tv|app|dev|tech|in)'
                        domains = re.findall(domain_pattern, raw_data.lower())
                        if domains:
                            # Reconstruct the full domain
                            full_domain = domains[0]
                            if isinstance(full_domain, tuple):
                                full_domain = '.'.join(full_domain)
                            website_visited = full_domain
                    except:
                        pass
                    
                # Keep original payload but limit size and clean it
                cleaned_data = ''.join(c if c.isprintable() else '?' for c in raw_data)
                http_payload = cleaned_data[:200] if len(cleaned_data) > 200 else cleaned_data
        
        # If we detected HTTP protocol but don't have website info, try to get it from IP
        if proto == "HTTP" and website_visited == "N/A" and dst_domain != "N/A":
            website_visited = dst_domain

    except Exception as e:
        proto = "Malformed"
        with _lock:
            capture_stats['errors'].append(f"Packet processing error: {str(e)}")

    packet_data = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'src_mac': src_mac,
        'dst_mac': dst_mac,
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_domain': src_domain,
        'dst_domain': dst_domain,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': proto,
        'dns_query': dns_query,
        'http_payload': http_payload,
        'website_visited': website_visited,  # New field
        'length': len(packet)
    }

    if terminal_live and pkt_index is not None:
        print(f"{pkt_index}. [{packet_data['timestamp']}] {proto} | "
              f"{src_ip} ({src_domain}):{src_port} → {dst_ip} ({dst_domain}):{dst_port} | "
              f"Website: {website_visited} | Size: {packet_data['length']} bytes | "
              f"DNS: {dns_query} | HTTP: {http_payload}")

    if live_callback:
        live_callback(packet_data)

    return packet_data


def continuous_sniffing(protocol_filter=None, ip_filter=None, terminal_live=False, interface=None):
    global stop_sniffing_flag, capture_stats
    stop_sniffing_flag = False
    
    # Reset stats
    with _lock:
        capture_stats['total_packets'] = 0
        capture_stats['last_packet_time'] = None
        capture_stats['errors'] = []
        continuous_packets.clear()  # Clear previous packets

    capture_filter = ""
    if protocol_filter:
        capture_filter += protocol_filter.lower()
    if ip_filter:
        if capture_filter:
            capture_filter += " and "
        capture_filter += f"host {ip_filter}"

    # Select interface
    target_interface = interface if interface else conf.iface
    
    def handle_packet(pkt):
        try:
            with _lock:
                pkt_index = len(continuous_packets) + 1
                data = process_packet(pkt, terminal_live=terminal_live, pkt_index=pkt_index)
                continuous_packets.append(data)
                
                # Update stats
                capture_stats['total_packets'] += 1
                capture_stats['last_packet_time'] = datetime.now()
                
                # Debug: Print packets for troubleshooting
                if terminal_live or len(continuous_packets) % 10 == 0:
                    print(f"[DEBUG] Captured packet {pkt_index}: {data['protocol']} | {data['src_ip']} -> {data['dst_ip']} | Website: {data['website_visited']}")
                
        except Exception as e:
            with _lock:
                capture_stats['errors'].append(f"Error processing packet: {str(e)}")

    def start_sniffing():
        try:
            print(f"[INFO] Starting packet capture on interface: {target_interface}")
            print(f"[INFO] Capture filter: {capture_filter if capture_filter else 'None (all traffic)'}")
            
            # Use batch approach with shorter timeouts but more frequent checks
            while not stop_sniffing_flag:
                try:
                    # Capture packets in small batches with very short timeout
                    sniff(
                        prn=handle_packet,
                        iface=target_interface,
                        filter=capture_filter if capture_filter else None,
                        store=False,
                        timeout=0.5,  # Very short timeout to be responsive
                        count=10   # Small batches for quick processing
                    )
                except Exception as inner_e:
                    if not stop_sniffing_flag:  # Only log if not intentionally stopped
                        error_msg = f"Sniffing batch error: {str(inner_e)}"
                        print(f"[WARNING] {error_msg}")
                        with _lock:
                            capture_stats['errors'].append(error_msg)
                        time.sleep(0.1)  # Very short pause before retrying
                    
        except Exception as e:
            error_msg = f"Sniffing error: {str(e)}"
            print(f"[ERROR] {error_msg}")
            with _lock:
                capture_stats['errors'].append(error_msg)

    thread = threading.Thread(target=start_sniffing, daemon=True)
    thread.start()
    
    # Give it a moment to start
    time.sleep(0.5)
    print("[INFO] Continuous background sniffing started.")


def stop_sniffing():
    global stop_sniffing_flag
    stop_sniffing_flag = True
    print("[INFO] Sniffing stop requested.")
