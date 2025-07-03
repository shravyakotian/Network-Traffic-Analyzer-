#!/usr/bin/env python3
"""
Real-Time Network Traffic Monitor
Shows EXACTLY what's being captured as it happens.
Displays every packet, connection, and process in real-time.

Usage:
    python realtime_network_monitor.py

Press Ctrl+C to stop and see summary.
"""

import os
import sys
import time
import socket
import signal
import threading
import subprocess
import re
import json
import ipaddress
import logging
from datetime import datetime
from collections import Counter, defaultdict
from typing import Dict, Set, List, Optional, Any

try:
    from scapy.all import *
    import psutil
    import requests
except ImportError:
    print("Error: Missing required packages. Install with:")
    print("pip install scapy psutil requests")
    sys.exit(1)

class RealTimeNetworkMonitor:
    def __init__(self):
        self.running = False
        self.start_time = None
        
        # Real-time tracking
        self.packet_count = 0
        self.bytes_captured = 0
        self.domains_seen = set()
        self.ips_seen = set()
        self.ports_seen = set()
        self.processes_seen = set()
        self.connections_seen = []
        self.protocols = Counter()
        
        # Recent activity (for display)
        self.recent_packets = []
        self.recent_connections = []
        self.recent_dns = []
        self.recent_http = []
        
        # Display settings
        self.max_recent_items = 10
        self.display_lock = threading.Lock()
        
        print("🔍 Real-Time Network Monitor Initialized")
        print("👀 Will show EXACTLY what's being captured as it happens")
        
        # Setup signal handler
        signal.signal(signal.SIGINT, self.stop_monitoring)
    
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def display_header(self):
        """Display the header with current stats"""
        print("=" * 120)
        print("🔍 REAL-TIME NETWORK TRAFFIC MONITOR")
        print("=" * 120)
        
        duration = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        print(f"⏱️  Duration: {duration:.1f}s | "
              f"📦 Packets: {self.packet_count} | "
              f"💾 Bytes: {self.bytes_captured:,} | "
              f"🌐 IPs: {len(self.ips_seen)} | "
              f"🌍 Domains: {len(self.domains_seen)} | "
              f"🔌 Ports: {len(self.ports_seen)} | "
              f"⚙️  Processes: {len(self.processes_seen)}")
        
        print("=" * 120)
    
    def display_real_time_activity(self):
        """Display real-time network activity"""
        with self.display_lock:
            self.clear_screen()
            self.display_header()
            
            # Recent packets
            if self.recent_packets:
                print("📦 RECENT PACKETS:")
                for packet in self.recent_packets[-self.max_recent_items:]:
                    timestamp = packet['timestamp']
                    src = packet.get('src', 'Unknown')
                    dst = packet.get('dst', 'Unknown')
                    protocol = packet.get('protocol_name', 'Unknown')
                    size = packet.get('size', 0)
                    ports = ""
                    if packet.get('src_port') and packet.get('dst_port'):
                        ports = f":{packet['src_port']} -> :{packet['dst_port']}"
                    
                    print(f"   🔵 {timestamp[-8:]} | {protocol} | {src}{ports} -> {dst} | {size} bytes")
                print()
            
            # Recent DNS queries
            if self.recent_dns:
                print("🔍 RECENT DNS QUERIES:")
                for dns in self.recent_dns[-self.max_recent_items:]:
                    timestamp = dns['timestamp']
                    query = dns['query']
                    print(f"   🔍 {timestamp[-8:]} | DNS Query: {query}")
                print()
            
            # Recent HTTP requests
            if self.recent_http:
                print("🌐 RECENT HTTP REQUESTS:")
                for http in self.recent_http[-self.max_recent_items:]:
                    timestamp = http['timestamp']
                    method = http.get('method', 'Unknown')
                    host = http.get('host', 'Unknown')
                    url = http.get('url', '/')
                    print(f"   🌐 {timestamp[-8:]} | {method} {host}{url}")
                print()
            
            # Recent connections
            if self.recent_connections:
                print("🔗 RECENT CONNECTIONS:")
                for conn in self.recent_connections[-self.max_recent_items:]:
                    timestamp = conn['timestamp']
                    process = conn.get('process', 'Unknown')
                    remote_ip = conn.get('remote_ip', 'Unknown')
                    remote_port = conn.get('remote_port', 'Unknown')
                    protocol = conn.get('protocol', 'Unknown')
                    domain = conn.get('domain', '')
                    
                    display_target = domain if domain else remote_ip
                    print(f"   🔗 {timestamp[-8:]} | {process} -> {display_target}:{remote_port} [{protocol}]")
                print()
            
            # Protocol distribution
            if self.protocols:
                print("📊 PROTOCOL DISTRIBUTION:")
                for protocol, count in self.protocols.most_common(5):
                    print(f"   📊 {protocol}: {count} packets")
                print()
            
            # Top domains
            if self.domains_seen:
                print("🌍 TOP DOMAINS:")
                for domain in list(self.domains_seen)[-10:]:
                    print(f"   🌍 {domain}")
                print()
            
            print("⏹️  Press Ctrl+C to stop and generate summary")
            print("=" * 120)
    
    def resolve_ip_to_domain(self, ip: str) -> Optional[str]:
        """Quick domain resolution"""
        try:
            if ipaddress.ip_address(ip).is_private:
                return None
        except:
            pass
        
        try:
            domain = socket.gethostbyaddr(ip)[0]
            return domain
        except:
            return None
    
    def capture_packets_realtime(self):
        """Capture packets and show them in real-time"""
        def packet_handler(packet):
            try:
                self.packet_count += 1
                packet_size = len(packet)
                self.bytes_captured += packet_size
                
                # Extract packet info
                packet_info = {
                    'timestamp': datetime.now().isoformat(),
                    'size': packet_size,
                    'src': None,
                    'dst': None,
                    'protocol_name': 'Unknown',
                    'src_port': None,
                    'dst_port': None
                }
                
                # Extract IP layer
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    packet_info['src'] = ip_layer.src
                    packet_info['dst'] = ip_layer.dst
                    
                    self.ips_seen.add(ip_layer.src)
                    self.ips_seen.add(ip_layer.dst)
                    
                    # Resolve domains (quick)
                    src_domain = self.resolve_ip_to_domain(ip_layer.src)
                    dst_domain = self.resolve_ip_to_domain(ip_layer.dst)
                    
                    if src_domain:
                        self.domains_seen.add(src_domain)
                    if dst_domain:
                        self.domains_seen.add(dst_domain)
                
                # Extract TCP layer
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    packet_info['src_port'] = tcp_layer.sport
                    packet_info['dst_port'] = tcp_layer.dport
                    packet_info['protocol_name'] = 'TCP'
                    
                    self.ports_seen.add(tcp_layer.sport)
                    self.ports_seen.add(tcp_layer.dport)
                    self.protocols['TCP'] += 1
                
                # Extract UDP layer
                if packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    packet_info['src_port'] = udp_layer.sport
                    packet_info['dst_port'] = udp_layer.dport
                    packet_info['protocol_name'] = 'UDP'
                    
                    self.ports_seen.add(udp_layer.sport)
                    self.ports_seen.add(udp_layer.dport)
                    self.protocols['UDP'] += 1
                
                # Extract DNS
                if packet.haslayer(DNS):
                    dns_layer = packet[DNS]
                    packet_info['protocol_name'] = 'DNS'
                    
                    if dns_layer.qd:
                        query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        if query_name and not query_name.endswith('.in-addr.arpa'):
                            dns_info = {
                                'timestamp': datetime.now().isoformat(),
                                'query': query_name
                            }
                            self.recent_dns.append(dns_info)
                            self.domains_seen.add(query_name)
                    
                    self.protocols['DNS'] += 1
                
                # Extract HTTP
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        if any(method in payload[:100] for method in ['GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ']):
                            lines = payload.split('\\n')
                            if lines:
                                request_line = lines[0]
                                host = None
                                
                                for line in lines[1:]:
                                    if line.lower().startswith('host:'):
                                        host = line.split(':', 1)[1].strip()
                                        break
                                
                                if host:
                                    parts = request_line.split()
                                    method = parts[0] if parts else 'Unknown'
                                    url = parts[1] if len(parts) > 1 else '/'
                                    
                                    http_info = {
                                        'timestamp': datetime.now().isoformat(),
                                        'method': method,
                                        'host': host,
                                        'url': url
                                    }
                                    
                                    self.recent_http.append(http_info)
                                    self.domains_seen.add(host)
                                    packet_info['protocol_name'] = 'HTTP'
                                    self.protocols['HTTP'] += 1
                    except:
                        pass
                
                # Extract ICMP
                if packet.haslayer(ICMP):
                    packet_info['protocol_name'] = 'ICMP'
                    self.protocols['ICMP'] += 1
                
                # Store recent packet
                self.recent_packets.append(packet_info)
                
                # Update display every 10 packets
                if self.packet_count % 10 == 0:
                    self.display_real_time_activity()
                
            except Exception as e:
                pass
        
        # Start packet capture
        try:
            threading.Thread(target=lambda: sniff(
                prn=packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            ), daemon=True).start()
        except Exception as e:
            print(f"Packet capture error: {e}")
    
    def monitor_connections_realtime(self):
        """Monitor network connections in real-time"""
        seen_connections = set()
        
        while self.running:
            try:
                connections = psutil.net_connections()
                
                for conn in connections:
                    if conn.raddr:  # Has remote address
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        # Create unique connection ID
                        conn_id = f"{conn.pid}_{remote_ip}_{remote_port}"
                        
                        if conn_id not in seen_connections:
                            seen_connections.add(conn_id)
                            
                            # Get process name
                            process_name = "Unknown"
                            if conn.pid:
                                try:
                                    process = psutil.Process(conn.pid)
                                    process_name = process.name()
                                    self.processes_seen.add(process_name)
                                except:
                                    pass
                            
                            # Resolve domain
                            domain = self.resolve_ip_to_domain(remote_ip)
                            if domain:
                                self.domains_seen.add(domain)
                            
                            # Determine protocol
                            protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                            if remote_port == 443:
                                protocol = "HTTPS" if conn.type == socket.SOCK_STREAM else "QUIC"
                            elif remote_port == 80:
                                protocol = "HTTP"
                            
                            connection_info = {
                                'timestamp': datetime.now().isoformat(),
                                'process': process_name,
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'protocol': protocol,
                                'domain': domain
                            }
                            
                            self.recent_connections.append(connection_info)
                            self.ips_seen.add(remote_ip)
                            self.ports_seen.add(remote_port)
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                time.sleep(5)
    
    def start_realtime_monitoring(self):
        """Start real-time monitoring"""
        print("🚀 Starting Real-Time Network Monitor...")
        print("👀 You will see EXACTLY what's being captured as it happens!")
        print("⏰ Starting in 3 seconds...")
        time.sleep(3)
        
        self.running = True
        self.start_time = datetime.now()
        
        # Start packet capture
        print("📦 Starting packet capture...")
        self.capture_packets_realtime()
        
        # Start connection monitoring
        print("🔗 Starting connection monitoring...")
        threading.Thread(target=self.monitor_connections_realtime, daemon=True).start()
        
        # Initial display
        time.sleep(1)
        self.display_real_time_activity()
        
        # Keep updating display
        try:
            while self.running:
                time.sleep(5)  # Update every 5 seconds
                self.display_real_time_activity()
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def stop_monitoring(self, signum=None, frame=None):
        """Stop monitoring and show final summary"""
        self.running = False
        
        print("\n" + "=" * 80)
        print("📊 FINAL SUMMARY")
        print("=" * 80)
        
        duration = (datetime.now() - self.start_time).total_seconds() if self.start_time else 0
        
        print(f"""
⏱️  Total Duration: {duration:.1f} seconds
📦 Total Packets Captured: {self.packet_count:,}
💾 Total Bytes Captured: {self.bytes_captured:,}
🌐 Unique IP Addresses: {len(self.ips_seen)}
🌍 Unique Domains: {len(self.domains_seen)}
🔌 Unique Ports: {len(self.ports_seen)}
⚙️  Unique Processes: {len(self.processes_seen)}
🔗 Total Connections: {len(self.recent_connections)}

📊 TOP PROTOCOLS:
""")
        
        for protocol, count in self.protocols.most_common(10):
            print(f"   📊 {protocol}: {count:,} packets")
        
        print(f"""
🌍 ALL DOMAINS DISCOVERED:
""")
        
        for domain in sorted(self.domains_seen):
            print(f"   🌍 {domain}")
        
        print("\n✅ Real-time monitoring completed!")
        sys.exit(0)

def main():
    """Main function"""
    print("🔍 Real-Time Network Traffic Monitor")
    print("👀 Shows EXACTLY what's being captured as it happens")
    print("📱 Live updates every few seconds")
    print()
    
    # Admin check
    try:
        import ctypes
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️  Note: Not running as Administrator")
            print("   Some packet capture may be limited")
            print()
    except:
        pass
    
    # Create and start monitor
    monitor = RealTimeNetworkMonitor()
    monitor.start_realtime_monitoring()

if __name__ == "__main__":
    main()
