#!/usr/bin/env python3
"""
Live Network Monitor - Real-time packet visualization
Displays detailed network activity as it happens
"""

import time
import threading
import sys
import os
import json
import logging
from datetime import datetime
from collections import defaultdict, deque
from typing import Dict, Set, List, Optional, Tuple
import signal

# Third-party imports
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    try:
        from scapy.layers.tls import TLS
        TLS_AVAILABLE = True
    except ImportError:
        TLS_AVAILABLE = False
    
    import psutil
    
    try:
        import netifaces
        NETIFACES_AVAILABLE = True
    except ImportError:
        NETIFACES_AVAILABLE = False
        print("⚠️  netifaces not available - using fallback interface detection")
    
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install with: pip install scapy psutil")
    sys.exit(1)

class LiveNetworkMonitor:
    """Real-time network monitor with detailed packet visualization"""
    
    def __init__(self):
        self.running = False
        self.packet_count = 0
        self.start_time = datetime.now()
        self.last_update = time.time()
        
        # Real-time data storage
        self.recent_packets = deque(maxlen=100)  # Keep last 100 packets for display
        self.packet_types = defaultdict(int)
        self.src_ips = defaultdict(int)
        self.dst_ips = defaultdict(int)
        self.ports = defaultdict(int)
        self.protocols = defaultdict(int)
        self.domains = set()
        self.http_requests = deque(maxlen=50)
        self.dns_queries = deque(maxlen=50)
        self.connections = defaultdict(int)
        
        # Statistics
        self.total_bytes = 0
        self.bytes_per_second = 0
        self.packets_per_second = 0
        
        # Threading
        self.lock = threading.Lock()
        self.display_thread = None
        self.stats_thread = None
        
        # Get network interfaces
        self.interfaces = self._get_network_interfaces()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        print("🌐 Live Network Monitor initialized")
        print(f"🔍 Monitoring {len(self.interfaces)} network interfaces")
        print("📊 Real-time packet visualization enabled")
        
    def _get_network_interfaces(self) -> List[str]:
        """Get available network interfaces"""
        if NETIFACES_AVAILABLE:
            try:
                interfaces = netifaces.interfaces()
                active_interfaces = []
                
                for iface in interfaces:
                    try:
                        # Check if interface has an IP address
                        addrs = netifaces.ifaddresses(iface)
                        if netifaces.AF_INET in addrs or netifaces.AF_INET6 in addrs:
                            active_interfaces.append(iface)
                    except:
                        continue
                        
                return active_interfaces if active_interfaces else ['any']
            except:
                pass
        
        # Fallback to scapy interface detection
        try:
            return [iface for iface in get_if_list() if iface != 'lo']
        except:
            return ['any']
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print("\n🛑 Received shutdown signal, stopping monitor...")
        self.stop()
        sys.exit(0)
    
    def _resolve_domain(self, ip: str) -> Optional[str]:
        """Resolve IP to domain name"""
        try:
            import socket
            domain = socket.gethostbyaddr(ip)[0]
            return domain
        except:
            return None
    
    def _extract_packet_info(self, packet) -> Dict:
        """Extract detailed information from a packet"""
        info = {
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'size': len(packet),
            'protocol': 'Unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'flags': [],
            'payload_size': 0,
            'domain': None,
            'http_info': None,
            'dns_info': None,
            'description': ''
        }
        
        try:
            # Layer 3 - IP
            if IP in packet:
                info['src_ip'] = packet[IP].src
                info['dst_ip'] = packet[IP].dst
                info['protocol'] = packet[IP].proto
                
                # Layer 4 - Transport
                if TCP in packet:
                    info['protocol'] = 'TCP'
                    info['src_port'] = packet[TCP].sport
                    info['dst_port'] = packet[TCP].dport
                    info['payload_size'] = len(packet[TCP].payload)
                    
                    # TCP flags
                    tcp_flags = []
                    if packet[TCP].flags & 0x02: tcp_flags.append('SYN')
                    if packet[TCP].flags & 0x10: tcp_flags.append('ACK')
                    if packet[TCP].flags & 0x01: tcp_flags.append('FIN')
                    if packet[TCP].flags & 0x04: tcp_flags.append('RST')
                    if packet[TCP].flags & 0x08: tcp_flags.append('PSH')
                    if packet[TCP].flags & 0x20: tcp_flags.append('URG')
                    info['flags'] = tcp_flags
                    
                    # Common ports
                    if info['dst_port'] == 80:
                        info['description'] = 'HTTP'
                    elif info['dst_port'] == 443:
                        info['description'] = 'HTTPS'
                    elif info['dst_port'] == 53:
                        info['description'] = 'DNS over TCP'
                    elif info['dst_port'] == 22:
                        info['description'] = 'SSH'
                    elif info['dst_port'] == 25:
                        info['description'] = 'SMTP'
                    elif info['dst_port'] == 993:
                        info['description'] = 'IMAPS'
                    elif info['dst_port'] == 995:
                        info['description'] = 'POP3S'
                    
                elif UDP in packet:
                    info['protocol'] = 'UDP'
                    info['src_port'] = packet[UDP].sport
                    info['dst_port'] = packet[UDP].dport
                    info['payload_size'] = len(packet[UDP].payload)
                    
                    # Common UDP ports
                    if info['dst_port'] == 53:
                        info['description'] = 'DNS'
                    elif info['dst_port'] == 443:
                        info['description'] = 'QUIC/HTTP3'
                    elif info['dst_port'] == 123:
                        info['description'] = 'NTP'
                    elif info['dst_port'] == 67 or info['dst_port'] == 68:
                        info['description'] = 'DHCP'
                    elif info['dst_port'] == 161:
                        info['description'] = 'SNMP'
                
                elif ICMP in packet:
                    info['protocol'] = 'ICMP'
                    info['description'] = f"ICMP Type {packet[ICMP].type}"
            
            # IPv6
            elif IPv6 in packet:
                info['src_ip'] = packet[IPv6].src
                info['dst_ip'] = packet[IPv6].dst
                info['protocol'] = 'IPv6'
                
                if TCP in packet:
                    info['protocol'] = 'TCP/IPv6'
                    info['src_port'] = packet[TCP].sport
                    info['dst_port'] = packet[TCP].dport
                elif UDP in packet:
                    info['protocol'] = 'UDP/IPv6'
                    info['src_port'] = packet[UDP].sport
                    info['dst_port'] = packet[UDP].dport
            
            # Application layer protocols
            if DNS in packet:
                info['dns_info'] = self._extract_dns_info(packet)
                info['description'] = 'DNS Query/Response'
            
            if HTTPRequest in packet:
                info['http_info'] = self._extract_http_info(packet)
                info['description'] = 'HTTP Request'
            
            if TLS_AVAILABLE and TLS in packet:
                info['description'] = 'TLS/SSL'
            
        except Exception as e:
            info['description'] = f'Parse error: {str(e)[:50]}'
        
        return info
    
    def _extract_dns_info(self, packet) -> Dict:
        """Extract DNS query information"""
        dns_info = {'queries': [], 'responses': []}
        
        try:
            if DNSQR in packet:
                for i in range(packet[DNS].qdcount):
                    query = packet[DNSQR]
                    dns_info['queries'].append({
                        'name': query.qname.decode('utf-8', errors='ignore').rstrip('.'),
                        'type': query.qtype,
                        'class': query.qclass
                    })
            
            if DNSRR in packet:
                for i in range(packet[DNS].ancount):
                    response = packet[DNSRR]
                    dns_info['responses'].append({
                        'name': response.rrname.decode('utf-8', errors='ignore').rstrip('.'),
                        'type': response.type,
                        'data': str(response.rdata)
                    })
        except:
            pass
        
        return dns_info
    
    def _extract_http_info(self, packet) -> Dict:
        """Extract HTTP request information"""
        http_info = {}
        
        try:
            if HTTPRequest in packet:
                http_info['method'] = packet[HTTPRequest].Method.decode('utf-8', errors='ignore')
                http_info['path'] = packet[HTTPRequest].Path.decode('utf-8', errors='ignore')
                http_info['host'] = packet[HTTPRequest].Host.decode('utf-8', errors='ignore') if packet[HTTPRequest].Host else None
                http_info['user_agent'] = packet[HTTPRequest].User_Agent.decode('utf-8', errors='ignore') if packet[HTTPRequest].User_Agent else None
        except:
            pass
        
        return http_info
    
    def _packet_callback(self, packet):
        """Process captured packets"""
        try:
            with self.lock:
                self.packet_count += 1
                packet_info = self._extract_packet_info(packet)
                
                # Update statistics
                self.total_bytes += packet_info['size']
                self.recent_packets.append(packet_info)
                
                # Update counters
                if packet_info['protocol']:
                    self.protocols[packet_info['protocol']] += 1
                
                if packet_info['src_ip']:
                    self.src_ips[packet_info['src_ip']] += 1
                
                if packet_info['dst_ip']:
                    self.dst_ips[packet_info['dst_ip']] += 1
                
                if packet_info['dst_port']:
                    self.ports[packet_info['dst_port']] += 1
                
                # DNS queries
                if packet_info['dns_info']:
                    for query in packet_info['dns_info']['queries']:
                        self.dns_queries.append({
                            'time': packet_info['timestamp'],
                            'domain': query['name'],
                            'type': query['type']
                        })
                        self.domains.add(query['name'])
                
                # HTTP requests
                if packet_info['http_info']:
                    self.http_requests.append({
                        'time': packet_info['timestamp'],
                        'method': packet_info['http_info'].get('method', 'Unknown'),
                        'host': packet_info['http_info'].get('host', 'Unknown'),
                        'path': packet_info['http_info'].get('path', '/')
                    })
                
                # Connection tracking
                if packet_info['src_ip'] and packet_info['dst_ip']:
                    connection_key = f"{packet_info['src_ip']}:{packet_info['src_port']} -> {packet_info['dst_ip']}:{packet_info['dst_port']}"
                    self.connections[connection_key] += 1
                
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _calculate_stats(self):
        """Calculate real-time statistics"""
        while self.running:
            try:
                time.sleep(1)
                current_time = time.time()
                
                with self.lock:
                    time_diff = current_time - self.last_update
                    if time_diff >= 1:
                        # Calculate rates
                        self.packets_per_second = self.packet_count / time_diff if time_diff > 0 else 0
                        self.bytes_per_second = self.total_bytes / time_diff if time_diff > 0 else 0
                        
                        # Reset counters for next interval
                        self.last_update = current_time
                        
            except Exception as e:
                print(f"Error calculating stats: {e}")
                time.sleep(1)
    
    def _display_loop(self):
        """Main display loop"""
        while self.running:
            try:
                self._update_display()
                time.sleep(0.5)  # Update display every 500ms
            except Exception as e:
                print(f"Display error: {e}")
                time.sleep(1)
    
    def _update_display(self):
        """Update the real-time display"""
        try:
            # Clear screen
            os.system('cls' if os.name == 'nt' else 'clear')
            
            with self.lock:
                # Header
                print("🌐 LIVE NETWORK MONITOR")
                print("=" * 80)
                
                # Runtime stats
                runtime = datetime.now() - self.start_time
                print(f"⏱️  Runtime: {runtime}")
                print(f"📊 Packets: {self.packet_count:,} | Bytes: {self.total_bytes:,}")
                print(f"📈 Rate: {self.packets_per_second:.1f} pkt/s | {self.bytes_per_second/1024:.1f} KB/s")
                print(f"🌍 Unique IPs: {len(self.src_ips)} src, {len(self.dst_ips)} dst")
                print(f"🔌 Ports: {len(self.ports)} | Protocols: {len(self.protocols)}")
                print(f"🌐 Domains: {len(self.domains)} | Connections: {len(self.connections)}")
                
                print("\n" + "=" * 80)
                
                # Recent packets
                print("📦 RECENT PACKETS (Last 10)")
                print("-" * 80)
                recent_10 = list(self.recent_packets)[-10:]
                for packet in recent_10:
                    src = f"{packet['src_ip']}:{packet['src_port']}" if packet['src_port'] else packet['src_ip'] or 'Unknown'
                    dst = f"{packet['dst_ip']}:{packet['dst_port']}" if packet['dst_port'] else packet['dst_ip'] or 'Unknown'
                    flags_str = '|'.join(packet['flags']) if packet['flags'] else ''
                    
                    print(f"[{packet['timestamp']}] {packet['protocol']:>6} {src:>21} -> {dst:<21} "
                          f"{packet['size']:>6}b {flags_str:>15} {packet['description']}")
                
                # DNS queries
                if self.dns_queries:
                    print("\n🔍 RECENT DNS QUERIES (Last 5)")
                    print("-" * 80)
                    for query in list(self.dns_queries)[-5:]:
                        print(f"[{query['time']}] {query['domain']} (Type: {query['type']})")
                
                # HTTP requests
                if self.http_requests:
                    print("\n🌐 RECENT HTTP REQUESTS (Last 5)")
                    print("-" * 80)
                    for req in list(self.http_requests)[-5:]:
                        print(f"[{req['time']}] {req['method']} {req['host']}{req['path']}")
                
                # Top protocols
                print("\n📊 TOP PROTOCOLS")
                print("-" * 40)
                for protocol, count in sorted(self.protocols.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"{protocol:>10}: {count:>8} packets")
                
                # Top ports
                print("\n🔌 TOP PORTS")
                print("-" * 40)
                for port, count in sorted(self.ports.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"{port:>10}: {count:>8} packets")
                
                # Top destinations
                print("\n🎯 TOP DESTINATIONS")
                print("-" * 40)
                for ip, count in sorted(self.dst_ips.items(), key=lambda x: x[1], reverse=True)[:5]:
                    print(f"{ip:>15}: {count:>8} packets")
                
                print("\n" + "=" * 80)
                print("⏹️  Press Ctrl+C to stop monitoring")
                
        except Exception as e:
            print(f"Display update error: {e}")
    
    def start(self):
        """Start the live monitor"""
        self.running = True
        self.start_time = datetime.now()
        self.last_update = time.time()
        
        print("🚀 Starting live network monitor...")
        print("📡 Capturing packets on all interfaces...")
        print("💻 Starting real-time display...")
        
        # Start background threads
        self.display_thread = threading.Thread(target=self._display_loop, daemon=True)
        self.stats_thread = threading.Thread(target=self._calculate_stats, daemon=True)
        
        self.display_thread.start()
        self.stats_thread.start()
        
        # Start packet capture
        try:
            sniff(iface=self.interfaces, prn=self._packet_callback, store=0)
        except PermissionError:
            print("\n❌ Permission denied - Run as Administrator for full packet capture")
            print("🔄 Falling back to limited monitoring...")
            # Try with limited permissions
            sniff(prn=self._packet_callback, store=0)
        except Exception as e:
            print(f"❌ Packet capture error: {e}")
            print("🔄 Trying alternative capture method...")
            sniff(prn=self._packet_callback, store=0)
    
    def stop(self):
        """Stop the monitor"""
        self.running = False
        
        print("\n🛑 Stopping live network monitor...")
        print(f"📊 Final Statistics:")
        print(f"   📦 Total packets: {self.packet_count:,}")
        print(f"   📊 Total bytes: {self.total_bytes:,}")
        print(f"   🌍 Unique IPs: {len(self.src_ips)} src, {len(self.dst_ips)} dst")
        print(f"   🔌 Unique ports: {len(self.ports)}")
        print(f"   🌐 Domains seen: {len(self.domains)}")
        print(f"   🔗 Connections: {len(self.connections)}")
        
        # Save summary
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        summary_file = f"live_monitor_summary_{timestamp}.json"
        
        summary = {
            'timestamp': datetime.now().isoformat(),
            'runtime_seconds': (datetime.now() - self.start_time).total_seconds(),
            'total_packets': self.packet_count,
            'total_bytes': self.total_bytes,
            'unique_source_ips': len(self.src_ips),
            'unique_destination_ips': len(self.dst_ips),
            'unique_ports': len(self.ports),
            'unique_domains': len(self.domains),
            'unique_connections': len(self.connections),
            'top_protocols': dict(sorted(self.protocols.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_ports': dict(sorted(self.ports.items(), key=lambda x: x[1], reverse=True)[:10]),
            'top_destinations': dict(sorted(self.dst_ips.items(), key=lambda x: x[1], reverse=True)[:10]),
            'domains_seen': list(self.domains),
            'recent_dns_queries': list(self.dns_queries),
            'recent_http_requests': list(self.http_requests)
        }
        
        try:
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            print(f"💾 Summary saved to: {summary_file}")
        except Exception as e:
            print(f"❌ Error saving summary: {e}")


def main():
    """Main function"""
    print("🌐 Live Network Monitor for Windows")
    print("🔍 Real-time packet visualization and analysis")
    print("📊 Comprehensive network activity monitoring")
    print("⚠️  Run as Administrator for complete access")
    print()
    
    if os.name == 'nt':
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️  WARNING: Not running as Administrator")
                print("   Some network features may be limited")
                print("   For complete network monitoring, run as Administrator")
                print()
        except:
            pass
    
    try:
        monitor = LiveNetworkMonitor()
        monitor.start()
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
