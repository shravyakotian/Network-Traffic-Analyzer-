#!/usr/bin/env python3
"""
Complete Network Traffic Scanner for Windows
Captures ALL network activity without any limitations.
Monitors every packet, every connection, every protocol.

Usage:
    python complete_network_scanner.py

Press Ctrl+C to stop and generate comprehensive report.
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
import struct
from datetime import datetime
from collections import Counter, defaultdict
from typing import Dict, Set, List, Optional, Any

try:
    from scapy.all import *
    import psutil
    import requests
    import concurrent.futures
    # import netifaces  # Optional - will use alternative methods
except ImportError:
    print("Error: Missing required packages. Install with:")
    print("pip install scapy psutil requests")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CompleteNetworkScanner:
    def __init__(self):
        self.running = False
        self.start_time = None
        self.log_file = f"complete_network_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.summary_file = f"complete_network_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.packets_file = f"complete_packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"
        
        # Comprehensive tracking - NO LIMITS!
        self.all_packets = []
        self.all_connections = []
        self.all_processes = {}
        self.all_domains = set()
        self.all_ips = set()
        self.all_ports = set()
        self.all_protocols = Counter()
        self.all_dns_queries = set()
        self.all_http_requests = []
        self.all_https_connections = []
        self.all_udp_traffic = []
        self.all_tcp_traffic = []
        self.all_icmp_traffic = []
        self.all_network_interfaces = {}
        self.all_listening_ports = []
        self.all_established_connections = []
        self.all_process_connections = defaultdict(list)
        
        # Raw packet data
        self.raw_packet_count = 0
        self.total_bytes_captured = 0
        self.packet_sizes = []
        
        # Connection tracking
        self.connection_states = Counter()
        self.connection_lock = threading.Lock()
        
        # Domain resolution - comprehensive
        self.domain_cache = {}
        self.reverse_dns_cache = {}
        
        # Network interface analysis
        self.interface_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'protocols': Counter()})
        
        # Get ALL network interfaces
        self.get_all_network_interfaces()
        
        # Setup signal handler
        signal.signal(signal.SIGINT, self.stop_scanning)
        
        print("🌐 Complete Network Scanner Initialized")
        print("🔍 Will capture ALL network traffic without limitations")
        print(f"📁 Log file: {self.log_file}")
        print(f"📊 Summary file: {self.summary_file}")
        print(f"📦 Packets file: {self.packets_file}")
    
    def get_all_network_interfaces(self):
        """Get ALL available network interfaces with detailed info"""
        try:
            # Scapy interfaces
            scapy_interfaces = get_if_list()
            
            # psutil interfaces
            psutil_interfaces = psutil.net_if_addrs()
            
            # Combine all interface information
            for iface in scapy_interfaces:
                self.all_network_interfaces[iface] = {
                    'type': 'scapy',
                    'name': iface,
                    'addresses': []
                }
            
            # Add psutil interface info
            for iface, addrs in psutil_interfaces.items():
                if iface not in self.all_network_interfaces:
                    self.all_network_interfaces[iface] = {
                        'type': 'psutil',
                        'name': iface,
                        'addresses': []
                    }
                
                for addr in addrs:
                    self.all_network_interfaces[iface]['addresses'].append({
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast,
                        'family': addr.family
                    })
            
            logger.info(f"Found {len(self.all_network_interfaces)} network interfaces")
            
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
    
    def resolve_all_domains(self, ip: str) -> Optional[str]:
        """Comprehensive domain resolution"""
        if not ip or ip in self.reverse_dns_cache:
            return self.reverse_dns_cache.get(ip)
        
        try:
            # Try multiple resolution methods
            domain = None
            
            # Method 1: Standard reverse DNS
            try:
                domain = socket.gethostbyaddr(ip)[0]
            except:
                pass
            
            # Method 2: Alternative resolution
            if not domain:
                try:
                    domain = socket.getfqdn(ip)
                    if domain == ip:
                        domain = None
                except:
                    pass
            
            # Cache result
            self.reverse_dns_cache[ip] = domain
            return domain
            
        except Exception as e:
            self.reverse_dns_cache[ip] = None
            return None
    
    def log_everything(self, category: str, message: str, data: Dict[str, Any] = None):
        """Log everything with detailed information"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{category}] {message}"
        
        if data:
            log_entry += f" | Data: {json.dumps(data, default=str)}"
        
        # Print to console
        print(log_entry)
        
        # Write to log file
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
        except Exception as e:
            logger.error(f"Error writing to log: {e}")
    
    def capture_all_packets(self):
        """Capture ALL packets without any filtering"""
        def packet_handler(packet):
            try:
                self.raw_packet_count += 1
                packet_size = len(packet)
                self.total_bytes_captured += packet_size
                self.packet_sizes.append(packet_size)
                
                # Extract basic packet info
                packet_info = {
                    'timestamp': datetime.now().isoformat(),
                    'size': packet_size,
                    'layers': [],
                    'src': None,
                    'dst': None,
                    'protocol': None,
                    'src_port': None,
                    'dst_port': None
                }
                
                # Analyze all layers
                layer = packet
                while layer:
                    layer_name = layer.__class__.__name__
                    packet_info['layers'].append(layer_name)
                    layer = layer.payload if hasattr(layer, 'payload') else None
                
                # Extract IP information
                if packet.haslayer(IP):
                    ip_layer = packet[IP]
                    packet_info['src'] = ip_layer.src
                    packet_info['dst'] = ip_layer.dst
                    packet_info['protocol'] = ip_layer.proto
                    
                    self.all_ips.add(ip_layer.src)
                    self.all_ips.add(ip_layer.dst)
                    
                    # Resolve domains for both IPs
                    src_domain = self.resolve_all_domains(ip_layer.src)
                    dst_domain = self.resolve_all_domains(ip_layer.dst)
                    
                    if src_domain:
                        self.all_domains.add(src_domain)
                    if dst_domain:
                        self.all_domains.add(dst_domain)
                
                # Extract TCP information
                if packet.haslayer(TCP):
                    tcp_layer = packet[TCP]
                    packet_info['src_port'] = tcp_layer.sport
                    packet_info['dst_port'] = tcp_layer.dport
                    packet_info['tcp_flags'] = tcp_layer.flags
                    
                    self.all_ports.add(tcp_layer.sport)
                    self.all_ports.add(tcp_layer.dport)
                    self.all_protocols['TCP'] += 1
                    
                    self.all_tcp_traffic.append(packet_info.copy())
                
                # Extract UDP information
                if packet.haslayer(UDP):
                    udp_layer = packet[UDP]
                    packet_info['src_port'] = udp_layer.sport
                    packet_info['dst_port'] = udp_layer.dport
                    
                    self.all_ports.add(udp_layer.sport)
                    self.all_ports.add(udp_layer.dport)
                    self.all_protocols['UDP'] += 1
                    
                    self.all_udp_traffic.append(packet_info.copy())
                
                # Extract ICMP information
                if packet.haslayer(ICMP):
                    icmp_layer = packet[ICMP]
                    packet_info['icmp_type'] = icmp_layer.type
                    packet_info['icmp_code'] = icmp_layer.code
                    
                    self.all_protocols['ICMP'] += 1
                    self.all_icmp_traffic.append(packet_info.copy())
                
                # Extract DNS information
                if packet.haslayer(DNS):
                    dns_layer = packet[DNS]
                    if dns_layer.qd:
                        query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        if query_name:
                            self.all_dns_queries.add(query_name)
                            self.all_domains.add(query_name)
                            packet_info['dns_query'] = query_name
                    
                    self.all_protocols['DNS'] += 1
                
                # Extract HTTP information
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode('utf-8', errors='ignore')
                        
                        # Check for HTTP
                        if any(method in payload[:100] for method in ['GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ', 'OPTIONS ']):
                            lines = payload.split('\\n')
                            if lines:
                                request_line = lines[0]
                                host = None
                                
                                for line in lines[1:]:
                                    if line.lower().startswith('host:'):
                                        host = line.split(':', 1)[1].strip()
                                        break
                                
                                http_info = {
                                    'timestamp': packet_info['timestamp'],
                                    'request_line': request_line,
                                    'host': host,
                                    'src_ip': packet_info['src'],
                                    'dst_ip': packet_info['dst'],
                                    'size': packet_size
                                }
                                
                                self.all_http_requests.append(http_info)
                                
                                if host:
                                    self.all_domains.add(host)
                                
                                self.all_protocols['HTTP'] += 1
                                
                    except:
                        pass
                
                # Store packet info
                self.all_packets.append(packet_info)
                
                # Log significant packets
                if self.raw_packet_count % 100 == 0:
                    self.log_everything("PACKET", f"Captured {self.raw_packet_count} packets, {self.total_bytes_captured} bytes")
                
            except Exception as e:
                logger.debug(f"Packet handler error: {e}")
        
        # Start packet capture on ALL interfaces without any filter
        try:
            self.log_everything("SYSTEM", "Starting comprehensive packet capture on ALL interfaces")
            threading.Thread(target=lambda: sniff(
                prn=packet_handler,
                store=False,
                stop_filter=lambda x: not self.running
            ), daemon=True).start()
            
        except Exception as e:
            logger.error(f"Packet capture error: {e}")
    
    def monitor_all_processes(self):
        """Monitor ALL processes and their network connections"""
        self.log_everything("SYSTEM", "Starting comprehensive process monitoring")
        
        while self.running:
            try:
                # Get all processes
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 'memory_info', 'cpu_percent']):
                    try:
                        proc_info = proc.info
                        pid = proc_info['pid']
                        
                        # Store process info
                        self.all_processes[pid] = {
                            'name': proc_info['name'],
                            'exe': proc_info['exe'],
                            'cmdline': proc_info['cmdline'],
                            'create_time': proc_info['create_time'],
                            'memory_info': proc_info['memory_info'],
                            'cpu_percent': proc_info['cpu_percent'],
                            'connections': []
                        }
                        
                        # Get ALL connections for this process
                        try:
                            connections = proc.connections()
                            for conn in connections:
                                conn_info = {
                                    'timestamp': datetime.now().isoformat(),
                                    'pid': pid,
                                    'process_name': proc_info['name'],
                                    'family': conn.family,
                                    'type': conn.type,
                                    'laddr': conn.laddr,
                                    'raddr': conn.raddr,
                                    'status': conn.status if hasattr(conn, 'status') else 'UDP'
                                }
                                
                                self.all_processes[pid]['connections'].append(conn_info)
                                self.all_connections.append(conn_info)
                                self.all_process_connections[pid].append(conn_info)
                                
                                # Track connection states
                                if hasattr(conn, 'status'):
                                    self.connection_states[conn.status] += 1
                                
                                # Add IPs and ports
                                if conn.laddr:
                                    self.all_ips.add(conn.laddr.ip)
                                    self.all_ports.add(conn.laddr.port)
                                
                                if conn.raddr:
                                    self.all_ips.add(conn.raddr.ip)
                                    self.all_ports.add(conn.raddr.port)
                                    
                                    # Resolve domain
                                    domain = self.resolve_all_domains(conn.raddr.ip)
                                    if domain:
                                        self.all_domains.add(domain)
                                
                                # Track established connections
                                if hasattr(conn, 'status') and conn.status == 'ESTABLISHED':
                                    self.all_established_connections.append(conn_info)
                        
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                            
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logger.error(f"Process monitoring error: {e}")
                time.sleep(5)
    
    def monitor_all_listening_ports(self):
        """Monitor ALL listening ports"""
        self.log_everything("SYSTEM", "Starting comprehensive port monitoring")
        
        while self.running:
            try:
                # Get all listening connections
                listening_connections = psutil.net_connections(kind='inet')
                
                for conn in listening_connections:
                    if conn.status == 'LISTEN':
                        port_info = {
                            'timestamp': datetime.now().isoformat(),
                            'address': conn.laddr.ip if conn.laddr else None,
                            'port': conn.laddr.port if conn.laddr else None,
                            'family': conn.family,
                            'type': conn.type,
                            'pid': conn.pid,
                            'process_name': None
                        }
                        
                        # Get process name
                        if conn.pid:
                            try:
                                process = psutil.Process(conn.pid)
                                port_info['process_name'] = process.name()
                            except:
                                pass
                        
                        self.all_listening_ports.append(port_info)
                        
                        if conn.laddr:
                            self.all_ports.add(conn.laddr.port)
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logger.error(f"Port monitoring error: {e}")
                time.sleep(15)
    
    def scan_network_ranges(self):
        """Scan local network ranges for active hosts"""
        self.log_everything("SYSTEM", "Starting network range scanning")
        
        # Get local network ranges
        local_ranges = []
        try:
            for interface_name, interface_info in self.all_network_interfaces.items():
                for addr in interface_info['addresses']:
                    if isinstance(addr, dict) and 'address' in addr:
                        ip = addr['address']
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            if ip_obj.is_private and not ip_obj.is_loopback:
                                # Create network range
                                netmask = addr.get('netmask', '255.255.255.0')
                                network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                                local_ranges.append(network)
                        except:
                            pass
        except Exception as e:
            logger.error(f"Network range detection error: {e}")
        
        # Scan each range
        for network in local_ranges:
            self.log_everything("NETWORK_SCAN", f"Scanning network range: {network}")
            
            # Ping sweep
            for ip in network.hosts():
                if not self.running:
                    break
                
                try:
                    # Quick ping check
                    response = subprocess.run(
                        ['ping', '-n', '1', '-w', '1000', str(ip)],
                        capture_output=True,
                        text=True,
                        timeout=2
                    )
                    
                    if response.returncode == 0:
                        self.all_ips.add(str(ip))
                        domain = self.resolve_all_domains(str(ip))
                        if domain:
                            self.all_domains.add(domain)
                        
                        self.log_everything("HOST_DISCOVERED", f"Active host: {ip} ({domain})")
                        
                except:
                    pass
                
                time.sleep(0.1)  # Small delay to avoid flooding
    
    def start_comprehensive_scan(self):
        """Start the most comprehensive network scan possible"""
        print("=" * 100)
        print("🌐 COMPLETE NETWORK SCANNER STARTED")
        print("🔍 Capturing ALL network traffic without limitations")
        print("=" * 100)
        print(f"📁 Log file: {self.log_file}")
        print(f"📊 Summary file: {self.summary_file}")
        print(f"📦 Packets file: {self.packets_file}")
        print(f"🌐 Network interfaces: {len(self.all_network_interfaces)}")
        print("⏹️  Press Ctrl+C to stop and generate comprehensive report")
        print("=" * 100)
        
        self.running = True
        self.start_time = datetime.now()
        
        # Initialize log file
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write(f"Complete Network Scanner - Started at {self.start_time.isoformat()}\n")
            f.write("=" * 100 + "\n\n")
        
        # Start ALL monitoring threads
        threads = []
        
        # 1. Comprehensive packet capture
        self.log_everything("SYSTEM", "Starting comprehensive packet capture")
        self.capture_all_packets()
        
        # 2. Complete process monitoring
        self.log_everything("SYSTEM", "Starting complete process monitoring")
        t1 = threading.Thread(target=self.monitor_all_processes, daemon=True)
        t1.start()
        threads.append(t1)
        
        # 3. All listening ports
        self.log_everything("SYSTEM", "Starting comprehensive port monitoring")
        t2 = threading.Thread(target=self.monitor_all_listening_ports, daemon=True)
        t2.start()
        threads.append(t2)
        
        # 4. Network range scanning
        self.log_everything("SYSTEM", "Starting network range scanning")
        t3 = threading.Thread(target=self.scan_network_ranges, daemon=True)
        t3.start()
        threads.append(t3)
        
        # 5. Status updates
        def comprehensive_status():
            while self.running:
                time.sleep(30)
                self.log_everything("STATUS", 
                    f"Packets: {self.raw_packet_count}, "
                    f"Bytes: {self.total_bytes_captured}, "
                    f"IPs: {len(self.all_ips)}, "
                    f"Domains: {len(self.all_domains)}, "
                    f"Ports: {len(self.all_ports)}, "
                    f"Connections: {len(self.all_connections)}, "
                    f"Processes: {len(self.all_processes)}"
                )
        
        t4 = threading.Thread(target=comprehensive_status, daemon=True)
        t4.start()
        threads.append(t4)
        
        self.log_everything("SYSTEM", "ALL monitoring systems active - comprehensive scan in progress")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_scanning()
    
    def stop_scanning(self, signum=None, frame=None):
        """Stop comprehensive scanning and generate complete report"""
        self.log_everything("SYSTEM", "Stopping comprehensive network scan...")
        self.running = False
        
        # Wait for threads to finish
        time.sleep(5)
        
        self.generate_complete_report()
        
        print("\n✅ Comprehensive scan completed. Check all output files.")
        sys.exit(0)
    
    def generate_complete_report(self):
        """Generate the most comprehensive network report possible"""
        end_time = datetime.now()
        duration = end_time - self.start_time if self.start_time else "Unknown"
        
        # Create the most comprehensive summary possible
        complete_summary = {
            'scan_info': {
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': end_time.isoformat(),
                'duration_seconds': duration.total_seconds() if hasattr(duration, 'total_seconds') else 0,
                'duration_minutes': duration.total_seconds() / 60 if hasattr(duration, 'total_seconds') else 0
            },
            'network_discovery': {
                'total_packets_captured': self.raw_packet_count,
                'total_bytes_captured': self.total_bytes_captured,
                'average_packet_size': sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0,
                'all_ip_addresses': sorted(list(self.all_ips)),
                'all_domains': sorted(list(self.all_domains)),
                'all_ports': sorted(list(self.all_ports)),
                'all_dns_queries': sorted(list(self.all_dns_queries))
            },
            'protocol_analysis': {
                'protocol_distribution': dict(self.all_protocols),
                'tcp_connections': len(self.all_tcp_traffic),
                'udp_connections': len(self.all_udp_traffic),
                'icmp_traffic': len(self.all_icmp_traffic),
                'http_requests': len(self.all_http_requests),
                'connection_states': dict(self.connection_states)
            },
            'process_analysis': {
                'total_processes_monitored': len(self.all_processes),
                'processes_with_connections': len([p for p in self.all_processes.values() if p['connections']]),
                'total_process_connections': len(self.all_connections),
                'established_connections': len(self.all_established_connections),
                'listening_ports': len(self.all_listening_ports)
            },
            'network_infrastructure': {
                'network_interfaces': self.all_network_interfaces,
                'interface_count': len(self.all_network_interfaces)
            },
            'detailed_data': {
                'all_packets': self.all_packets[-1000:],  # Last 1000 packets
                'all_connections': self.all_connections,
                'all_processes': self.all_processes,
                'all_tcp_traffic': self.all_tcp_traffic,
                'all_udp_traffic': self.all_udp_traffic,
                'all_icmp_traffic': self.all_icmp_traffic,
                'all_http_requests': self.all_http_requests,
                'all_listening_ports': self.all_listening_ports,
                'all_established_connections': self.all_established_connections,
                'process_connections': dict(self.all_process_connections)
            }
        }
        
        # Save complete JSON summary
        with open(self.summary_file, 'w', encoding='utf-8') as f:
            json.dump(complete_summary, f, indent=2, ensure_ascii=False, default=str)
        
        # Generate comprehensive text report
        text_report = self.generate_text_report(complete_summary)
        
        # Append to log
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write("\n\n" + "=" * 100 + "\n")
            f.write("COMPLETE NETWORK SCAN REPORT\n")
            f.write("=" * 100 + "\n")
            f.write(text_report)
        
        # Print comprehensive report
        print("\n" + "=" * 100)
        print("📊 COMPLETE NETWORK SCAN REPORT")
        print("=" * 100)
        print(text_report)
        print(f"📁 Full log: {self.log_file}")
        print(f"📊 Complete summary: {self.summary_file}")
        print("=" * 100)
    
    def generate_text_report(self, summary):
        """Generate comprehensive text report"""
        scan_info = summary['scan_info']
        network = summary['network_discovery']
        protocols = summary['protocol_analysis']
        processes = summary['process_analysis']
        
        report = f"""
📅 SCAN SUMMARY:
   Duration: {scan_info['duration_minutes']:.1f} minutes
   Packets captured: {network['total_packets_captured']:,}
   Bytes captured: {network['total_bytes_captured']:,}
   Average packet size: {network['average_packet_size']:.1f} bytes
   
🌐 NETWORK DISCOVERY:
   IP addresses discovered: {len(network['all_ip_addresses'])}
   Domains discovered: {len(network['all_domains'])}
   Ports discovered: {len(network['all_ports'])}
   DNS queries captured: {len(network['all_dns_queries'])}
   
📊 PROTOCOL ANALYSIS:
   TCP connections: {protocols['tcp_connections']}
   UDP connections: {protocols['udp_connections']}
   ICMP traffic: {protocols['icmp_traffic']}
   HTTP requests: {protocols['http_requests']}
   
🔍 PROCESS ANALYSIS:
   Total processes monitored: {processes['total_processes_monitored']}
   Processes with network activity: {processes['processes_with_connections']}
   Total connections: {processes['total_process_connections']}
   Established connections: {processes['established_connections']}
   Listening ports: {processes['listening_ports']}

🌍 ALL DISCOVERED IP ADDRESSES:
"""
        
        for ip in network['all_ip_addresses'][:50]:  # Show first 50
            report += f"   🌍 {ip}\n"
        
        if len(network['all_ip_addresses']) > 50:
            report += f"   ... and {len(network['all_ip_addresses']) - 50} more\n"
        
        report += f"""
🌐 ALL DISCOVERED DOMAINS:
"""
        
        for domain in network['all_domains'][:50]:  # Show first 50
            report += f"   🌐 {domain}\n"
            
        if len(network['all_domains']) > 50:
            report += f"   ... and {len(network['all_domains']) - 50} more\n"
        
        report += f"""
📡 PROTOCOL DISTRIBUTION:
"""
        
        for protocol, count in protocols['protocol_distribution'].items():
            report += f"   📡 {protocol}: {count:,} packets\n"
        
        report += f"""
🔌 CONNECTION STATES:
"""
        
        for state, count in protocols['connection_states'].items():
            report += f"   🔌 {state}: {count} connections\n"
        
        return report


def main():
    """Main function"""
    print("🌐 Complete Network Scanner for Windows")
    print("🔍 Captures ALL network traffic without any limitations")
    print("📊 Comprehensive analysis of packets, connections, processes, and protocols")
    print("⚠️  Run as Administrator for complete access")
    print()
    
    # Admin check
    try:
        import ctypes
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️  WARNING: Not running as Administrator")
            print("   Some network features may be limited")
            print("   For complete network scanning, run as Administrator")
            print()
    except:
        pass
    
    # Create and start comprehensive scanner
    scanner = CompleteNetworkScanner()
    scanner.start_comprehensive_scan()


if __name__ == "__main__":
    main()
