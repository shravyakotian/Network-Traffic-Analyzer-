#!/usr/bin/env python3
"""
Ultimate Network Traffic Monitor for Windows
Captures ALL network activity including browser traffic using multiple proven methods.
Specially designed for Windows systems with comprehensive detection.

Usage:
    python ultimate_network_monitor.py

Press Ctrl+C to stop and generate summary.
"""

import os
import sys
import time
import socket
import signal
import threading
import subprocess
import re
from datetime import datetime
from collections import Counter
import json
import ipaddress

try:
    from scapy.all import *
    import psutil
except ImportError:
    print("Error: Missing required packages. Install with:")
    print("pip install scapy psutil")
    sys.exit(1)

class UltimateNetworkMonitor:
    def __init__(self):
        self.running = False
        self.start_time = None
        self.log_file = f"ultimate_network_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.summary_file = f"ultimate_network_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Comprehensive tracking
        self.total_packets = 0
        self.websites_visited = set()
        self.domains_visited = set()
        self.ip_addresses = set()
        self.protocols = Counter()
        self.dns_queries = set()
        self.http_requests = []
        self.browser_connections = []
        self.all_connections = []
        
        # Domain resolution cache
        self.domain_cache = {}
        
        # Setup signal handler
        signal.signal(signal.SIGINT, self.stop_monitoring)
        
        print("🚀 Ultimate Network Traffic Monitor Initialized")
    
    def resolve_ip_to_domain(self, ip):
        """Resolve IP to domain with caching"""
        if ip in self.domain_cache:
            return self.domain_cache[ip]
        
        # Skip local IPs
        try:
            if ipaddress.ip_address(ip).is_private:
                self.domain_cache[ip] = None
                return None
        except:
            pass
        
        try:
            domain = socket.gethostbyaddr(ip)[0]
            self.domain_cache[ip] = domain
            return domain
        except:
            self.domain_cache[ip] = None
            return None
    
    def log_activity(self, activity_type, message):
        """Log activity to file and console"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{activity_type}] {message}"
        
        # Print to console
        print(log_entry)
        
        # Write to log file
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
        except:
            pass
    
    def monitor_dns_queries(self):
        """Monitor DNS queries in real-time on all interfaces"""
        def dns_handler(packet):
            try:
                if packet.haslayer(DNS):
                    dns_layer = packet[DNS]
                    if dns_layer.qd:  # DNS Query
                        query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        if query_name and not query_name.endswith('.in-addr.arpa'):
                            self.dns_queries.add(query_name)
                            self.websites_visited.add(query_name)
                            self.log_activity("DNS", f"Query: {query_name}")
            except:
                pass
        
        # Start DNS monitoring on all interfaces
        try:
            # Try to get available interfaces
            from scapy.all import get_if_list
            interfaces = get_if_list()
            self.log_activity("SYSTEM", f"Available interfaces: {interfaces}")
            
            # Monitor DNS on all interfaces
            threading.Thread(target=lambda: sniff(filter="udp port 53", prn=dns_handler, store=False, 
                                                 stop_filter=lambda x: not self.running), daemon=True).start()
        except Exception as e:
            self.log_activity("ERROR", f"DNS monitoring setup error: {e}")
            # Fallback to basic DNS monitoring
            threading.Thread(target=lambda: sniff(filter="port 53", prn=dns_handler, store=False, 
                                                 stop_filter=lambda x: not self.running), daemon=True).start()
    
    def monitor_browser_processes(self):
        """Monitor browser processes and their connections (TCP and UDP for QUIC)"""
        browsers = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe', 'safari.exe', 'iexplore.exe', 'brave.exe']
        web_ports = [80, 443, 8080, 8443, 3000, 5000, 9000]  # Common web ports
        
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    proc_name = proc.info['name']
                    if proc_name and proc_name.lower() in browsers:
                        try:
                            # Get both TCP and UDP connections
                            tcp_connections = proc.connections(kind='tcp')
                            udp_connections = proc.connections(kind='udp')
                            all_connections = tcp_connections + udp_connections
                            
                            for conn in all_connections:
                                if conn.raddr:  # Has remote address
                                    remote_ip = conn.raddr.ip
                                    remote_port = conn.raddr.port
                                    
                                    # Check for web traffic (not just 80/443)
                                    is_web_traffic = (
                                        remote_port in web_ports or
                                        (conn.type == socket.SOCK_DGRAM and remote_port == 443) or  # QUIC
                                        (conn.status == 'ESTABLISHED' and remote_port in [80, 443]) or
                                        not self.resolve_ip_to_domain(remote_ip) is None  # Has resolvable domain
                                    )
                                    
                                    if is_web_traffic:
                                        # Determine protocol
                                        if conn.type == socket.SOCK_DGRAM and remote_port == 443:
                                            protocol = "QUIC/HTTP3"
                                        elif conn.type == socket.SOCK_DGRAM:
                                            protocol = "UDP"
                                        elif remote_port == 443:
                                            protocol = "HTTPS/TCP"
                                        elif remote_port == 80:
                                            protocol = "HTTP/TCP"
                                        else:
                                            protocol = f"TCP/{remote_port}"
                                        
                                        # Resolve domain
                                        domain = self.resolve_ip_to_domain(remote_ip)
                                        
                                        connection_key = f"{proc_name}_{remote_ip}_{remote_port}_{protocol}"
                                        
                                        # Avoid duplicates (check last 50 connections)
                                        recent_keys = [f"{c['browser']}_{c['remote_ip']}_{c['remote_port']}_{c['protocol']}" 
                                                     for c in self.browser_connections[-50:]]
                                        
                                        if connection_key not in recent_keys:
                                            connection_info = {
                                                'timestamp': datetime.now().isoformat(),
                                                'browser': proc_name,
                                                'pid': proc.info['pid'],
                                                'remote_ip': remote_ip,
                                                'remote_port': remote_port,
                                                'protocol': protocol,
                                                'domain': domain,
                                                'status': getattr(conn, 'status', 'UDP'),
                                                'connection_type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                                            }
                                            
                                            self.browser_connections.append(connection_info)
                                            self.ip_addresses.add(remote_ip)
                                            
                                            if domain:
                                                self.websites_visited.add(domain)
                                                self.domains_visited.add(domain)
                                                self.log_activity("BROWSER", f"{proc_name} -> {domain} ({remote_ip}:{remote_port}) [{protocol}]")
                                            else:
                                                self.log_activity("BROWSER", f"{proc_name} -> {remote_ip}:{remote_port} [{protocol}]")
                                        
                        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                            continue
                
                time.sleep(2)  # Check every 2 seconds for more responsive detection
                
            except Exception as e:
                self.log_activity("ERROR", f"Browser monitoring error: {e}")
                time.sleep(5)
    
    def monitor_network_connections(self):
        """Monitor all network connections including UDP (QUIC) and TCP"""
        while self.running:
            try:
                # Get both TCP and UDP connections
                tcp_connections = psutil.net_connections(kind='tcp')
                udp_connections = psutil.net_connections(kind='udp')
                all_connections = tcp_connections + udp_connections
                
                for conn in all_connections:
                    if conn.raddr:  # Has remote address
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port
                        
                        # Check for web traffic (expanded criteria)
                        is_web_traffic = (
                            remote_port in [80, 443, 8080, 8443, 3000, 5000, 9000] or
                            (conn.type == socket.SOCK_DGRAM and remote_port == 443) or  # QUIC
                            (hasattr(conn, 'status') and conn.status == 'ESTABLISHED' and remote_port in [80, 443])
                        )
                        
                        if is_web_traffic:
                            # Determine protocol
                            if conn.type == socket.SOCK_DGRAM and remote_port == 443:
                                protocol = "QUIC/HTTP3"
                            elif conn.type == socket.SOCK_DGRAM:
                                protocol = "UDP"
                            elif remote_port == 443:
                                protocol = "HTTPS/TCP"
                            elif remote_port == 80:
                                protocol = "HTTP/TCP"
                            else:
                                protocol = f"TCP/{remote_port}"
                            
                            # Skip if already processed recently
                            connection_key = f"{remote_ip}:{remote_port}:{protocol}"
                            recent_keys = [f"{c['remote_ip']}:{c['remote_port']}:{c['protocol']}" 
                                         for c in self.all_connections[-30:]]
                            
                            if connection_key not in recent_keys:
                                domain = self.resolve_ip_to_domain(remote_ip)
                                
                                connection_info = {
                                    'timestamp': datetime.now().isoformat(),
                                    'local_ip': conn.laddr.ip if conn.laddr else 'N/A',
                                    'local_port': conn.laddr.port if conn.laddr else 'N/A',
                                    'remote_ip': remote_ip,
                                    'remote_port': remote_port,
                                    'protocol': protocol,
                                    'domain': domain,
                                    'status': getattr(conn, 'status', 'UDP'),
                                    'pid': conn.pid,
                                    'connection_type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                                }
                                
                                # Get process name if available
                                if conn.pid:
                                    try:
                                        process = psutil.Process(conn.pid)
                                        connection_info['process'] = process.name()
                                    except:
                                        connection_info['process'] = 'Unknown'
                                else:
                                    connection_info['process'] = 'Unknown'
                                
                                self.all_connections.append(connection_info)
                                self.ip_addresses.add(remote_ip)
                                
                                if domain:
                                    self.websites_visited.add(domain)
                                    self.domains_visited.add(domain)
                                    self.log_activity("NETWORK", f"{connection_info['process']} -> {domain} ({remote_ip}:{remote_port}) [{protocol}]")
                                else:
                                    self.log_activity("NETWORK", f"{connection_info['process']} -> {remote_ip}:{remote_port} [{protocol}]")
                
                time.sleep(3)  # Check every 3 seconds
                
            except Exception as e:
                self.log_activity("ERROR", f"Network monitoring error: {e}")
                time.sleep(10)
    
    def monitor_http_traffic(self):
        """Monitor HTTP traffic using packet capture"""
        def http_handler(packet):
            try:
                if packet.haslayer(TCP) and packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Check for HTTP requests
                    if any(method in payload for method in ['GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ']):
                        
                        # Extract Host header
                        lines = payload.split('\n')
                        host = None
                        request_line = lines[0].strip() if lines else ''
                        
                        for line in lines:
                            if line.lower().startswith('host:'):
                                host = line.split(':', 1)[1].strip()
                                break
                        
                        if host:
                            self.websites_visited.add(host)
                            self.domains_visited.add(host)
                            
                            http_request = {
                                'timestamp': datetime.now().isoformat(),
                                'method': request_line.split()[0] if request_line else 'Unknown',
                                'url': request_line.split()[1] if len(request_line.split()) > 1 else '/',
                                'host': host,
                                'src_ip': packet[IP].src,
                                'dst_ip': packet[IP].dst
                            }
                            
                            self.http_requests.append(http_request)
                            self.log_activity("HTTP", f"{http_request['method']} {host}{http_request['url']}")
                        
                        self.total_packets += 1
                        
            except Exception as e:
                pass
        
        # Start HTTP monitoring
        threading.Thread(target=lambda: sniff(filter="tcp port 80", prn=http_handler, store=False, stop_filter=lambda x: not self.running), daemon=True).start()
    
    def monitor_quic_traffic(self):
        """Monitor QUIC traffic (HTTP/3) over UDP port 443"""
        def quic_handler(packet):
            try:
                if packet.haslayer(UDP) and packet.haslayer(IP):
                    # QUIC typically uses UDP port 443
                    if packet[UDP].dport == 443 or packet[UDP].sport == 443:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                        
                        # Determine direction and target
                        target_ip = dst_ip if dst_port == 443 else src_ip
                        target_port = dst_port if dst_port == 443 else src_port
                        
                        # Resolve domain for target IP
                        domain = self.resolve_ip_to_domain(target_ip)
                        
                        # Create unique key to avoid duplicates
                        quic_key = f"QUIC_{target_ip}_{target_port}"
                        recent_keys = [f"QUIC_{c.get('remote_ip', '')}_{c.get('remote_port', '')}" 
                                     for c in self.all_connections[-20:]]
                        
                        if quic_key not in recent_keys:
                            quic_connection = {
                                'timestamp': datetime.now().isoformat(),
                                'local_ip': src_ip if dst_port == 443 else dst_ip,
                                'local_port': src_port if dst_port == 443 else dst_port,
                                'remote_ip': target_ip,
                                'remote_port': target_port,
                                'protocol': 'QUIC/HTTP3',
                                'domain': domain,
                                'status': 'UDP',
                                'connection_type': 'UDP',
                                'process': 'Unknown'
                            }
                            
                            self.all_connections.append(quic_connection)
                            self.ip_addresses.add(target_ip)
                            
                            if domain:
                                self.websites_visited.add(domain)
                                self.domains_visited.add(domain)
                                self.log_activity("QUIC", f"HTTP/3 connection to {domain} ({target_ip}:443)")
                            else:
                                self.log_activity("QUIC", f"HTTP/3 connection to {target_ip}:443")
                        
            except Exception as e:
                pass
        
        # Start QUIC monitoring
        threading.Thread(target=lambda: sniff(filter="udp port 443", prn=quic_handler, store=False, 
                                             stop_filter=lambda x: not self.running), daemon=True).start()
    
    def start_monitoring(self):
        """Start comprehensive monitoring"""
        print("="*80)
        print("🚀 ULTIMATE NETWORK TRAFFIC MONITOR STARTED")
        print("="*80)
        print(f"📁 Log file: {self.log_file}")
        print(f"📊 Summary file: {self.summary_file}")
        print("⏹️  Press Ctrl+C to stop monitoring and generate summary")
        print("="*80)
        
        self.running = True
        self.start_time = datetime.now()
        
        # Initialize log file
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write(f"Ultimate Network Traffic Monitor - Started at {self.start_time.isoformat()}\n")
            f.write("="*80 + "\n\n")
        
        # Start all monitoring threads
        self.log_activity("SYSTEM", "Starting DNS monitoring...")
        self.monitor_dns_queries()
        
        self.log_activity("SYSTEM", "Starting browser monitoring (TCP + UDP/QUIC)...")
        threading.Thread(target=self.monitor_browser_processes, daemon=True).start()
        
        self.log_activity("SYSTEM", "Starting network connection monitoring (TCP + UDP)...")
        threading.Thread(target=self.monitor_network_connections, daemon=True).start()
        
        self.log_activity("SYSTEM", "Starting HTTP traffic monitoring...")
        self.monitor_http_traffic()
        
        self.log_activity("SYSTEM", "Starting QUIC/HTTP3 traffic monitoring...")
        threading.Thread(target=self.monitor_quic_traffic, daemon=True).start()
        
        # Status update thread
        def status_update():
            while self.running:
                time.sleep(30)  # Every 30 seconds
                self.log_activity("STATUS", f"Websites: {len(self.websites_visited)}, IPs: {len(self.ip_addresses)}, DNS: {len(self.dns_queries)}")
        
        threading.Thread(target=status_update, daemon=True).start()
        
        self.log_activity("SYSTEM", "All monitoring systems active. Browse websites to see activity...")
        
        # Keep main thread alive
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_monitoring()
    
    def stop_monitoring(self, signum=None, frame=None):
        """Stop monitoring and generate summary"""
        self.log_activity("SYSTEM", "Stopping network monitoring...")
        self.running = False
        
        # Wait for threads to finish
        time.sleep(3)
        
        self.generate_summary()
        
        print("\n✅ Monitoring stopped. Check the log and summary files.")
        sys.exit(0)
    
    def generate_summary(self):
        """Generate comprehensive summary"""
        end_time = datetime.now()
        duration = end_time - self.start_time if self.start_time else "Unknown"
        
        # Create summary data
        summary = {
            'session_info': {
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': end_time.isoformat(),
                'duration_seconds': duration.total_seconds() if hasattr(duration, 'total_seconds') else 0,
                'total_packets': self.total_packets
            },
            'websites_visited': sorted(list(self.websites_visited)),
            'domains_resolved': sorted(list(self.domains_visited)),
            'ip_addresses': sorted(list(self.ip_addresses)),
            'dns_queries': sorted(list(self.dns_queries)),
            'http_requests': self.http_requests,
            'browser_connections': self.browser_connections,
            'all_connections': self.all_connections,
            'statistics': {
                'unique_websites': len(self.websites_visited),
                'unique_domains': len(self.domains_visited),
                'unique_ips': len(self.ip_addresses),
                'dns_queries_count': len(self.dns_queries),
                'http_requests_count': len(self.http_requests),
                'browser_connections_count': len(self.browser_connections),
                'total_connections': len(self.all_connections)
            }
        }
        
        # Save JSON summary
        with open(self.summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        # Generate text summary
        text_summary = self.generate_text_summary(summary)
        
        # Append to log
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write("\n\n" + "="*80 + "\n")
            f.write("FINAL SUMMARY\n")
            f.write("="*80 + "\n")
            f.write(text_summary)
        
        # Print to console
        print("\n" + "="*80)
        print("📊 ULTIMATE NETWORK TRAFFIC SUMMARY")
        print("="*80)
        print(text_summary)
        print(f"📁 Full log: {self.log_file}")
        print(f"📊 JSON summary: {self.summary_file}")
        print("="*80)
    
    def generate_text_summary(self, summary):
        """Generate readable text summary"""
        duration = summary['session_info']['duration_seconds']
        
        text = f"""
📅 Monitoring Duration: {duration:.1f} seconds ({duration/60:.1f} minutes)
📦 Total Network Activity: {summary['statistics']['total_connections']} connections
🌐 Browser Connections: {summary['statistics']['browser_connections_count']}
📡 HTTP Requests: {summary['statistics']['http_requests_count']}
🔍 DNS Queries: {summary['statistics']['dns_queries_count']}

🌐 WEBSITES VISITED ({len(summary['websites_visited'])}):
"""
        
        if summary['websites_visited']:
            for website in summary['websites_visited']:
                text += f"   ✅ {website}\n"
        else:
            text += "   ❌ No websites detected\n"
        
        if summary['dns_queries']:
            text += f"""
🔍 DNS QUERIES ({len(summary['dns_queries'])}):
"""
            for query in summary['dns_queries']:
                if not query.endswith('.in-addr.arpa'):
                    text += f"   🔍 {query}\n"
        
        if summary['browser_connections']:
            text += f"""
🌐 BROWSER CONNECTIONS ({len(summary['browser_connections'])}):
"""
            for conn in summary['browser_connections'][-20:]:  # Last 20
                domain = conn['domain'] if conn['domain'] else conn['remote_ip']
                text += f"   🌐 {conn['browser']} -> {domain} ({conn['protocol']})\n"
        
        if summary['http_requests']:
            text += f"""
📡 HTTP REQUESTS ({len(summary['http_requests'])}):
"""
            for req in summary['http_requests'][-15:]:  # Last 15
                text += f"   📡 {req['method']} {req['host']}{req['url']}\n"
        
        text += f"""
🌍 UNIQUE IP ADDRESSES ({len(summary['ip_addresses'])}):
"""
        for ip in summary['ip_addresses'][-30:]:  # Last 30
            text += f"   🌍 {ip}\n"
        
        return text

def main():
    """Main function"""
    print("🚀 Ultimate Network Traffic Monitor for Windows")
    print("📋 Comprehensive monitoring using multiple detection methods")
    print("🔍 Monitors: DNS queries, browser connections, HTTP requests, network connections")
    print("⚠️  Best results when running as Administrator")
    print()
    
    # Admin check
    try:
        import ctypes
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️  Note: Not running as Administrator")
            print("   Some deep packet inspection may be limited")
            print("   Browser and network monitoring will still work")
            print()
    except:
        pass
    
    # Create and start monitor
    monitor = UltimateNetworkMonitor()
    monitor.start_monitoring()

if __name__ == "__main__":
    main()
