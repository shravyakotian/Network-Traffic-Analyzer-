#!/usr/bin/env python3
"""
Advanced Network Traffic Monitor for Windows
Captures ALL network activity including browser traffic, encrypted connections, and system activity.
Uses multiple detection methods to ensure comprehensive monitoring.

Usage:
    python advanced_network_monitor.py

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
from collections import defaultdict, Counter
import json
import ipaddress

try:
    from scapy.all import *
    import psutil
except ImportError:
    print("Error: Missing required packages. Install with:")
    print("pip install scapy psutil")
    sys.exit(1)

# Windows-specific imports
if os.name == 'nt':
    try:
        import wmi
        WMI_AVAILABLE = True
    except ImportError:
        WMI_AVAILABLE = False
        print("Warning: WMI not available. Install with: pip install WMI")

class AdvancedNetworkMonitor:
    def __init__(self):
        self.running = False
        self.packets_captured = []
        self.start_time = None
        self.log_file = f"network_activity_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.summary_file = f"network_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Enhanced statistics
        self.total_packets = 0
        self.websites_visited = set()
        self.domains_visited = set()
        self.ip_addresses = set()
        self.protocols = Counter()
        self.dns_queries = set()
        self.http_requests = []
        self.https_connections = []
        self.process_connections = {}
        self.browser_activity = []
        
        # Domain/IP resolution cache
        self.ip_to_domain_cache = {}
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.stop_monitoring)
        
        # Initialize WMI for Windows process monitoring
        if os.name == 'nt' and WMI_AVAILABLE:
            try:
                self.wmi_conn = wmi.WMI()
            except:
                self.wmi_conn = None
        else:
            self.wmi_conn = None
    
    def get_domain_from_ip(self, ip):
        """Enhanced domain resolution with caching"""
        if ip in self.ip_to_domain_cache:
            return self.ip_to_domain_cache[ip]
        
        # Skip private/local IPs
        try:
            if ipaddress.ip_address(ip).is_private:
                return None
        except:
            pass
        
        try:
            domain = socket.gethostbyaddr(ip)[0]
            self.ip_to_domain_cache[ip] = domain
            return domain
        except:
            self.ip_to_domain_cache[ip] = None
            return None
    
    def get_process_info(self, src_ip, src_port, dst_ip, dst_port):
        """Get process information for network connections"""
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if (conn.laddr and conn.laddr.ip == src_ip and conn.laddr.port == src_port) or \
                   (conn.raddr and conn.raddr.ip == dst_ip and conn.raddr.port == dst_port):
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            return {
                                'pid': conn.pid,
                                'name': process.name(),
                                'exe': process.exe(),
                                'cmdline': ' '.join(process.cmdline())
                            }
                        except:
                            pass
        except:
            pass
        return None
    
    def monitor_browser_connections(self):
        """Monitor browser process connections"""
        browser_processes = ['chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe', 'safari.exe', 'iexplore.exe']
        
        while self.running:
            try:
                for proc in psutil.process_iter(['pid', 'name']):
                    if proc.info['name'] and proc.info['name'].lower() in browser_processes:
                        try:
                            connections = proc.connections()
                            for conn in connections:
                                if conn.status == 'ESTABLISHED' and conn.raddr:
                                    domain = self.get_domain_from_ip(conn.raddr.ip)
                                    
                                    connection_info = {
                                        'timestamp': datetime.now().isoformat(),
                                        'process': proc.info['name'],
                                        'pid': proc.info['pid'],
                                        'local_ip': conn.laddr.ip,
                                        'local_port': conn.laddr.port,
                                        'remote_ip': conn.raddr.ip,
                                        'remote_port': conn.raddr.port,
                                        'domain': domain,
                                        'status': conn.status
                                    }
                                    
                                    # Add to browser activity
                                    self.browser_activity.append(connection_info)
                                    
                                    # Add to websites if domain found
                                    if domain:
                                        self.websites_visited.add(domain)
                                        self.domains_visited.add(domain)
                                    
                                    self.ip_addresses.add(conn.raddr.ip)
                                    
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
                
                time.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                print(f"[ERROR] Browser monitoring error: {e}")
                time.sleep(5)
    
    def capture_dns_queries(self):
        """Capture DNS queries using multiple methods"""
        def dns_packet_handler(packet):
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                if dns_layer.qd:  # Query
                    try:
                        query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        if query_name and not query_name.endswith('.in-addr.arpa'):
                            self.dns_queries.add(query_name)
                            self.websites_visited.add(query_name)
                            print(f"[DNS] Query: {query_name}")
                    except:
                        pass
        
        # Start DNS packet capture
        threading.Thread(target=lambda: sniff(filter="udp port 53", prn=dns_packet_handler, store=False, stop_filter=lambda x: not self.running), daemon=True).start()
    
    def monitor_netstat_connections(self):
        """Monitor connections using netstat"""
        while self.running:
            try:
                # Run netstat command
                result = subprocess.run(['netstat', '-n'], capture_output=True, text=True, timeout=10)
                
                for line in result.stdout.split('\n'):
                    if 'ESTABLISHED' in line and ':80' in line or ':443' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            foreign_addr = parts[2]
                            if ':' in foreign_addr:
                                ip = foreign_addr.split(':')[0]
                                port = foreign_addr.split(':')[1]
                                
                                if port in ['80', '443']:
                                    domain = self.get_domain_from_ip(ip)
                                    if domain:
                                        self.websites_visited.add(domain)
                                        self.domains_visited.add(domain)
                                        print(f"[NETSTAT] Connection to {domain} ({ip}:{port})")
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                print(f"[ERROR] Netstat monitoring error: {e}")
                time.sleep(10)
    
    def process_packet(self, packet):
        """Enhanced packet processing"""
        try:
            packet_info = {
                'timestamp': datetime.now().isoformat(),
                'protocol': 'Unknown',
                'src_ip': 'N/A',
                'dst_ip': 'N/A',
                'src_port': 'N/A',
                'dst_port': 'N/A',
                'length': len(packet),
                'website_visited': 'N/A',
                'dns_query': 'N/A',
                'http_payload': 'N/A',
                'process_info': None,
                'is_browser_traffic': False
            }
            
            # Extract IP information
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                
                self.ip_addresses.add(packet[IP].src)
                self.ip_addresses.add(packet[IP].dst)
                
                # Try to resolve domains
                src_domain = self.get_domain_from_ip(packet[IP].src)
                dst_domain = self.get_domain_from_ip(packet[IP].dst)
                
                if src_domain:
                    self.domains_visited.add(src_domain)
                if dst_domain:
                    self.domains_visited.add(dst_domain)
                
                # Process TCP packets
                if TCP in packet:
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    
                    # Get process information
                    process_info = self.get_process_info(packet[IP].src, packet[TCP].sport, 
                                                       packet[IP].dst, packet[TCP].dport)
                    if process_info:
                        packet_info['process_info'] = process_info
                        # Check if it's browser traffic
                        if process_info['name'].lower() in ['chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe']:
                            packet_info['is_browser_traffic'] = True
                    
                    # Protocol detection
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        packet_info['protocol'] = 'HTTP'
                    elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        packet_info['protocol'] = 'HTTPS'
                        # For HTTPS, use the destination domain
                        if dst_domain:
                            packet_info['website_visited'] = dst_domain
                            self.websites_visited.add(dst_domain)
                    elif packet[TCP].dport == 53 or packet[TCP].sport == 53:
                        packet_info['protocol'] = 'DNS_TCP'
                    else:
                        packet_info['protocol'] = 'TCP'
                    
                    # Extract HTTP payload
                    if packet.haslayer(Raw):
                        try:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            
                            # HTTP request detection
                            if any(method in payload for method in ['GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ']):
                                packet_info['protocol'] = 'HTTP'
                                
                                # Extract Host header
                                lines = payload.split('\n')
                                for line in lines:
                                    if line.lower().startswith('host:'):
                                        host = line.split(':', 1)[1].strip()
                                        packet_info['website_visited'] = host
                                        self.websites_visited.add(host)
                                        break
                                
                                # Extract request line
                                if lines:
                                    request_line = lines[0].strip()
                                    packet_info['http_payload'] = request_line
                                    self.http_requests.append({
                                        'timestamp': packet_info['timestamp'],
                                        'request': request_line,
                                        'host': packet_info['website_visited']
                                    })
                                    
                                    print(f"[HTTP] {request_line} -> {packet_info['website_visited']}")
                            
                            elif payload.startswith('HTTP/'):
                                packet_info['protocol'] = 'HTTP_RESPONSE'
                                packet_info['http_payload'] = payload.split('\n')[0].strip()
                                
                        except:
                            pass
                
                # Process UDP packets
                elif UDP in packet:
                    packet_info['src_port'] = packet[UDP].sport
                    packet_info['dst_port'] = packet[UDP].dport
                    
                    if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                        packet_info['protocol'] = 'DNS'
                    else:
                        packet_info['protocol'] = 'UDP'
                
                # Process ICMP packets
                elif ICMP in packet:
                    packet_info['protocol'] = 'ICMP'
                else:
                    packet_info['protocol'] = 'IP'
            
            # Process ARP packets
            elif ARP in packet:
                packet_info['protocol'] = 'ARP'
                packet_info['src_ip'] = packet[ARP].psrc
                packet_info['dst_ip'] = packet[ARP].pdst
            
            # Process DNS packets
            if DNS in packet:
                packet_info['protocol'] = 'DNS'
                dns_layer = packet[DNS]
                if dns_layer.qd:
                    try:
                        query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        packet_info['dns_query'] = query_name
                        if not query_name.endswith('.in-addr.arpa'):
                            packet_info['website_visited'] = query_name
                            self.dns_queries.add(query_name)
                            self.websites_visited.add(query_name)
                            print(f"[DNS] Query: {query_name}")
                    except:
                        pass
            
            # Update statistics
            self.protocols[packet_info['protocol']] += 1
            self.total_packets += 1
            
            # Store packet info
            self.packets_captured.append(packet_info)
            
            # Log important packets
            if (packet_info['website_visited'] != 'N/A' or 
                packet_info['is_browser_traffic'] or 
                packet_info['protocol'] in ['HTTP', 'HTTPS', 'DNS']):
                self.log_packet(packet_info)
            
            # Print progress
            if self.total_packets % 500 == 0:
                print(f"[INFO] Captured {self.total_packets} packets, {len(self.websites_visited)} websites detected")
                
        except Exception as e:
            print(f"[ERROR] Error processing packet: {e}")
    
    def log_packet(self, packet_info):
        """Enhanced packet logging"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                browser_flag = "[BROWSER]" if packet_info['is_browser_traffic'] else ""
                process_info = f"[{packet_info['process_info']['name']}]" if packet_info['process_info'] else ""
                
                log_entry = (
                    f"[{packet_info['timestamp']}] {browser_flag} {process_info} "
                    f"{packet_info['protocol']} | "
                    f"{packet_info['src_ip']}:{packet_info['src_port']} -> "
                    f"{packet_info['dst_ip']}:{packet_info['dst_port']} | "
                    f"Website: {packet_info['website_visited']} | "
                    f"DNS: {packet_info['dns_query']} | "
                    f"Size: {packet_info['length']} bytes"
                )
                f.write(log_entry + "\n")
        except Exception as e:
            print(f"[ERROR] Failed to write to log: {e}")
    
    def start_monitoring(self):
        """Start comprehensive monitoring"""
        print("="*80)
        print("🚀 ADVANCED NETWORK TRAFFIC MONITOR STARTED")
        print("="*80)
        print(f"📁 Log file: {self.log_file}")
        print(f"📊 Summary file: {self.summary_file}")
        print("⏹️  Press Ctrl+C to stop monitoring and generate summary")
        print("="*80)
        
        self.running = True
        self.start_time = datetime.now()
        
        # Initialize log file
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write(f"Advanced Network Traffic Monitor Log - Started at {self.start_time.isoformat()}\n")
            f.write("="*80 + "\n\n")
        
        # Start browser monitoring thread
        threading.Thread(target=self.monitor_browser_connections, daemon=True).start()
        
        # Start DNS monitoring
        self.capture_dns_queries()
        
        # Start netstat monitoring
        threading.Thread(target=self.monitor_netstat_connections, daemon=True).start()
        
        print("🔍 Starting comprehensive packet capture...")
        print("📱 Monitoring browser connections...")
        print("🔍 Monitoring DNS queries...")
        print("🌐 Monitoring network connections...")
        print()
        
        try:
            # Main packet capture
            sniff(prn=self.process_packet, store=False, stop_filter=lambda x: not self.running)
            
        except Exception as e:
            print(f"[ERROR] Packet capture failed: {e}")
            print("💡 Try running as Administrator")
    
    def stop_monitoring(self, signum=None, frame=None):
        """Stop monitoring and generate summary"""
        print("\n\n🛑 Stopping network monitoring...")
        self.running = False
        
        # Wait for threads to finish
        time.sleep(2)
        
        self.generate_summary()
        
        print("\n✅ Monitoring stopped. Check the log and summary files.")
        sys.exit(0)
    
    def generate_summary(self):
        """Generate comprehensive summary"""
        end_time = datetime.now()
        duration = end_time - self.start_time if self.start_time else "Unknown"
        
        # Create summary data
        summary = {
            'monitoring_session': {
                'start_time': self.start_time.isoformat() if self.start_time else None,
                'end_time': end_time.isoformat(),
                'duration_seconds': duration.total_seconds() if hasattr(duration, 'total_seconds') else 0,
                'total_packets_captured': self.total_packets
            },
            'websites_visited': sorted(list(self.websites_visited)),
            'domains_resolved': sorted(list(self.domains_visited)),
            'ip_addresses_seen': sorted(list(self.ip_addresses)),
            'dns_queries': sorted(list(self.dns_queries)),
            'protocol_distribution': dict(self.protocols),
            'http_requests': self.http_requests,
            'browser_activity': self.browser_activity,
            'https_connections': self.https_connections,
            'top_websites': self.get_top_websites(),
            'statistics': {
                'unique_websites': len(self.websites_visited),
                'unique_domains': len(self.domains_visited),
                'unique_ips': len(self.ip_addresses),
                'dns_queries_count': len(self.dns_queries),
                'http_requests_count': len(self.http_requests),
                'browser_connections': len(self.browser_activity)
            }
        }
        
        # Save JSON summary
        with open(self.summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        
        # Generate text summary
        text_summary = self.generate_text_summary(summary)
        
        # Append summary to log file
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write("\n\n" + "="*80 + "\n")
            f.write("COMPREHENSIVE MONITORING SESSION SUMMARY\n")
            f.write("="*80 + "\n")
            f.write(text_summary)
        
        # Print summary to console
        print("\n" + "="*80)
        print("📊 COMPREHENSIVE NETWORK TRAFFIC SUMMARY")
        print("="*80)
        print(text_summary)
        print(f"📁 Full log saved to: {self.log_file}")
        print(f"📊 JSON summary saved to: {self.summary_file}")
        print("="*80)
    
    def get_top_websites(self):
        """Get most frequently visited websites"""
        website_counts = Counter()
        
        # Count from packets
        for packet in self.packets_captured:
            website = packet.get('website_visited', 'N/A')
            if website != 'N/A':
                website_counts[website] += 1
        
        # Count from browser activity
        for activity in self.browser_activity:
            if activity['domain']:
                website_counts[activity['domain']] += 1
        
        return dict(website_counts.most_common(20))
    
    def generate_text_summary(self, summary):
        """Generate comprehensive text summary"""
        text = f"""
📅 Session Duration: {summary['monitoring_session']['duration_seconds']:.1f} seconds
📦 Total Packets Captured: {summary['monitoring_session']['total_packets_captured']}
🌐 Browser Connections Monitored: {summary['statistics']['browser_connections']}

🌐 WEBSITES VISITED ({len(summary['websites_visited'])}):
"""
        
        if summary['websites_visited']:
            for website in summary['websites_visited'][:30]:  # Show top 30
                text += f"   • {website}\n"
            if len(summary['websites_visited']) > 30:
                text += f"   ... and {len(summary['websites_visited']) - 30} more\n"
        else:
            text += "   (No websites detected)\n"
        
        text += f"""
🔍 DNS QUERIES ({len(summary['dns_queries'])}):
"""
        
        if summary['dns_queries']:
            for query in summary['dns_queries'][:30]:
                if not query.endswith('.in-addr.arpa'):
                    text += f"   • {query}\n"
        else:
            text += "   (No DNS queries detected)\n"
        
        text += f"""
🌍 IP ADDRESSES CONTACTED ({len(summary['ip_addresses_seen'])}):
"""
        
        for ip in summary['ip_addresses_seen'][:30]:
            text += f"   • {ip}\n"
        
        text += f"""
📡 PROTOCOL DISTRIBUTION:
"""
        
        for protocol, count in sorted(summary['protocol_distribution'].items(), key=lambda x: x[1], reverse=True):
            text += f"   • {protocol}: {count} packets\n"
        
        if summary['browser_activity']:
            text += f"""
🌐 BROWSER CONNECTIONS ({len(summary['browser_activity'])}):
"""
            for activity in summary['browser_activity'][:20]:
                browser = activity['process']
                domain = activity['domain'] if activity['domain'] else activity['remote_ip']
                text += f"   • {browser}: {domain}\n"
        
        if summary['http_requests']:
            text += f"""
🔗 HTTP REQUESTS ({len(summary['http_requests'])}):
"""
            for req in summary['http_requests'][:15]:
                text += f"   • {req['request']} -> {req['host']}\n"
        
        if summary['top_websites']:
            text += f"""
🏆 TOP WEBSITES (by activity):
"""
            for website, count in list(summary['top_websites'].items())[:15]:
                text += f"   • {website}: {count} connections\n"
        
        return text

def main():
    """Main function"""
    print("🚀 Advanced Network Traffic Monitor for Windows")
    print("📋 This tool uses multiple methods to capture ALL network activity")
    print("🔍 Including browser traffic, DNS queries, and system connections")
    print("⚠️  Make sure you're running as Administrator")
    print()
    
    # Check if running as admin
    try:
        import ctypes
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️  WARNING: Not running as Administrator!")
            print("   Some traffic may not be captured. Please run as Administrator.")
            print()
    except:
        pass
    
    # Create monitor instance
    monitor = AdvancedNetworkMonitor()
    
    # Start monitoring
    monitor.start_monitoring()

if __name__ == "__main__":
    main()
