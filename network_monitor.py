#!/usr/bin/env python3
"""
Simple Network Traffic Monitor
Runs continuously in background, captures all network traffic,
saves to log file with website/domain summary.

Usage:
    python network_monitor.py

Press Ctrl+C to stop and generate summary.
"""

import os
import sys
import time
import socket
import signal
import threading
from datetime import datetime
from collections import defaultdict, Counter
import json

try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, Raw, ARP, ICMP, get_if_list
except ImportError:
    print("Error: Scapy not installed. Install with: pip install scapy")
    sys.exit(1)

class NetworkMonitor:
    def __init__(self):
        self.running = False
        self.packets_captured = []
        self.start_time = None
        self.log_file = f"network_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.summary_file = f"network_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Statistics
        self.total_packets = 0
        self.websites_visited = set()
        self.domains_visited = set()
        self.ip_addresses = set()
        self.protocols = Counter()
        self.dns_queries = set()
        self.http_requests = []
        
        # Setup signal handler for graceful shutdown
        signal.signal(signal.SIGINT, self.stop_monitoring)
        
    def extract_domain_from_ip(self, ip):
        """Try to resolve IP to domain name"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    def process_packet(self, packet):
        """Process each captured packet"""
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
                'http_payload': 'N/A'
            }
            
            # Extract basic IP information
            if IP in packet:
                packet_info['src_ip'] = packet[IP].src
                packet_info['dst_ip'] = packet[IP].dst
                
                # Add IPs to our tracking set
                self.ip_addresses.add(packet[IP].src)
                self.ip_addresses.add(packet[IP].dst)
                
                # Try to resolve domains for IPs
                src_domain = self.extract_domain_from_ip(packet[IP].src)
                dst_domain = self.extract_domain_from_ip(packet[IP].dst)
                
                if src_domain:
                    self.domains_visited.add(src_domain)
                if dst_domain:
                    self.domains_visited.add(dst_domain)
                
                # Process TCP packets
                if TCP in packet:
                    packet_info['src_port'] = packet[TCP].sport
                    packet_info['dst_port'] = packet[TCP].dport
                    
                    # Determine protocol based on port
                    if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                        packet_info['protocol'] = 'HTTP'
                    elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        packet_info['protocol'] = 'HTTPS'
                    elif packet[TCP].dport == 53 or packet[TCP].sport == 53:
                        packet_info['protocol'] = 'DNS_TCP'
                    else:
                        packet_info['protocol'] = 'TCP'
                    
                    # Extract HTTP data
                    if packet.haslayer(Raw):
                        try:
                            payload = packet[Raw].load.decode('utf-8', errors='ignore')
                            
                            # Check for HTTP requests
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
                            
                            elif payload.startswith('HTTP/'):
                                packet_info['protocol'] = 'HTTP_RESPONSE'
                                packet_info['http_payload'] = payload.split('\n')[0].strip()
                                
                        except Exception as e:
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
                        packet_info['website_visited'] = query_name
                        self.dns_queries.add(query_name)
                        
                        # Add to websites if it looks like a domain
                        if '.' in query_name and not query_name.endswith('.in-addr.arpa'):
                            self.websites_visited.add(query_name)
                    except:
                        pass
            
            # Update statistics
            self.protocols[packet_info['protocol']] += 1
            self.total_packets += 1
            
            # Store packet info
            self.packets_captured.append(packet_info)
            
            # Log packet (every 10th packet to avoid spam)
            if self.total_packets % 10 == 0:
                self.log_packet(packet_info)
            
            # Print progress every 100 packets
            if self.total_packets % 100 == 0:
                print(f"[INFO] Captured {self.total_packets} packets, {len(self.websites_visited)} websites detected")
                
        except Exception as e:
            print(f"[ERROR] Error processing packet: {e}")
    
    def log_packet(self, packet_info):
        """Log packet information to file"""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                log_entry = (
                    f"[{packet_info['timestamp']}] "
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
        """Start packet capture"""
        print("="*80)
        print("🚀 NETWORK TRAFFIC MONITOR STARTED")
        print("="*80)
        print(f"📁 Log file: {self.log_file}")
        print(f"📊 Summary file: {self.summary_file}")
        print("⏹️  Press Ctrl+C to stop monitoring and generate summary")
        print("="*80)
        
        self.running = True
        self.start_time = datetime.now()
        
        # Initialize log file
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write(f"Network Traffic Monitor Log - Started at {self.start_time.isoformat()}\n")
            f.write("="*80 + "\n\n")
        
        try:
            # Start packet capture
            print(f"🔍 Starting packet capture...")
            sniff(prn=self.process_packet, store=False, stop_filter=lambda x: not self.running)
            
        except Exception as e:
            print(f"[ERROR] Packet capture failed: {e}")
            print("💡 Try running as Administrator/sudo")
            
    def stop_monitoring(self, signum=None, frame=None):
        """Stop monitoring and generate summary"""
        print("\n\n🛑 Stopping network monitoring...")
        self.running = False
        
        # Wait a moment for any remaining packets
        time.sleep(1)
        
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
            'top_websites': self.get_top_websites(),
            'statistics': {
                'unique_websites': len(self.websites_visited),
                'unique_domains': len(self.domains_visited),
                'unique_ips': len(self.ip_addresses),
                'dns_queries_count': len(self.dns_queries),
                'http_requests_count': len(self.http_requests)
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
            f.write("MONITORING SESSION SUMMARY\n")
            f.write("="*80 + "\n")
            f.write(text_summary)
        
        # Print summary to console
        print("\n" + "="*80)
        print("📊 NETWORK TRAFFIC SUMMARY")
        print("="*80)
        print(text_summary)
        print(f"📁 Full log saved to: {self.log_file}")
        print(f"📊 JSON summary saved to: {self.summary_file}")
        print("="*80)
    
    def get_top_websites(self):
        """Get most frequently visited websites"""
        website_counts = Counter()
        for packet in self.packets_captured:
            website = packet.get('website_visited', 'N/A')
            if website != 'N/A':
                website_counts[website] += 1
        
        return dict(website_counts.most_common(20))
    
    def generate_text_summary(self, summary):
        """Generate human-readable text summary"""
        text = f"""
📅 Session Duration: {summary['monitoring_session']['duration_seconds']:.1f} seconds
📦 Total Packets Captured: {summary['monitoring_session']['total_packets_captured']}

🌐 WEBSITES VISITED ({len(summary['websites_visited'])}):
"""
        
        for website in summary['websites_visited'][:20]:  # Show top 20
            text += f"   • {website}\n"
        
        if len(summary['websites_visited']) > 20:
            text += f"   ... and {len(summary['websites_visited']) - 20} more\n"
        
        text += f"""
🔍 DNS QUERIES ({len(summary['dns_queries'])}):
"""
        
        for query in summary['dns_queries'][:20]:  # Show top 20
            if not query.endswith('.in-addr.arpa'):  # Skip reverse DNS
                text += f"   • {query}\n"
        
        text += f"""
🌍 IP ADDRESSES ({len(summary['ip_addresses_seen'])}):
"""
        
        for ip in summary['ip_addresses_seen'][:20]:  # Show top 20
            text += f"   • {ip}\n"
        
        text += f"""
📡 PROTOCOL DISTRIBUTION:
"""
        
        for protocol, count in sorted(summary['protocol_distribution'].items(), key=lambda x: x[1], reverse=True):
            text += f"   • {protocol}: {count} packets\n"
        
        if summary['http_requests']:
            text += f"""
🔗 HTTP REQUESTS ({len(summary['http_requests'])}):
"""
            for req in summary['http_requests'][:10]:  # Show top 10
                text += f"   • {req['request']} -> {req['host']}\n"
        
        if summary['top_websites']:
            text += f"""
🏆 TOP WEBSITES (by packet count):
"""
            for website, count in list(summary['top_websites'].items())[:10]:
                text += f"   • {website}: {count} packets\n"
        
        return text

def main():
    """Main function"""
    print("🚀 Network Traffic Monitor")
    print("📋 This tool will capture all network traffic and save to log files")
    print("⚠️  Make sure you're running as Administrator on Windows or with sudo on Linux")
    print()
    
    # Check if running as admin (Windows)
    try:
        import ctypes
        if os.name == 'nt' and not ctypes.windll.shell32.IsUserAnAdmin():
            print("⚠️  WARNING: Not running as Administrator. Some packets may not be captured.")
            print("   For best results, run as Administrator.")
            print()
    except:
        pass
    
    # Create monitor instance
    monitor = NetworkMonitor()
    
    # Start monitoring
    monitor.start_monitoring()

if __name__ == "__main__":
    main()
