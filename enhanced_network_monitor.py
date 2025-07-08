
#!/usr/bin/env python3

"""
Enhanced Network Traffic Monitor for Windows
Optimized for capturing modern browser traffic including QUIC/HTTP3.
Uses advanced techniques to detect all network activity.

Usage:
    python enhanced_network_monitor.py

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
import json
import re
import ipaddress
import logging
import csv
from fpdf import FPDF

import argparse
from datetime import datetime
from collections import Counter, defaultdict
from typing import Dict, Set, List, Optional

from scapy.layers.dns import DNS
from scapy.layers.inet import UDP, IP, TCP



try:
    from scapy.all import *
    import psutil
    import requests
    import concurrent.futures
except ImportError:
    print("Error: Missing required packages. Install with:")
    print("pip install scapy psutil requests")
    sys.exit(1)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)



def remove_emojis(text):
    return re.sub(r'[^\x00-\x7F]+', '', text)


class EnhancedNetworkMonitor:
    def __init__(self):
        self.total_bytes = 0
        self.protocol_bytes = Counter()
        self.ip_traffic_bytes = defaultdict(int)  # NEW: track bytes per IP

        self.running = False
        self.start_time = None
        self.log_file = f"enhanced_network_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        self.summary_file = f"enhanced_network_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.CSV_file = f"enhanced_network_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        self.PDF_file = f"enhanced_network_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

        # Tracking data structures
        self.websites_visited = set()
        self.domains_visited = set()
        self.ip_addresses = set()
        self.dns_queries = set()
        self.http_requests = []
        self.browser_connections = []
        self.quic_connections = []
        self.all_connections = []
        self.protocol_stats = Counter()

        # Connection tracking to avoid duplicates
        self.seen_connections = set()
        self.connection_lock = threading.Lock()

        # Domain resolution cache with TTL
        self.domain_cache = {}
        self.cache_timestamps = {}
        self.cache_ttl = 300  # 5 minutes

        # Network interface info
        self.interfaces = []
        self.get_network_interfaces()

        # Browser process patterns
        self.browser_patterns = {
            'chrome.exe': ['chrome', 'chromium'],
            'msedge.exe': ['edge', 'msedge'],
            'firefox.exe': ['firefox'],
            'opera.exe': ['opera'],
            'brave.exe': ['brave'],
            'iexplore.exe': ['iexplore'],
            'safari.exe': ['safari']
        }

        # Setup signal handler (only if in main thread)
        if threading.current_thread() == threading.main_thread():
            signal.signal(signal.SIGINT, self.stop_monitoring)
        else:
            print("⚠️ Not in main thread — skipping signal handler setup")

        print("🚀 Enhanced Network Traffic Monitor Initialized")
        print(f"📁 Log file: {self.log_file}")
        print(f"📊 Summary file: {self.summary_file}")

    def get_snapshot(self):
        """
        Return a lightweight current snapshot of stats,
        without stopping the monitor or writing files.
        """
        return {
            'websites_visited': list(self.websites_visited),
            'domains_resolved': list(self.domains_visited),
            'ip_addresses': list(self.ip_addresses),
            'dns_queries': list(self.dns_queries),
            'total_bytes': self.total_bytes,
            'protocol_stats': dict(self.protocol_stats),
            'active_connections': len(self.all_connections),
            'browser_connections': len(self.browser_connections),
            'quic_connections': len(self.quic_connections),
        }

    def export_csv(self, summary):
        csv_file = self.summary_file.replace('.json', '.csv')
        with open(csv_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Timestamp', 'Process/Browser', 'Remote IP', 'Remote Port', 'Protocol', 'Domain'])

            for conn in summary['connections']['all_connections']:
                writer.writerow([
                    conn.get('timestamp'),
                    conn.get('process', conn.get('browser', 'Unknown')),
                    conn.get('remote_ip'),
                    conn.get('remote_port'),
                    conn.get('protocol'),
                    conn.get('domain')
                ])
        print(f"📄 CSV summary saved to: {csv_file}")

    def export_pdf(self, text_summary):
        pdf_file = self.summary_file.replace('.json', '.pdf')
        pdf = FPDF()
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.set_font("Arial", size=10)

        for line in text_summary.strip().split('\n'):
            pdf.multi_cell(0, 10, line)
        pdf.output(pdf_file)
        print(f"📄 PDF summary saved to: {pdf_file}")

    def get_network_interfaces(self):
        """Get available network interfaces"""
        try:
            from scapy.all import get_if_list
            self.interfaces = get_if_list()
            logger.info(f"Available network interfaces: {self.interfaces}")
        except Exception as e:
            logger.error(f"Error getting network interfaces: {e}")
            self.interfaces = []

    def resolve_ip_to_domain(self, ip: str) -> Optional[str]:
        """Resolve IP to domain with caching and TTL"""
        if not ip:
            return None

        # Check cache first
        if ip in self.domain_cache:
            cache_time = self.cache_timestamps.get(ip, 0)
            if time.time() - cache_time < self.cache_ttl:
                return self.domain_cache[ip]

        # Skip local IPs
        try:
            if ipaddress.ip_address(ip).is_private:
                return None
        except:
            pass

        # Resolve with timeout
        try:
            domain = socket.gethostbyaddr(ip)[0]
            self.domain_cache[ip] = domain
            self.cache_timestamps[ip] = time.time()
            return domain
        except:
            # Cache negative result
            self.domain_cache[ip] = None
            self.cache_timestamps[ip] = time.time()
            return None

    def log_activity(self, activity_type: str, message: str):
        """Log activity to file and console"""
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{activity_type}] {message}"

        # Print to console
        print(log_entry)

        # Write to log file
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry + "\n")
        except Exception as e:
            logger.error(f"Error writing to log file: {e}")

    def is_browser_process(self, process_name: str) -> bool:
        """Check if a process is a browser"""
        if not process_name:
            return False

        process_name = process_name.lower()
        for browser_exe, patterns in self.browser_patterns.items():
            if process_name == browser_exe.lower():
                return True
            for pattern in patterns:
                if pattern in process_name:
                    return True
        return False

    def monitor_dns_queries(self):
        """Monitor DNS queries on all interfaces"""

        def dns_handler(packet):
            try:
                if packet.haslayer(DNS):
                    self.total_bytes += len(packet)
                    self.protocol_bytes['DNS'] += len(packet)

                    # NEW: count per-IP bytes
                    if packet.haslayer(IP):  # NEW
                        remote_ip = packet[IP].dst  # NEW
                        self.ip_traffic_bytes[remote_ip] += len(packet)  # NEW

                    dns_layer = packet[DNS]
                    if dns_layer.qd:  # DNS Query
                        query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                        if query_name and not query_name.endswith('.in-addr.arpa'):
                            self.dns_queries.add(query_name)
                            self.websites_visited.add(query_name)
                            self.log_activity("DNS", f"Query: {query_name}")

                    # Also check DNS responses for additional domains
                    if dns_layer.an:  # DNS Answer
                        for i in range(dns_layer.ancount):
                            try:
                                answer = dns_layer.an[i]
                                if hasattr(answer, 'rrname'):
                                    domain = answer.rrname.decode('utf-8', errors='ignore').rstrip('.')
                                    if domain and not domain.endswith('.in-addr.arpa'):
                                        self.domains_visited.add(domain)
                            except:
                                pass
            except Exception as e:
                logger.debug(f"DNS handler error: {e}")

        # Start DNS monitoring
        try:
            threading.Thread(target=lambda: sniff(
                filter="udp port 53",
                prn=dns_handler,
                store=False,
                stop_filter=lambda x: not self.running
            ), daemon=True).start()
            logger.info("DNS monitoring started")
        except Exception as e:
            logger.error(f"DNS monitoring setup error: {e}")

    def monitor_browser_processes(self):
        """Monitor browser processes and their connections"""
        logger.info("Starting browser process monitoring...")

        while self.running:
            try:
                # Get all processes
                processes = list(psutil.process_iter(['pid', 'name', 'create_time']))

                for proc in processes:
                    try:
                        proc_name = proc.info['name']
                        if not self.is_browser_process(proc_name):
                            continue

                        # Get process connections
                        connections = proc.connections()

                        for conn in connections:
                            if not conn.raddr:
                                continue

                            remote_ip = conn.raddr.ip
                            remote_port = conn.raddr.port

                            # Check for web-related traffic
                            is_web_traffic = (
                                    remote_port in [80, 443, 8080, 8443, 3000, 5000, 8000, 9000] or
                                    (conn.type == socket.SOCK_DGRAM and remote_port == 443) or  # QUIC
                                    self.resolve_ip_to_domain(remote_ip) is not None
                            )

                            if is_web_traffic:
                                # Determine protocol
                                if conn.type == socket.SOCK_DGRAM and remote_port == 443:
                                    protocol = "QUIC/HTTP3"
                                elif conn.type == socket.SOCK_DGRAM:
                                    protocol = "UDP"
                                elif remote_port == 443:
                                    protocol = "HTTPS"
                                elif remote_port == 80:
                                    protocol = "HTTP"
                                else:
                                    protocol = f"TCP/{remote_port}"

                                # Create connection identifier
                                conn_id = f"{proc_name}_{remote_ip}_{remote_port}_{protocol}"

                                with self.connection_lock:
                                    if conn_id not in self.seen_connections:
                                        self.seen_connections.add(conn_id)

                                        # Resolve domain
                                        domain = self.resolve_ip_to_domain(remote_ip)

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
                                        self.protocol_stats[protocol] += 1

                                        if domain:
                                            self.websites_visited.add(domain)
                                            self.domains_visited.add(domain)
                                            self.log_activity("BROWSER",
                                                              f"{proc_name} -> {domain} ({remote_ip}:{remote_port}) [{protocol}]")
                                        else:
                                            self.log_activity("BROWSER",
                                                              f"{proc_name} -> {remote_ip}:{remote_port} [{protocol}]")

                                        # Special handling for QUIC connections
                                        if protocol == "QUIC/HTTP3":
                                            self.quic_connections.append(connection_info)

                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue

                time.sleep(1)  # Check every second for better responsiveness

            except Exception as e:
                logger.error(f"Browser monitoring error: {e}")
                time.sleep(5)

    def monitor_network_connections(self):
        """Monitor all network connections"""
        logger.info("Starting network connection monitoring...")

        while self.running:
            try:
                # Get all network connections
                connections = psutil.net_connections()

                for conn in connections:
                    if not conn.raddr:
                        continue

                    remote_ip = conn.raddr.ip
                    remote_port = conn.raddr.port

                    # Check for interesting traffic
                    is_interesting = (
                            remote_port in [80, 443, 8080, 8443, 3000, 5000, 8000, 9000] or
                            (conn.type == socket.SOCK_DGRAM and remote_port == 443) or
                            (hasattr(conn, 'status') and conn.status == 'ESTABLISHED')
                    )

                    if is_interesting:
                        # Determine protocol
                        if conn.type == socket.SOCK_DGRAM and remote_port == 443:
                            protocol = "QUIC/HTTP3"
                        elif conn.type == socket.SOCK_DGRAM:
                            protocol = "UDP"
                        elif remote_port == 443:
                            protocol = "HTTPS"
                        elif remote_port == 80:
                            protocol = "HTTP"
                        else:
                            protocol = f"TCP/{remote_port}"

                        # Get process info
                        process_name = "Unknown"
                        if conn.pid:
                            try:
                                process = psutil.Process(conn.pid)
                                process_name = process.name()
                            except:
                                pass

                        # Create connection identifier
                        conn_id = f"{process_name}_{remote_ip}_{remote_port}_{protocol}"

                        with self.connection_lock:
                            if conn_id not in self.seen_connections:
                                self.seen_connections.add(conn_id)

                                # Resolve domain
                                domain = self.resolve_ip_to_domain(remote_ip)

                                connection_info = {
                                    'timestamp': datetime.now().isoformat(),
                                    'process': process_name,
                                    'pid': conn.pid,
                                    'local_ip': conn.laddr.ip if conn.laddr else None,
                                    'local_port': conn.laddr.port if conn.laddr else None,
                                    'remote_ip': remote_ip,
                                    'remote_port': remote_port,
                                    'protocol': protocol,
                                    'domain': domain,
                                    'status': getattr(conn, 'status', 'UDP'),
                                    'connection_type': 'TCP' if conn.type == socket.SOCK_STREAM else 'UDP'
                                }

                                self.all_connections.append(connection_info)
                                self.ip_addresses.add(remote_ip)
                                self.protocol_stats[protocol] += 1

                                if domain:
                                    self.websites_visited.add(domain)
                                    self.domains_visited.add(domain)
                                    self.log_activity("NETWORK",
                                                      f"{process_name} -> {domain} ({remote_ip}:{remote_port}) [{protocol}]")
                                else:
                                    self.log_activity("NETWORK",
                                                      f"{process_name} -> {remote_ip}:{remote_port} [{protocol}]")

                time.sleep(2)  # Check every 2 seconds

            except Exception as e:
                logger.error(f"Network monitoring error: {e}")
                time.sleep(10)

    def monitor_http_traffic(self):
        """Monitor HTTP traffic using packet capture"""

        def http_handler(packet):
            try:
                if packet.haslayer(TCP) and packet.haslayer(Raw):
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')

                    if packet.haslayer(IP):  # NEW
                        remote_ip = packet[IP].dst  # NEW
                        self.ip_traffic_bytes[remote_ip] += len(packet)  # NEW

                    # Check for HTTP requests
                    if any(method in payload for method in ['GET ', 'POST ', 'HEAD ', 'PUT ', 'DELETE ']):
                        self.total_bytes += len(packet)
                        self.protocol_bytes['HTTP'] += len(packet)

                        lines = payload.split('\n')
                        host = None
                        request_line = lines[0].strip() if lines else ''

                        # Extract Host header
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
                                'dst_ip': packet[IP].dst,
                                'src_port': packet[TCP].sport,
                                'dst_port': packet[TCP].dport
                            }

                            self.http_requests.append(http_request)
                            self.log_activity("HTTP", f"{http_request['method']} {host}{http_request['url']}")
            except Exception as e:
                logger.debug(f"HTTP handler error: {e}")

        # Start HTTP monitoring
        try:
            threading.Thread(target=lambda: sniff(
                filter="tcp port 80",
                prn=http_handler,
                store=False,
                stop_filter=lambda x: not self.running
            ), daemon=True).start()
            logger.info("HTTP traffic monitoring started")
        except Exception as e:
            logger.error(f"HTTP monitoring setup error: {e}")

    def monitor_quic_traffic(self):
        """Monitor QUIC traffic (HTTP/3) over UDP"""

        def quic_handler(packet):
            try:
                if packet.haslayer(UDP) and packet.haslayer(IP):
                    # QUIC typically uses UDP port 443
                    if packet[UDP].dport == 443 or packet[UDP].sport == 443:
                        self.total_bytes += len(packet)
                        self.protocol_bytes['QUIC/HTTP3'] += len(packet)

                        # NEW: Count per-IP traffic
                        remote_ip = packet[IP].dst
                        self.ip_traffic_bytes[remote_ip] += len(packet)

                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport

                        # Determine direction
                        if dst_port == 443:
                            target_ip = dst_ip
                            target_port = 443
                        else:
                            target_ip = src_ip
                            target_port = 443

                        # Check for QUIC packet characteristics
                        if packet.haslayer(Raw):
                            payload = packet[Raw].load
                            # Basic QUIC packet detection (first byte patterns)
                            if len(payload) > 0 and (payload[0] & 0x80):  # Long header packets
                                quic_id = f"QUIC_{target_ip}_{target_port}"

                                with self.connection_lock:
                                    if quic_id not in self.seen_connections:
                                        self.seen_connections.add(quic_id)

                                        domain = self.resolve_ip_to_domain(target_ip)

                                        quic_connection = {
                                            'timestamp': datetime.now().isoformat(),
                                            'src_ip': src_ip,
                                            'dst_ip': dst_ip,
                                            'src_port': src_port,
                                            'dst_port': dst_port,
                                            'remote_ip': target_ip,
                                            'remote_port': target_port,
                                            'protocol': 'QUIC/HTTP3',
                                            'domain': domain,
                                            'connection_type': 'UDP'
                                        }

                                        self.quic_connections.append(quic_connection)
                                        self.ip_addresses.add(target_ip)
                                        self.protocol_stats['QUIC/HTTP3'] += 1

                                        if domain:
                                            self.websites_visited.add(domain)
                                            self.domains_visited.add(domain)
                                            self.log_activity("QUIC",
                                                              f"HTTP/3 connection to {domain} ({target_ip}:443)")
                                        else:
                                            self.log_activity("QUIC", f"HTTP/3 connection to {target_ip}:443")
            except Exception as e:
                logger.debug(f"QUIC handler error: {e}")

        # Start QUIC monitoring
        try:
            threading.Thread(target=lambda: sniff(
                filter="udp port 443",
                prn=quic_handler,
                store=False,
                stop_filter=lambda x: not self.running
            ), daemon=True).start()
            logger.info("QUIC traffic monitoring started")
        except Exception as e:
            logger.error(f"QUIC monitoring setup error: {e}")

    def start_monitoring(self):
        """Start comprehensive monitoring"""
        print("=" * 80)
        print("🚀 ENHANCED NETWORK TRAFFIC MONITOR STARTED")
        print("=" * 80)
        print(f"📁 Log file: {self.log_file}")
        print(f"📊 Summary file: {self.summary_file}")
        print(f"🌐 Network interfaces: {len(self.interfaces)}")
        print("⏹️  Press Ctrl+C to stop monitoring and generate summary")
        print("=" * 80)

        self.running = True
        self.start_time = datetime.now()

        # Initialize log file
        with open(self.log_file, 'w', encoding='utf-8') as f:
            f.write(f"Enhanced Network Traffic Monitor - Started at {self.start_time.isoformat()}\n")
            f.write("=" * 80 + "\n\n")

        # Start all monitoring threads
        threads = []

        # DNS monitoring
        self.log_activity("SYSTEM", "Starting DNS monitoring...")
        self.monitor_dns_queries()

        # Browser process monitoring
        self.log_activity("SYSTEM", "Starting browser process monitoring...")
        t1 = threading.Thread(target=self.monitor_browser_processes, daemon=True)
        t1.start()
        threads.append(t1)

        # Network connection monitoring
        self.log_activity("SYSTEM", "Starting network connection monitoring...")
        t2 = threading.Thread(target=self.monitor_network_connections, daemon=True)
        t2.start()
        threads.append(t2)

        # HTTP traffic monitoring
        self.log_activity("SYSTEM", "Starting HTTP traffic monitoring...")
        self.monitor_http_traffic()

        # QUIC traffic monitoring
        self.log_activity("SYSTEM", "Starting QUIC/HTTP3 traffic monitoring...")
        self.monitor_quic_traffic()

        # Status update thread
        def status_update():
            while self.running:
                time.sleep(30)  # Every 30 seconds
                self.log_activity("STATUS",
                                  f"Websites: {len(self.websites_visited)}, "
                                  f"IPs: {len(self.ip_addresses)}, "
                                  f"DNS: {len(self.dns_queries)}, "
                                  f"Connections: {len(self.all_connections)}, "
                                  f"QUIC: {len(self.quic_connections)}"
                                  )

        t3 = threading.Thread(target=status_update, daemon=True)
        t3.start()
        threads.append(t3)

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
                'duration_minutes': duration.total_seconds() / 60 if hasattr(duration, 'total_seconds') else 0
            },
            'bandwidth': {
                'total_bytes': self.total_bytes,
                'total_kilobytes': self.total_bytes / 1024,
                'total_megabytes': self.total_bytes / (1024 * 1024),
                'protocol_bytes': dict(self.protocol_bytes),
                'per_ip_traffic': dict(self.ip_traffic_bytes)  # NEW
            },

            'detection_results': {
                'websites_visited': sorted(list(self.websites_visited)),
                'domains_resolved': sorted(list(self.domains_visited)),
                'ip_addresses': sorted(list(self.ip_addresses)),
                'dns_queries': sorted(list(self.dns_queries))
            },
            'connections': {
                'browser_connections': self.browser_connections,
                'quic_connections': self.quic_connections,
                'all_connections': self.all_connections,
                'http_requests': self.http_requests
            },
            'statistics': {
                'unique_websites': len(self.websites_visited),
                'unique_domains': len(self.domains_visited),
                'unique_ips': len(self.ip_addresses),
                'dns_queries_count': len(self.dns_queries),
                'browser_connections_count': len(self.browser_connections),
                'quic_connections_count': len(self.quic_connections),
                'total_connections': len(self.all_connections),
                'http_requests_count': len(self.http_requests),
                'protocol_distribution': dict(self.protocol_stats)
            },
            'system_info': {
                'network_interfaces': self.interfaces,
                'cache_size': len(self.domain_cache)
            }
        }

        # compute top talkers
        top_talkers = sorted(
            self.ip_traffic_bytes.items(),
            key=lambda x: x[1],
            reverse=True
        )[:10]  # top 10

        summary['statistics']['top_talkers'] = [
            {'ip': ip, 'bytes': bytes_} for ip, bytes_ in top_talkers
        ]


        # Save JSON summary
        with open(self.summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        # Generate and save text summary
        text_summary = self.generate_text_summary(summary)

        # Append to log
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write("\n\n" + "=" * 80 + "\n")
            f.write("FINAL SUMMARY\n")
            f.write("=" * 80 + "\n")
            f.write(text_summary)

        self.export_csv(summary)
        clean_summary = remove_emojis(text_summary)
        self.export_pdf(clean_summary)

        # Print to console
        print("\n" + "=" * 80)
        print("📊 ENHANCED NETWORK TRAFFIC SUMMARY")
        print("=" * 80)
        print(text_summary)
        print(f"📁 Full log: {self.log_file}")
        print(f"📊 JSON summary: {self.summary_file}")
        print(f"📊 CSV file: {self.CSV_file}")
        print(f"📊 PDF file: {self.PDF_file}")
        print("=" * 80)



    def generate_text_summary(self, summary):
        """Generate readable text summary"""
        stats = summary['statistics']
        session = summary['session_info']

        text = f"""
    📅 SESSION INFO:
       Duration: {session['duration_minutes']:.1f} minutes
       Websites detected: {stats['unique_websites']}
       Domains resolved: {stats['unique_domains']}
       IP addresses: {stats['unique_ips']}
       Total connections: {stats['total_connections']}
       Browser connections: {stats['browser_connections_count']}
       QUIC connections: {stats['quic_connections_count']}
       HTTP requests: {stats['http_requests_count']}
       DNS queries: {stats['dns_queries_count']}

    📊 PROTOCOL DISTRIBUTION:
    """

        for protocol, count in stats['protocol_distribution'].items():
            text += f"   {protocol}: {count} connections\n"

        text += f"""

    📦 BANDWIDTH USAGE:
       Total: {self.total_bytes / (1024 * 1024):.2f} MB
    """

        for proto, bytes_count in self.protocol_bytes.items():
            text += f"   {proto}: {bytes_count} bytes\n"

        text += f"""


    🌐 WEBSITES VISITED ({stats['unique_websites']}):
    """

        if summary['detection_results']['websites_visited']:
            for website in summary['detection_results']['websites_visited']:
                text += f"   ✅ {website}\n"
        else:
            text += "   ❌ No websites detected\n"

        # Show recent browser connections
        if summary['connections']['browser_connections']:
            text += f"""
    🌐 RECENT BROWSER CONNECTIONS:
    """
            for conn in summary['connections']['browser_connections'][-15:]:
                domain = conn['domain'] if conn['domain'] else conn['remote_ip']
                text += f"   🌐 {conn['browser']} -> {domain} ({conn['protocol']})\n"

        # Show QUIC connections if any
        if summary['connections']['quic_connections']:
            text += f"""
    ⚡ QUIC/HTTP3 CONNECTIONS ({len(summary['connections']['quic_connections'])}):
    """
            for conn in summary['connections']['quic_connections'][-10:]:
                domain = conn['domain'] if conn['domain'] else conn['remote_ip']
                text += f"   ⚡ {domain} ({conn['remote_ip']}:443)\n"

        # Show DNS queries
        if summary['detection_results']['dns_queries']:
            text += f"""
    🔍 DNS QUERIES ({len(summary['detection_results']['dns_queries'])}):
    """
            for query in summary['detection_results']['dns_queries'][-20:]:
                text += f"   🔍 {query}\n"

        # Add PER-IP TRAFFIC section
        text += f"""

    📈 PER-IP TRAFFIC:
    """
        if self.ip_traffic_bytes:
            for ip, bytes_count in sorted(self.ip_traffic_bytes.items(), key=lambda x: -x[1]):
                text += f"   {ip}: {bytes_count} bytes\n"
        else:
            text += "   ❌ No IP traffic recorded.\n"

        # Add TOP TALKERS section
        text += f"""

    👑 TOP TALKERS:
    """
        if stats.get('top_talkers'):
            for talker in stats['top_talkers']:
                text += f"   {talker['ip']}: {talker['bytes']} bytes\n"
        else:
            text += "   ❌ No data\n"

        return text


def main():
    print("🚀 Enhanced Network Traffic Monitor")
    print("⚡ Choose mode:")
    print("1️⃣ Terminal")
    print("2️⃣ Web UI (Streamlit)")
    choice = input("Enter choice [1/2]: ").strip()

    if choice == "1":
        monitor = EnhancedNetworkMonitor()
        monitor.start_monitoring()
    elif choice == "2":
        print("🌐 Launching Streamlit UI...")
        os.system("streamlit run ui_app.py")
    else:
        print("❌ Invalid choice.")


if __name__ == "__main__":
    main()





