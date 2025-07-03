#!/usr/bin/env python3
"""
Network Traffic Analyzer - Diagnostic Tool
This script helps diagnose packet capture issues on your system.
"""

import sys
import platform
import os
from datetime import datetime

def check_system_requirements():
    """Check if system meets requirements for packet capture"""
    print("=" * 50)
    print("SYSTEM DIAGNOSTIC REPORT")
    print("=" * 50)
    print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    print("1. SYSTEM INFORMATION")
    print("-" * 30)
    print(f"Operating System: {platform.system()} {platform.release()}")
    print(f"Python Version: {platform.python_version()}")
    print(f"Architecture: {platform.machine()}")
    
    # Check if running as administrator (Windows)
    if platform.system() == "Windows":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            print(f"Running as Administrator: {'Yes' if is_admin else 'No'}")
            if not is_admin:
                print("⚠️  WARNING: Running as Administrator is recommended for packet capture on Windows")
        except:
            print("Running as Administrator: Cannot determine")
    
    print()
    
    print("2. PYTHON PACKAGES")
    print("-" * 30)
    
    # Check Scapy
    try:
        import scapy
        print(f"✅ Scapy version: {scapy.__version__}")
    except ImportError:
        print("❌ Scapy not installed")
        return False
    
    # Check other required packages
    packages = ['streamlit', 'pandas', 'socket']
    for pkg in packages:
        try:
            __import__(pkg)
            print(f"✅ {pkg}: Available")
        except ImportError:
            print(f"❌ {pkg}: Not available")
    
    print()
    
    print("3. NETWORK INTERFACES")
    print("-" * 30)
    
    try:
        from scapy.all import get_if_list, conf
        interfaces = get_if_list()
        print(f"Available interfaces: {len(interfaces)}")
        print(f"Default interface: {conf.iface}")
        
        for i, iface in enumerate(interfaces):
            print(f"  {i+1}. {iface}")
        
        if not interfaces:
            print("❌ No network interfaces found")
            return False
        
    except Exception as e:
        print(f"❌ Error accessing network interfaces: {e}")
        return False
    
    print()
    
    print("4. PACKET CAPTURE TEST")
    print("-" * 30)
    
    try:
        from scapy.all import sniff, IP, TCP, UDP
        from scapy.layers.dns import DNS
        from scapy.layers.http import HTTP
        import re
        
        print("Testing packet capture for 15 seconds...")
        print("(Generate some network traffic by browsing websites)")
        print()
        
        # Store captured data
        captured_data = {
            'packets': [],
            'dns_queries': set(),
            'http_hosts': set(),
            'websites_visited': set()
        }
        
        def process_packet(pkt):
            try:
                captured_data['packets'].append(pkt)
                
                # Extract DNS queries
                if pkt.haslayer(DNS) and pkt[DNS].qd is not None:
                    try:
                        dns_query = pkt[DNS].qd.qname.decode('utf-8').rstrip('.')
                        if dns_query and not dns_query.startswith('_'):  # Skip service discovery
                            captured_data['dns_queries'].add(dns_query)
                            captured_data['websites_visited'].add(dns_query)
                    except:
                        pass
                
                # Extract HTTP Host headers
                if pkt.haslayer(TCP) and pkt[TCP].dport == 80:
                    try:
                        if hasattr(pkt, 'load'):
                            payload = pkt.load.decode('utf-8', errors='ignore')
                            host_match = re.search(r'Host: ([^\r\n]+)', payload)
                            if host_match:
                                host = host_match.group(1).strip()
                                captured_data['http_hosts'].add(host)
                                captured_data['websites_visited'].add(host)
                    except:
                        pass
                
                # Extract HTTPS SNI (Server Name Indication)
                if pkt.haslayer(TCP) and pkt[TCP].dport == 443:
                    try:
                        if hasattr(pkt, 'load') and pkt.load:
                            payload = pkt.load
                            # Look for SNI in TLS Client Hello
                            if b'\x16\x03' in payload[:3]:  # TLS handshake
                                # Simple SNI extraction (not perfect but works for many cases)
                                sni_match = re.search(rb'[\x00-\x1f]([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', payload)
                                if sni_match:
                                    sni = sni_match.group(1).decode('utf-8')
                                    if '.' in sni and len(sni) > 4:
                                        captured_data['websites_visited'].add(sni)
                    except:
                        pass
                        
            except Exception as e:
                pass
        
        packets = sniff(timeout=15, prn=process_packet, store=False)
        packet_count = len(captured_data['packets'])
        
        if packet_count > 0:
            print(f"✅ Successfully captured {packet_count} packets")
            
            # Show websites visited
            if captured_data['websites_visited']:
                print(f"\n🌐 Websites/Domains Detected ({len(captured_data['websites_visited'])}):")
                for site in sorted(captured_data['websites_visited']):
                    print(f"  • {site}")
            else:
                print("\n🌐 No websites/domains detected")
                print("   (Try visiting some websites during the test)")
            
            # Show DNS queries
            if captured_data['dns_queries']:
                print(f"\n🔍 DNS Queries ({len(captured_data['dns_queries'])}):")
                for query in sorted(captured_data['dns_queries']):
                    print(f"  • {query}")
            
            # Show HTTP hosts
            if captured_data['http_hosts']:
                print(f"\n🌍 HTTP Hosts ({len(captured_data['http_hosts'])}):")
                for host in sorted(captured_data['http_hosts']):
                    print(f"  • {host}")
            
            # Analyze packet types
            print(f"\n📊 Packet Analysis:")
            protocols = {}
            for pkt in captured_data['packets']:
                if pkt.haslayer(IP):
                    if pkt.haslayer(TCP):
                        port = pkt[TCP].dport
                        if port == 80:
                            proto = "HTTP"
                        elif port == 443:
                            proto = "HTTPS"
                        elif port == 53:
                            proto = "DNS"
                        else:
                            proto = f"TCP:{port}"
                    elif pkt.haslayer(UDP):
                        port = pkt[UDP].dport
                        if port == 53:
                            proto = "DNS"
                        else:
                            proto = f"UDP:{port}"
                    else:
                        proto = "Other-IP"
                else:
                    proto = "Non-IP"
                
                protocols[proto] = protocols.get(proto, 0) + 1
            
            print("Protocol distribution:")
            for proto, count in sorted(protocols.items(), key=lambda x: x[1], reverse=True):
                print(f"  {proto}: {count}")
                
        else:
            print("❌ No packets captured")
            print("Possible issues:")
            print("  - No network traffic during test")
            print("  - Insufficient permissions")
            print("  - Firewall blocking packet capture")
            print("  - Missing WinPcap/Npcap (Windows)")
            return False
            
    except Exception as e:
        print(f"❌ Packet capture test failed: {e}")
        return False
    
    print()
    
    print("5. WINDOWS-SPECIFIC CHECKS")
    print("-" * 30)
    
    if platform.system() == "Windows":
        print("Windows packet capture requirements:")
        print("  - WinPcap or Npcap must be installed")
        print("  - Windows Defender real-time protection may interfere")
        print("  - Corporate firewalls may block packet capture")
        print("  - Some VPN software may interfere")
        
        # Check for common packet capture software
        try:
            import winreg
            # Check for Npcap
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap")
                winreg.CloseKey(key)
                print("✅ Npcap appears to be installed")
            except FileNotFoundError:
                print("❌ Npcap not found in registry")
        except:
            print("Cannot check for Npcap installation")
    
    print()
    
    print("6. RECOMMENDATIONS")
    print("-" * 30)
    
    recommendations = [
        "✅ System appears ready for packet capture",
        "Generate network traffic during monitoring (browse websites, etc.)",
        "Check selected fields in the application sidebar",
        "Monitor the packet count statistics in the app"
    ]
    
    if platform.system() == "Windows":
        recommendations.extend([
            "Run the application as Administrator",
            "Install Npcap if not already installed (https://nmap.org/npcap/)",
            "Temporarily disable Windows Defender real-time protection for testing",
            "Check Windows Firewall settings"
        ])
    
    for rec in recommendations:
        print(f"  {rec}")
    
    return True

if __name__ == "__main__":
    try:
        success = check_system_requirements()
        if success:
            print("\n✅ System diagnostic completed successfully!")
        else:
            print("\n❌ System diagnostic found issues that need to be resolved.")
    except KeyboardInterrupt:
        print("\n\nDiagnostic interrupted by user.")
    except Exception as e:
        print(f"\n❌ Unexpected error during diagnostic: {e}")
