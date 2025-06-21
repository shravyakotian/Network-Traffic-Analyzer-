from collections import Counter, defaultdict

def analyze_packets(packets):
    print("\n[INFO] Analyzing captured packets...\n")

    if not packets:
        print("[WARN] No packets to analyze.")
        return

    protocol_counter = Counter()
    for pkt in packets:
        protocol_counter[pkt['protocol']] += 1

    data_by_src_ip = defaultdict(int)
    for pkt in packets:
        data_by_src_ip[pkt['src_ip']] += pkt['length']

    src_counter = Counter(pkt['src_ip'] for pkt in packets)
    dst_counter = Counter(pkt['dst_ip'] for pkt in packets)

    ddos_suspects = [ip for ip, count in src_counter.items() if count > 50]

    print("Protocol Usage:")
    print("-" * 30)
    for proto, count in protocol_counter.most_common():
        print(f"{proto:<10}: {count} packets")

    print("\nData Volume by Source IP:")
    print("-" * 40)
    for ip, total_size in sorted(data_by_src_ip.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<15} → {total_size} bytes")

    print("\nTop Source IPs:")
    print("-" * 30)
    for ip, count in src_counter.most_common(5):
        print(f"{ip:<15}: {count} packets sent")

    print("\nTop Destination IPs:")
    print("-" * 30)
    for ip, count in dst_counter.most_common(5):
        print(f"{ip:<15}: {count} packets received")

    print("\nPotential DDoS Sources (threshold > 50 packets):")
    print("-" * 50)
    if ddos_suspects:
        for ip in ddos_suspects:
            print(f"Suspicious IP: {ip} → {src_counter[ip]} packets sent")
    else:
        print("No DDoS-like activity detected.")
