from collections import Counter, defaultdict

def analyze_packets(packets):
    if not packets:
        return {}, {}, {}, {}, []

    protocol_counter = Counter()
    for pkt in packets:
        protocol_counter[pkt['protocol']] += 1

    data_by_src_ip = defaultdict(int)
    for pkt in packets:
        data_by_src_ip[pkt['src_ip']] += pkt['length']

    src_counter = Counter(pkt['src_ip'] for pkt in packets)
    dst_counter = Counter(pkt['dst_ip'] for pkt in packets)

    ddos_suspects = [ip for ip, count in src_counter.items() if count > 50]

    return dict(protocol_counter), dict(data_by_src_ip), src_counter.most_common(5), dst_counter.most_common(5), ddos_suspects
