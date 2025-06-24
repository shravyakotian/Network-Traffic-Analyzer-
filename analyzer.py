from collections import Counter, defaultdict
import pandas as pd

def analyze_packets(packets, save_to_file=False, filename="analysis_report.csv"):
    """
    Analyze captured packets and optionally save results to CSV.

    :param packets: List of captured packet data
    :param save_to_file: If True, saves analysis to CSV
    :param filename: CSV file name for saving results
    :return: Tuple of protocol stats, data volume, top sources/destinations, and DDoS suspects
    """
    if not packets:
        return {}, {}, [], [], []

    protocol_counter = Counter()
    data_by_src_ip = defaultdict(int)
    src_counter = Counter()
    dst_counter = Counter()

    for pkt in packets:
        protocol_counter[pkt['protocol']] += 1
        data_by_src_ip[pkt['src_ip']] += pkt['length']
        src_counter[pkt['src_ip']] += 1
        dst_counter[pkt['dst_ip']] += 1

    ddos_suspects = [ip for ip, count in src_counter.items() if count > 50]

    # Save to file if requested
    if save_to_file:
        with open(filename, "w") as f:
            f.write("Protocol Usage:\n")
            for proto, count in protocol_counter.items():
                f.write(f"{proto},{count}\n")

            f.write("\nData Volume by Source IP:\n")
            for ip, size in data_by_src_ip.items():
                f.write(f"{ip},{size}\n")

            f.write("\nTop Source IPs:\n")
            for ip, count in src_counter.most_common(5):
                f.write(f"{ip},{count}\n")

            f.write("\nTop Destination IPs:\n")
            for ip, count in dst_counter.most_common(5):
                f.write(f"{ip},{count}\n")

            f.write("\nPotential DDoS Suspects:\n")
            for ip in ddos_suspects:
                f.write(f"{ip}\n")

        print(f"[INFO] Analysis report saved to {filename}")

    return (
        dict(protocol_counter),
        dict(data_by_src_ip),
        src_counter.most_common(5),
        dst_counter.most_common(5),
        ddos_suspects
    )
