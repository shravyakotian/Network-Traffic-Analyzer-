from packet_sniffer import start_sniffing
from analyzer import analyze_packets

def display_packets(packets):
    print("\nCaptured Packets:\n")
    print("{:<20} {:<15} {:<15} {:<10} {:<6}".format("Timestamp", "Source IP", "Destination IP", "Protocol", "Size"))
    print("-" * 70)

    for pkt in packets:
        print("{:<20} {:<15} {:<15} {:<10} {:<6}".format(
            pkt['timestamp'], pkt['src_ip'], pkt['dst_ip'], pkt['protocol'], pkt['length']
        ))

if __name__ == "__main__":
    packets = start_sniffing(packet_count=1000)
    display_packets(packets)
    analyze_packets(packets)
