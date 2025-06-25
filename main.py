import os
from packet_sniffer import start_sniffing
from analyzer import analyze_packets
from exporter import auto_save_to_csv, save_analysis_to_csv
import pandas as pd


def run_terminal_mode():
    print("\n[INFO] Running in Terminal Mode...\n")

    # Enable live terminal output
    packets = start_sniffing(packet_count=1000, terminal_live=True)

    if not packets:
        print("No packets captured.")
        return

    print(f"\n[INFO] Total Packets Captured: {len(packets)}\n")

    auto_save_to_csv(packets)

    print("\n[INFO] Summary of Captured Packets:\n")
    for idx, pkt in enumerate(packets, 1):
        print(f"{idx}: {pkt}")

    proto_stats, data_by_src, top_src, top_dst, ddos_list = analyze_packets(packets)

    print("\n[INFO] Protocol Usage:")
    for proto, count in proto_stats.items():
        print(f"{proto}: {count}")

    print("\n[INFO] Data Volume by Source IP:")
    for ip, total in data_by_src.items():
        print(f"{ip}: {total} bytes")

    print("\n[INFO] Top Source IPs:")
    for ip, count in top_src:
        print(f"{ip}: {count} packets")

    print("\n[INFO] Top Destination IPs:")
    for ip, count in top_dst:
        print(f"{ip}: {count} packets")

    if ddos_list:
        print(f"\n[ALERT] Potential DDoS sources detected: {', '.join(ddos_list)}")
    else:
        print("\n[INFO] No DDoS-like activity detected.")

    save_analysis_to_csv(proto_stats, data_by_src, top_src, top_dst, ddos_list)
    print("\n[INFO] Packet data and analysis saved.\n")


def run_streamlit_app():
    print("\n[INFO] Launching Streamlit App in browser...\n")
    os.system("streamlit run app_ui.py")


if __name__ == "__main__":
    print("\n==============================")
    print("  Network Traffic Analyzer")
    print("==============================\n")
    print("1️⃣  Run in Terminal (Text Output with Live Capture)")
    print("2️⃣  Run as Web App (Browser)")

    choice = input("\nSelect Mode (1 or 2): ").strip()

    if choice == "1":
        run_terminal_mode()
    elif choice == "2":
        run_streamlit_app()
    else:
        print("\n Invalid Choice. Please run the program again.\n")
