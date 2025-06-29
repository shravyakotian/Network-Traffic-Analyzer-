import os
import time
from datetime import datetime, timedelta
from packet_sniffer import continuous_sniffing, continuous_packets, _lock, stop_sniffing
from analyzer import analyze_packets
from exporter import auto_save_to_csv, save_analysis_to_csv
import pandas as pd


def filter_by_time(packets, time_range):
    """
    Filters captured packets based on selected time range.
    """
    if time_range == "All":
        return packets

    cutoff = datetime.now()
    if time_range == "Last 5 Minutes":
        cutoff -= timedelta(minutes=5)
    elif time_range == "Last 30 Minutes":
        cutoff -= timedelta(minutes=30)
    elif time_range == "Last 1 Hour":
        cutoff -= timedelta(hours=1)

    return [pkt for pkt in packets if datetime.strptime(pkt['timestamp'], "%Y-%m-%d %H:%M:%S") >= cutoff]


def run_terminal_mode():
    """
    Runs packet capture and analysis in terminal mode with real-time statistics.
    """
    print("\n===============================")
    print("      Terminal Packet Capture")
    print("===============================\n")

    try:
        refresh_interval = float(input("Enter dashboard refresh interval in seconds (default 1s): ").strip())
        if refresh_interval <= 0:
            raise ValueError
    except ValueError:
        refresh_interval = 1
        print("[INFO] Invalid input, using default 1 second.")

    print("\nDisplay Packets for:")
    print("1️⃣ Last 5 Minutes")
    print("2️⃣ Last 30 Minutes")
    print("3️⃣ Last 1 Hour")
    print("4️⃣ All")

    choice = input("Select option (1/2/3/4): ").strip()
    time_option = "All"
    if choice == "1":
        time_option = "Last 5 Minutes"
    elif choice == "2":
        time_option = "Last 30 Minutes"
    elif choice == "3":
        time_option = "Last 1 Hour"

    continuous_sniffing(terminal_live=True)

    try:
        prev_count = 0
        while True:
            time.sleep(refresh_interval)

            with _lock:
                snapshot = continuous_packets.copy()

            filtered_snapshot = filter_by_time(snapshot, time_option)

            if len(filtered_snapshot) > prev_count:
                print(f"\n✅ Total Packets Captured (Filtered): {len(filtered_snapshot)}")

                print("\n📥 Latest Packets:\n")
                for idx, pkt in enumerate(filtered_snapshot[-5:], len(filtered_snapshot) - 4):
                    print(f"{idx}. [{pkt['protocol']}] {pkt['src_ip']}:{pkt['src_port']} → {pkt['dst_ip']}:{pkt['dst_port']} | "
                          f"MAC: {pkt['src_mac']} → {pkt['dst_mac']} | Size: {pkt['length']} bytes")

                print("\n📊 Live Packet Analysis:\n")
                proto_stats, data_by_src, top_src, top_dst, ddos_list = analyze_packets(filtered_snapshot)

                print("🔹 Protocol Usage:")
                for proto, count in proto_stats.items():
                    print(f"- {proto}: {count} packets")

                print("\n🔹 Data Volume by Source IP:")
                for ip, total in data_by_src.items():
                    print(f"- {ip}: {total} bytes")

                print("\n🔹 Top 3 Source IPs:")
                for ip, count in top_src[:3]:
                    print(f"- {ip}: {count} packets")

                print("\n🔹 Top 3 Destination IPs:")
                for ip, count in top_dst[:3]:
                    print(f"- {ip}: {count} packets")

                print("\n🚨 Potential DDoS Sources:")
                if ddos_list:
                    for ip in ddos_list:
                        print(f"- ⚠️ {ip}")
                else:
                    print("- No DDoS-like activity detected.")

                prev_count = len(filtered_snapshot)

    except KeyboardInterrupt:
        print("\n[INFO] Capture stopped by user.\n")
        stop_sniffing()

        with _lock:
            final_data = continuous_packets.copy()

        print(f"\n✅ Final Packet Count: {len(final_data)}")
        auto_save_to_csv(final_data)

        proto_stats, data_by_src, top_src, top_dst, ddos_list = analyze_packets(final_data)
        save_analysis_to_csv(proto_stats, data_by_src, top_src, top_dst, ddos_list)
        print("\n💾 Final packet data and analysis saved to CSV.\n")


def run_streamlit_app():
    """
    Launches the Streamlit web interface.
    """
    print("\n[INFO] Launching Streamlit App in browser...\n")
    os.system("streamlit run app_ui.py")


if __name__ == "__main__":
    print("\n==============================")
    print("  Network Traffic Analyzer")
    print("===============================\n")
    print("1️⃣  Run in Terminal (Live Capture + Real-Time Analysis)")
    print("2️⃣  Run as Web App (Browser)")

    choice = input("\nSelect Mode (1 or 2): ").strip()

    if choice == "1":
        run_terminal_mode()
    elif choice == "2":
        run_streamlit_app()
    else:
        print("\n⛔ Invalid Choice. Please run the program again.\n")
