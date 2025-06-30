import os
import time
from datetime import datetime, timedelta
from packet_sniffer import continuous_sniffing, continuous_packets, _lock, stop_sniffing
from analyzer import analyze_packets
from exporter import auto_save_to_csv, save_analysis_to_csv


def filter_by_time(packets, time_unit, time_value, show_all):
    if show_all:
        return packets

    cutoff = datetime.now()
    if time_unit == "minutes":
        cutoff -= timedelta(minutes=time_value)
    elif time_unit == "hours":
        cutoff -= timedelta(hours=time_value)

    return [pkt for pkt in packets if datetime.strptime(pkt['timestamp'], "%Y-%m-%d %H:%M:%S") >= cutoff]


def run_terminal_mode():
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

    print("\nDisplay Packets for Time Range:")

    # Strict time unit validation
    while True:
        unit_input = input("Select time unit - (m)inutes or (h)ours [default: m]: ").strip().lower()
        if unit_input == "":
            unit_input = "m"
        if unit_input in ["m", "h"]:
            break
        print("[ERROR] Invalid input! Please enter 'm' for minutes or 'h' for hours.")

    time_unit = "minutes" if unit_input == "m" else "hours"

    try:
        time_value = int(input("Enter time value (positive number) [default: 5]: ").strip())
        if time_value <= 0:
            raise ValueError
    except ValueError:
        time_value = 5

    show_all = input("Show all packets? (y/n) [default: n]: ").strip().lower() == "y"

    # Field selection
    print("\nAvailable Fields to Display:")
    valid_fields = [
        "timestamp", "src_mac", "dst_mac", "src_ip", "dst_ip",
        "src_domain", "dst_domain", "src_port", "dst_port",
        "protocol", "length", "dns_query", "http_payload"
    ]
    print(", ".join(valid_fields))

    fields_input = input("Enter fields to display (comma separated) or press Enter to show all: ").strip().lower()

    if not fields_input:
        selected_fields = valid_fields
    else:
        selected_fields = [f.strip() for f in fields_input.split(",") if f.strip() in valid_fields]
        if not selected_fields:
            print("[INFO] Invalid selection, displaying all fields.")
            selected_fields = valid_fields

    continuous_sniffing(terminal_live=True)

    try:
        prev_count = 0
        while True:
            time.sleep(refresh_interval)

            with _lock:
                snapshot = continuous_packets.copy()

            filtered_snapshot = filter_by_time(snapshot, time_unit, time_value, show_all)

            if len(filtered_snapshot) > prev_count:
                print(f"\n✅ Total Packets Captured (Filtered): {len(filtered_snapshot)}")
                print("\n📥 Latest Packets:\n")

                for idx, pkt in enumerate(filtered_snapshot[-5:], len(filtered_snapshot) - 4):
                    output_parts = [f"{idx}."]
                    for field in selected_fields:
                        value = pkt.get(field, "N/A")
                        if field == "http_payload" and value and len(value) > 50:
                            value = value[:50] + "..."
                        output_parts.append(f"{field}: {value}")
                    print(" | ".join(output_parts))

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
