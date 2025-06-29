import streamlit as st
from packet_sniffer import continuous_sniffing, continuous_packets
from analyzer import analyze_packets
from exporter import generate_csv_download_link, save_analysis_to_csv
import pandas as pd
import time
from datetime import datetime, timedelta

st.set_page_config(page_title="Network Traffic Analyzer", layout="centered")

st.title("🌐 Network Traffic Analyzer")
st.write("Monitor live network traffic, select display fields, filter captured packets by custom time, view statistics, and detect possible DDoS activity.")

st.divider()

# Sidebar - Settings
st.sidebar.header("🔧 Filter & Capture Settings")

available_fields = {
    "S.No": "S.No",
    "Timestamp": "timestamp",
    "Source MAC": "src_mac",
    "Destination MAC": "dst_mac",
    "Source IP": "src_ip",
    "Destination IP": "dst_ip",
    "Source Domain": "src_domain",
    "Destination Domain": "dst_domain",
    "Source Port": "src_port",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Packet Size": "length",
    "DNS Query": "dns_query",
    "HTTP Payload": "http_payload"
}

st.sidebar.markdown("✅ **Select fields to display/export**")

selected_display_fields = []
for label in available_fields.keys():
    if st.sidebar.checkbox(label, value=False):
        selected_display_fields.append(label)

# Continuous monitoring settings
st.sidebar.header("⚡ Continuous Monitor Settings")
refresh_interval = st.sidebar.number_input("🔄 Dashboard Refresh Interval (seconds)", min_value=1, max_value=10, value=2, step=1)

# Custom time filter
st.sidebar.markdown("⏱️ **Display Packets for Custom Time Range**")
time_unit = st.sidebar.selectbox("Time Unit", ["Minutes", "Hours"])
time_value = st.sidebar.number_input("Enter Value", min_value=1, value=5, step=1)
show_all = st.sidebar.checkbox("Show All Packets", value=False)

if "monitoring" not in st.session_state:
    st.session_state["monitoring"] = False

if st.sidebar.button("🚀 Start Continuous Monitoring"):
    continuous_sniffing()
    st.session_state["monitoring"] = True
    st.success("Continuous monitoring started.")

if "packets" not in st.session_state:
    st.session_state["packets"] = []

if st.button("🛑 Stop Continuous Monitoring"):
    st.session_state["monitoring"] = False
    st.warning("Continuous monitoring stopped. Data remains visible.")


# Function to filter by custom time
def filter_by_time(packets):
    if show_all:
        return packets
    cutoff = datetime.now()
    if time_unit == "Minutes":
        cutoff -= timedelta(minutes=time_value)
    elif time_unit == "Hours":
        cutoff -= timedelta(hours=time_value)
    return [pkt for pkt in packets if datetime.strptime(pkt['timestamp'], "%Y-%m-%d %H:%M:%S") >= cutoff]


# Live Dashboard
if st.session_state.get("monitoring"):
    st.info(f"Dashboard auto-refreshing every {refresh_interval} seconds...")

    packet_snapshot = continuous_packets.copy()
    filtered_packets = filter_by_time(packet_snapshot)
    df = pd.DataFrame(filtered_packets)

    if not df.empty:
        df["S.No"] = range(1, len(df) + 1)

        for field in available_fields.values():
            if field not in df.columns:
                df[field] = "N/A"

        mapped_columns = [available_fields[field] for field in selected_display_fields if field in available_fields]

        if mapped_columns:
            st.dataframe(df[mapped_columns], use_container_width=True)

        st.session_state["packets"] = packet_snapshot

        st.divider()
        st.subheader("📊 Live Packet Analysis")

        proto_stats, data_by_src, top_src, top_dst, ddos_list = analyze_packets(df.to_dict(orient="records"))

        with st.expander("📌 Protocol Usage", expanded=True):
            st.table(pd.DataFrame(proto_stats.items(), columns=["Protocol", "Count"]))

        with st.expander("📦 Data Volume by Source IP", expanded=True):
            st.table(pd.DataFrame(data_by_src.items(), columns=["Source IP", "Total Data (bytes)"]))

        with st.expander("🌐 Top Source IPs", expanded=True):
            st.table(pd.DataFrame(top_src, columns=["Source IP", "Packet Count"]))

        with st.expander("🌐 Top Destination IPs", expanded=True):
            st.table(pd.DataFrame(top_dst, columns=["Destination IP", "Packet Count"]))

        with st.expander("🚨 Potential DDoS Sources", expanded=True):
            if ddos_list:
                st.error(f"Suspicious IPs Detected: {', '.join(ddos_list)}")
            else:
                st.success("No DDoS-like activity detected.")

    time.sleep(refresh_interval)
    st.rerun()

# Results after Stop
if st.session_state["packets"] and not st.session_state.get("monitoring"):
    st.divider()
    st.subheader("📥 Captured Packets Summary")

    filtered_packets = filter_by_time(st.session_state["packets"])
    df = pd.DataFrame(filtered_packets)
    df["S.No"] = range(1, len(df) + 1)

    for field in available_fields.values():
        if field not in df.columns:
            df[field] = "N/A"

    available_protocols = ["All"] + sorted(df["protocol"].dropna().unique())
    selected_protocol = st.selectbox("Filter by Protocol", available_protocols)

    all_ips = pd.concat([df["src_ip"], df["dst_ip"]]).dropna().unique()
    available_ips = ["All"] + sorted(all_ips)
    selected_ip = st.selectbox("Filter by IP (source or destination)", available_ips)

    filtered_df = df.copy()
    if selected_protocol != "All":
        filtered_df = filtered_df[filtered_df["protocol"] == selected_protocol]
    if selected_ip != "All":
        filtered_df = filtered_df[(filtered_df["src_ip"] == selected_ip) | (filtered_df["dst_ip"] == selected_ip)]

    mapped_columns = [available_fields[field] for field in selected_display_fields if field in available_fields]
    st.dataframe(filtered_df[mapped_columns], use_container_width=True)

    download_link = generate_csv_download_link(filtered_df[mapped_columns].to_dict(orient="records"), filename="filtered_packets.csv")
    st.markdown(download_link, unsafe_allow_html=True)

    st.divider()
    st.subheader("📊 Packet Analysis Results (Filtered Packets)")

    proto_stats, data_by_src, top_src, top_dst, ddos_list = analyze_packets(filtered_df.to_dict(orient="records"))
    save_analysis_to_csv(proto_stats, data_by_src, top_src, top_dst, ddos_list)

    with st.expander("📌 Protocol Usage", expanded=True):
        st.table(pd.DataFrame(proto_stats.items(), columns=["Protocol", "Count"]))

    with st.expander("📦 Data Volume by Source IP", expanded=True):
        st.table(pd.DataFrame(data_by_src.items(), columns=["Source IP", "Total Data (bytes)"]))

    with st.expander("🌐 Top Source IPs", expanded=True):
        st.table(pd.DataFrame(top_src, columns=["Source IP", "Packet Count"]))

    with st.expander("🌐 Top Destination IPs", expanded=True):
        st.table(pd.DataFrame(top_dst, columns=["Destination IP", "Packet Count"]))

    with st.expander("🚨 Potential DDoS Sources", expanded=True):
        if ddos_list:
            st.error(f"Suspicious IPs Detected: {', '.join(ddos_list)}")
        else:
            st.success("No DDoS-like activity detected.")
