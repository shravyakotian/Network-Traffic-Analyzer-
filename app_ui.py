import streamlit as st
from packet_sniffer import start_sniffing
from analyzer import analyze_packets
from exporter import generate_csv_download_link, auto_save_to_csv, save_analysis_to_csv
import pandas as pd

st.set_page_config(page_title="Network Traffic Analyzer", layout="centered")

st.title("🌐 Network Traffic Analyzer")
st.write(
    "Monitor live network traffic, select display fields, filter captured packets, view statistics, and detect possible DDoS activity."
)

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
    "Source Port": "src_port",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Packet Size": "length"
}

st.sidebar.markdown("✅ **Select fields to display/export**")

# Checkbox list for selecting fields (individual checkboxes)
selected_display_fields = []
for label in available_fields.keys():
    if st.sidebar.checkbox(label, value=False):
        selected_display_fields.append(label)

packet_limit = st.sidebar.number_input("🔢 Number of packets to capture", min_value=10, max_value=10000, value=1000, step=100)

# Live placeholder
live_placeholder = st.empty()

# Session state to store packets
if "packets" not in st.session_state:
    st.session_state["packets"] = []

# Start Capture
if st.button("🚀 Start Packet Capture"):

    if not selected_display_fields:
        st.warning("⚠️ Please select at least one field to display before capturing packets.")
    else:
        st.info(f"Capturing up to {packet_limit} packets... Live updates below:")

        live_packets = []

        def show_live_packet(packet_data):
            live_packets.append(packet_data)
            temp_df = pd.DataFrame(live_packets)
            temp_df["S.No"] = range(1, len(temp_df) + 1)
            mapped_columns = [available_fields[field] for field in selected_display_fields]
            live_placeholder.dataframe(temp_df[mapped_columns], use_container_width=True)

        packets = start_sniffing(packet_count=packet_limit, live_callback=show_live_packet)
        st.session_state["packets"] = packets
        st.success(f"✅ Packet capture complete! Total packets: {len(packets)}")
        auto_save_to_csv(packets)

# If packets exist, filtering & analysis
if st.session_state["packets"]:
    st.divider()
    st.subheader("📥 Captured Packets Summary")

    df = pd.DataFrame(st.session_state["packets"])
    df["S.No"] = range(1, len(df) + 1)

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

    mapped_columns = [available_fields[field] for field in selected_display_fields]
    st.dataframe(filtered_df[mapped_columns], use_container_width=True)

    download_link = generate_csv_download_link(
        filtered_df[mapped_columns].to_dict(orient="records"),
        filename="filtered_packets.csv"
    )
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
