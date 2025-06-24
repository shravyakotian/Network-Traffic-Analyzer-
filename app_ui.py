import streamlit as st
from packet_sniffer import start_sniffing
from analyzer import analyze_packets
from exporter import generate_csv_download_link, auto_save_to_csv, save_analysis_to_csv
import pandas as pd

st.set_page_config(page_title="Network Traffic Analyzer", layout="centered")

st.title("🌐 Network Traffic Analyzer")
st.write("Monitor live network traffic, filter by protocol or IP, view statistics, and detect possible DDoS activity.")

st.divider()

if st.button("🚀 Start Packet Capture"):
    st.info("Capturing packets... Please wait.")
    packets = start_sniffing(packet_count=1000)

    st.success("✅ Packet capture complete!")

    auto_save_to_csv(packets)

    st.subheader("📥 Captured Packets")

    if packets:
        for idx, pkt in enumerate(packets, 1):
            pkt["S.No"] = idx
        df = pd.DataFrame(packets)
        df = df[["S.No", "timestamp", "src_mac", "dst_mac", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length"]]

        # Filter Options
        st.sidebar.header("🔍 Filter Options")
        protocols = ["All"] + sorted(df["protocol"].unique())
        selected_protocol = st.sidebar.selectbox("Filter by Protocol", protocols)

        ip_filter = st.sidebar.text_input("Filter by IP (source or destination)")

        filtered_df = df

        if selected_protocol != "All":
            filtered_df = filtered_df[filtered_df["protocol"] == selected_protocol]

        if ip_filter:
            filtered_df = filtered_df[(filtered_df["src_ip"] == ip_filter) | (filtered_df["dst_ip"] == ip_filter)]

        st.dataframe(filtered_df, use_container_width=True)

        download_link = generate_csv_download_link(filtered_df.to_dict(orient="records"), filename="filtered_packets.csv")
        st.markdown(download_link, unsafe_allow_html=True)

    else:
        st.warning("No packets captured.")

    st.divider()

    st.subheader("📊 Packet Analysis Results")

    proto_stats, data_by_src, top_src, top_dst, ddos_list = analyze_packets(packets)

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
