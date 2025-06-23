import streamlit as st
from packet_sniffer import start_sniffing
from analyzer import analyze_packets
from exporter import generate_csv_download_link
import pandas as pd

st.set_page_config(page_title="Network Traffic Analyzer", layout="centered")

st.title("🌐 Network Traffic Analyzer")
st.write("Monitor live network traffic, view protocol usage, top IPs, and detect possible DDoS activity.")

st.divider()

if st.button("🚀 Start Packet Capture"):
    st.info("Capturing packets... Please wait.")
    packets = start_sniffing(packet_count=100)

    st.success("✅ Packet capture complete!")

    st.subheader("📥 Captured Packets")

    if packets:
        for idx, pkt in enumerate(packets, 1):
            pkt["S.No"] = idx
        df = pd.DataFrame(packets)
        df = df[["S.No", "timestamp", "src_ip", "dst_ip", "protocol", "length"]]

        st.dataframe(df, use_container_width=True)

        download_link = generate_csv_download_link(packets, filename="captured_packets.csv")
        st.markdown(download_link, unsafe_allow_html=True)

    else:
        st.warning("No packets captured.")

    st.divider()

    st.subheader("📊 Packet Analysis Results")

    proto_stats, data_by_src, top_src, top_dst, ddos_list = analyze_packets(packets)

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
