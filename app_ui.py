import streamlit as st
from enhanced_network_monitor import EnhancedNetworkMonitor
import pandas as pd
import time
from datetime import datetime, timedelta
import threading
import os

st.set_page_config(page_title="Enhanced Network Traffic Monitor", layout="wide")

st.title("🌐 Enhanced Network Traffic Monitor")
st.divider()

if 'monitor' not in st.session_state:
    st.session_state.monitor = EnhancedNetworkMonitor()
    st.session_state.monitoring = False

monitor = st.session_state.monitor

# Sidebar Controls
st.sidebar.header("🔧 Monitor Controls")
refresh_interval = st.sidebar.number_input("Refresh Interval (seconds)", min_value=1, max_value=10, value=2)

if not st.session_state.monitoring:
    if st.sidebar.button("🚀 Start Monitoring"):
        st.session_state.monitoring = True
        monitor.running = True
        threading.Thread(target=monitor.start_monitoring, daemon=True).start()
        st.success("Monitoring started.")
else:
    if st.sidebar.button("🛑 Stop Monitoring"):
        monitor.running = False
        st.session_state.monitoring = False
        st.warning("Monitoring stopped.")

st.divider()

if st.session_state.monitoring:
    st.info(f"Monitoring is active. Refreshes every {refresh_interval} seconds.")
else:
    st.info("Monitoring is stopped. Start to see live stats.")

# Optional field selection
st.sidebar.header("📝 Fields to Display")
fields = ["Websites Visited", "Unique IPs", "DNS Queries", "Protocol Stats", "Top Talkers"]
selected_fields = [f for f in fields if st.sidebar.checkbox(f, value=False)]

# New Time Filter
st.sidebar.header("⏳ Display Data For")
time_filter = st.sidebar.selectbox(
    "Time Range",
    ["Show All", "Last 5 minutes", "Last 30 minutes", "Last 1 hour", "Last 1 day"]
)

def filter_by_time(connections):
    if time_filter == "Show All":
        return connections
    cutoff = datetime.now()
    if time_filter == "Last 5 minutes":
        cutoff -= timedelta(minutes=5)
    elif time_filter == "Last 30 minutes":
        cutoff -= timedelta(minutes=30)
    elif time_filter == "Last 1 hour":
        cutoff -= timedelta(hours=1)
    elif time_filter == "Last 1 day":
        cutoff -= timedelta(days=1)
    filtered = [
        conn for conn in connections
        if 'timestamp' in conn and datetime.fromisoformat(conn['timestamp']) >= cutoff
    ]
    return filtered

# Snapshot
snapshot = monitor.get_snapshot()

# Metrics
col1, col2, col3 = st.columns(3)
if "Websites Visited" in selected_fields:
    col1.metric("Websites Visited", len(snapshot['websites_visited']))
if "Unique IPs" in selected_fields:
    col2.metric("Unique IPs", len(snapshot['ip_addresses']))
if "DNS Queries" in selected_fields:
    col3.metric("DNS Queries", len(snapshot['dns_queries']))

if "Websites Visited" in selected_fields:
    st.markdown("### 🌐 Websites Visited")
    if snapshot['websites_visited']:
        st.write(snapshot['websites_visited'])
    else:
        st.write("No websites detected yet.")

if "Protocol Stats" in selected_fields:
    st.markdown("### 🔌 Protocol Stats")
    proto_df = pd.DataFrame(list(snapshot['protocol_stats'].items()), columns=["Protocol", "Connections"])
    if not proto_df.empty:
        st.dataframe(proto_df, use_container_width=True)
    else:
        st.write("No protocol data yet.")

if "Top Talkers" in selected_fields:
    st.markdown("### 📈 Top Talkers (IPs)")
    top_ips_raw = sorted(monitor.ip_traffic_bytes.items(), key=lambda x: -x[1])
    top_ips = pd.DataFrame(top_ips_raw, columns=["IP", "Bytes"])
    if not top_ips.empty:
        st.dataframe(top_ips.head(10), use_container_width=True)
    else:
        st.write("No traffic data yet.")

# Show HTTP Requests
if snapshot.get('http_requests'):
    st.markdown("### 🌐 Captured HTTP Requests")
    df_http = pd.DataFrame(snapshot['http_requests'])
    if not df_http.empty:
        st.dataframe(df_http, use_container_width=True)
    else:
        st.write("No HTTP requests captured yet.")

# Show Activity Log
st.markdown("### 📜 Activity Log")

if os.path.exists(monitor.log_file):
    with open(monitor.log_file, "r", encoding="utf-8") as logf:
        logs = logf.read()
    st.text_area("Log Output", logs, height=300)
else:
    st.info("Log file not created yet. Start monitoring to generate logs.")

# Export section
st.divider()
st.subheader("📦 Export Data")

col1, col2 = st.columns(2)
with col1:
    if st.button("📄 Export CSV"):
        monitor.generate_summary()
        csv_path = monitor.summary_file.replace(".json", ".csv")
        with open(csv_path, "r", encoding="utf-8") as f:
            csv_data = f.read()
        st.download_button("⬇️ Download CSV", csv_data, file_name="network_summary.csv", mime="text/csv")

with col2:
    if st.button("📄 Export PDF"):
        monitor.generate_summary()
        pdf_path = monitor.summary_file.replace(".json", ".pdf")
        with open(pdf_path, "rb") as f:
            pdf_data = f.read()
        st.download_button("⬇️ Download PDF", pdf_data, file_name="network_summary.pdf", mime="application/pdf")

# Auto-refresh the page
time.sleep(refresh_interval)
st.rerun()
