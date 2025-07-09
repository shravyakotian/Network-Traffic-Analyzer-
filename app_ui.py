import streamlit as st
from enhanced_network_monitor import EnhancedNetworkMonitor
import pandas as pd
import plotly.express as px
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
    st.session_state.monitor_thread_started = False

monitor = st.session_state.monitor

# ===========================
# 🌟 Sidebar - Professional UX
# ===========================

with st.sidebar:
    st.header("⚙️ Monitor Settings")

    start_stop = st.radio(
        "Monitoring Control",
        options=["", "Start 🚀", "Stop 🛑"],
        index=0,
        format_func=lambda x: "👉 Please select" if x == "" else x
    )

    refresh_interval = st.slider(
        "🔁 Refresh Interval (seconds)",
        min_value=1, max_value=10, value=2
    )

    # 🧹 Perform start/stop actions
    if start_stop == "Start 🚀" and not st.session_state.monitoring:
        st.session_state.monitoring = True
        monitor.running = True
        if not st.session_state.monitor_thread_started:
            threading.Thread(target=monitor.start_monitoring, daemon=True).start()
            st.session_state.monitor_thread_started = True
        st.success("✅ Monitoring started.")

    elif start_stop == "Stop 🛑" and st.session_state.monitoring:
        monitor.running = False
        st.session_state.monitoring = False
        st.session_state.monitor_thread_started = False
        st.warning("🛑 Monitoring stopped.")

    # 🟢 Show updated status *after* start/stop logic
    st.markdown(f"### 🚦 Status: {'🟢 Active' if st.session_state.monitoring else '🔴 Stopped'}")

    st.divider()

    with st.expander("📊 Metrics to Display", expanded=True):
        fields = ["Websites Visited", "Unique IPs", "DNS Queries", "Protocol Stats", "Top Talkers"]
        selected_fields = [f for f in fields if st.checkbox(f, value=False)]

    st.divider()

    st.header("⏳ Time Range Filter")
    time_range_choice = st.radio(
        "Show Data For:",
        ["", "Show All", "Custom"],
        index=0,
        format_func=lambda x: "👉 Please select" if x == "" else x
    )

    if time_range_choice == "Custom":
        time_unit = st.selectbox(
            "Time Unit",
            ["", "Minutes", "Hours", "Days"],
            index=0,
            format_func=lambda x: "👉 Please select" if x == "" else x
        )
        time_value = None
        if time_unit and time_unit != "":
            time_value = st.slider("Value", min_value=1, max_value=60, value=5)
    else:
        time_unit, time_value = None, None

# ==============================
# 🔎 Utility: Time Filter + Empty
# ==============================

def filter_by_time(connections):
    if time_range_choice == "Show All" or not time_unit or not time_value:
        return connections
    cutoff = datetime.now()
    if time_unit == "Minutes":
        cutoff -= timedelta(minutes=time_value)
    elif time_unit == "Hours":
        cutoff -= timedelta(hours=time_value)
    elif time_unit == "Days":
        cutoff -= timedelta(days=time_value)
    return [
        conn for conn in connections
        if 'timestamp' in conn and datetime.fromisoformat(conn['timestamp']) >= cutoff
    ]

def show_empty(message):
    st.write(f"🔍 *{message}*")

# ===================
# 📊 Main Dashboard
# ===================

snapshot = monitor.get_snapshot()

# Spinner if running
if st.session_state.monitoring:
    with st.spinner("Monitoring in progress..."):
        st.info(f"Monitoring is active. Refreshes every {refresh_interval} seconds.")
else:
    st.info("Monitoring is stopped. Start to see live stats.")

# Metrics
col1, col2, col3 = st.columns(3)
if "Websites Visited" in selected_fields:
    col1.metric("Websites Visited", len(snapshot['websites_visited']))
if "Unique IPs" in selected_fields:
    col2.metric("Unique IPs", len(snapshot['ip_addresses']))
if "DNS Queries" in selected_fields:
    col3.metric("DNS Queries", len(snapshot['dns_queries']))

# Sections
if "Websites Visited" in selected_fields:
    st.markdown("### 🌐 Websites Visited")
    if snapshot['websites_visited']:
        st.write(snapshot['websites_visited'])
    else:
        show_empty("No websites detected yet.")

if "Protocol Stats" in selected_fields:
    st.markdown("### 🔌 Protocol Stats")
    proto_df = pd.DataFrame(list(snapshot['protocol_stats'].items()), columns=["Protocol", "Connections"])
    if not proto_df.empty:
        col_a, col_b = st.columns(2)
        with col_a:
            fig_pie = px.pie(proto_df, names='Protocol', values='Connections', title='Protocol Distribution')
            st.plotly_chart(fig_pie, use_container_width=True)
        with col_b:
            fig_bar = px.bar(proto_df, x='Protocol', y='Connections', title='Protocol Connections', text_auto=True)
            st.plotly_chart(fig_bar, use_container_width=True)
    else:
        show_empty("No protocol data yet.")

if "Top Talkers" in selected_fields:
    st.markdown("### 📈 Top Talkers (IPs)")
    top_ips_raw = sorted(monitor.ip_traffic_bytes.items(), key=lambda x: -x[1])
    top_ips = pd.DataFrame(top_ips_raw, columns=["IP", "Bytes"])
    if not top_ips.empty:
        fig_top = px.bar(top_ips.head(10), x='Bytes', y='IP', orientation='h', title='Top Talkers by Traffic')
        st.plotly_chart(fig_top, use_container_width=True)
    else:
        show_empty("No traffic data yet.")

if "Unique IPs" in selected_fields:
    st.markdown("### 🌍 Unique IP Addresses")
    if snapshot['ip_addresses']:
        df_ips = pd.DataFrame(snapshot['ip_addresses'], columns=["IP Address"])
        st.dataframe(df_ips, use_container_width=True)
    else:
        show_empty("No IPs detected yet.")

if "DNS Queries" in selected_fields:
    st.markdown("### 🧬 DNS Queries")
    if snapshot['dns_queries']:
        df_dns = pd.DataFrame(snapshot['dns_queries'], columns=["DNS Query"])
        st.dataframe(df_dns, use_container_width=True)
    else:
        show_empty("No DNS queries captured yet.")

# HTTP Requests
if snapshot.get('http_requests'):
    st.markdown("### 🌐 Captured HTTP Requests")
    df_http = pd.DataFrame(snapshot['http_requests'])
    if not df_http.empty:
        st.dataframe(df_http, use_container_width=True)
    else:
        show_empty("No HTTP requests captured yet.")

# Activity Log
with st.expander("📜 Activity Log", expanded=False):
    if os.path.exists(monitor.log_file):
        with open(monitor.log_file, "r", encoding="utf-8") as logf:
            logs = logf.read()
        logs = "\n".join(logs.splitlines()[-500:])
        st.text_area("Log Output", logs, height=300, max_chars=10000, key="log_viewer")
    else:
        st.info("Log file not created yet. Start monitoring to generate logs.")

# ==================
# 📦 Export Section
# ==================

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

# ========================
# 🔄 Auto-refresh if active
# ========================

if st.session_state.monitoring:
    time.sleep(refresh_interval)
    st.rerun()
