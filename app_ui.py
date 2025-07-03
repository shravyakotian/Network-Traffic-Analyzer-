import streamlit as st
from packet_sniffer import continuous_sniffing, continuous_packets
from analyzer import analyze_packets
from exporter import generate_csv_download_link, save_analysis_to_csv
import pandas as pd
import time
from datetime import datetime, timedelta
# Add diagnostic imports
from scapy.all import get_if_list, conf
import platform
import os

st.set_page_config(page_title="Network Traffic Analyzer", layout="centered")

st.title("🌐 Network Traffic Analyzer")
st.write("Monitor live network traffic, select display fields, filter captured packets by custom time, view statistics, and detect possible DDoS activity.")

# Add diagnostic information
st.divider()
st.subheader("🔍 System Diagnostics")

with st.expander("System Information", expanded=False):
    col1, col2 = st.columns(2)
    with col1:
        st.write(f"**Operating System:** {platform.system()} {platform.release()}")
        st.write(f"**Python Version:** {platform.python_version()}")
        
        # Check if running as admin (Windows specific)
        admin_status = "Unknown"
        if platform.system() == "Windows":
            try:
                import ctypes
                admin_status = "Yes" if ctypes.windll.shell32.IsUserAnAdmin() else "No"
            except:
                admin_status = "Cannot determine"
        else:
            admin_status = "Yes" if os.geteuid() == 0 else "No"
        
        st.write(f"**Running as Admin:** {admin_status}")
    
    with col2:
        interfaces = get_if_list()
        st.write(f"**Available Network Interfaces:** {len(interfaces)}")
        st.write(f"**Default Interface:** {conf.iface}")
        
        if st.checkbox("Show All Interfaces", value=False):
            for i, iface in enumerate(interfaces):
                st.write(f"{i+1}. {iface}")

# Add warning for Windows users
if platform.system() == "Windows":
    st.warning("⚠️ **Important for Windows users:**\n"
               "- Run as Administrator for better packet capture\n"
               "- Ensure WinPcap or Npcap is installed\n"
               "- Disable Windows Defender real-time protection temporarily if needed\n"
               "- Some corporate networks may block packet capture")

st.divider()

# Sidebar - Settings
st.sidebar.header("🔧 Filter & Capture Settings")

# Network Interface Selection
st.sidebar.subheader("🌐 Network Interface")
interfaces = get_if_list()
interface_options = ["Auto (Default)"] + [f"Interface {i+1}" for i in range(len(interfaces))]
selected_interface_idx = st.sidebar.selectbox("Select Network Interface", 
                                             range(len(interface_options)), 
                                             format_func=lambda x: interface_options[x])

if selected_interface_idx > 0:
    selected_interface = interfaces[selected_interface_idx - 1]
    st.sidebar.write(f"Selected: {selected_interface}")
else:
    selected_interface = None

available_fields = {
    "S.No": "S.No",
    "Timestamp": "timestamp",
    "Website Visited": "website_visited",
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

# Initialize session state for field selection
if "selected_fields" not in st.session_state:
    st.session_state.selected_fields = ["S.No", "Timestamp", "Website Visited", "Source IP", "Destination IP", "Protocol", "Packet Size", "HTTP Payload"]

selected_display_fields = []
for label in available_fields.keys():
    is_selected = st.sidebar.checkbox(label, value=label in st.session_state.selected_fields, key=f"field_{label}")
    if is_selected:
        selected_display_fields.append(label)

# Update session state
st.session_state.selected_fields = selected_display_fields

# Continuous monitoring settings
st.sidebar.header("⚡ Continuous Monitor Settings")
refresh_interval = st.sidebar.number_input("🔄 Dashboard Refresh Interval (seconds)", min_value=1, max_value=10, value=2, step=1)

# Custom time filter
st.sidebar.markdown("⏱️ **Display Packets for Custom Time Range**")
time_unit = st.sidebar.selectbox("Time Unit", ["Minutes", "Hours"])
time_value = st.sidebar.number_input("Enter Value", min_value=1, value=5, step=1)
show_all = st.sidebar.checkbox("Show All Packets", value=False)

# Initialize session states
if "monitoring" not in st.session_state:
    st.session_state["monitoring"] = False

if "packets" not in st.session_state:
    st.session_state["packets"] = []

if "capture_error" not in st.session_state:
    st.session_state["capture_error"] = None

# Modified start monitoring button
if st.sidebar.button("🚀 Start Continuous Monitoring"):
    try:
        # Clear any previous errors
        st.session_state["capture_error"] = None
        
        # Start continuous sniffing with selected interface
        continuous_sniffing(interface=selected_interface)
        st.session_state["monitoring"] = True
        st.success("✅ Continuous monitoring started successfully!")
        
        # Display some initial info
        st.info(f"🔍 Monitoring interface: {selected_interface if selected_interface else 'Default'}")
        st.info("📊 Packets will appear below as they are captured...")
        
    except Exception as e:
        st.session_state["capture_error"] = str(e)
        st.error(f"❌ Failed to start monitoring: {str(e)}")
        st.error("💡 Try running the application as Administrator or check your network permissions")

# Display capture error if any
if st.session_state.get("capture_error"):
    st.error(f"⚠️ Capture Error: {st.session_state['capture_error']}")

if st.button("🛑 Stop Continuous Monitoring"):
    from packet_sniffer import stop_sniffing
    stop_sniffing()
    st.session_state["monitoring"] = False
    st.warning("⏹️ Continuous monitoring stopped. Data remains visible.")

if st.button("🗑️ Clear All Captured Data"):
    from packet_sniffer import continuous_packets
    continuous_packets.clear()
    st.session_state["packets"] = []
    st.success("🗑️ All captured data cleared.")

# Debug section
st.sidebar.header("🔧 Debug")
if st.sidebar.button("📊 Show Debug Info"):
    from packet_sniffer import get_capture_stats
    stats = get_capture_stats()
    st.sidebar.write(f"**Stats:** {stats}")
    st.sidebar.write(f"**Packets in memory:** {len(continuous_packets)}")
    st.sidebar.write(f"**Session packets:** {len(st.session_state.get('packets', []))}")
    
    # Show first few packets for debugging
    if len(continuous_packets) > 0:
        st.sidebar.write("**First 3 packets:**")
        for i, pkt in enumerate(continuous_packets[:3]):
            st.sidebar.write(f"{i+1}. {pkt['timestamp']} - {pkt['protocol']} - {pkt['src_ip']} -> {pkt['dst_ip']}")

if st.sidebar.button("🌐 Show Website Detection"):
    if len(continuous_packets) > 0:
        websites = set()
        http_packets = []
        for pkt in continuous_packets:
            website = pkt.get('website_visited', 'N/A')
            if website != 'N/A':
                websites.add(website)
            if pkt.get('protocol') == 'HTTP' and pkt.get('http_payload') != 'N/A':
                http_packets.append(pkt)
        
        st.sidebar.write(f"**Websites detected:** {len(websites)}")
        for website in sorted(websites):
            st.sidebar.write(f"- {website}")
        
        st.sidebar.write(f"**HTTP packets:** {len(http_packets)}")
        for pkt in http_packets[:3]:  # Show first 3
            st.sidebar.write(f"- {pkt['src_ip']} -> {pkt['dst_ip']}: {pkt['website_visited']}")
    else:
        st.sidebar.write("No packets captured yet")

if st.sidebar.button("🧪 Run Quick Test"):
    st.sidebar.write("Running quick packet capture test...")
    try:
        from scapy.all import sniff
        test_packets = sniff(timeout=3, count=5)
        st.sidebar.success(f"✅ Captured {len(test_packets)} packets in quick test")
    except Exception as e:
        st.sidebar.error(f"❌ Quick test failed: {e}")

if st.sidebar.button("🔥 Test HTTP Requests"):
    st.sidebar.write("Testing HTTP requests...")
    import requests
    import time
    
    # Clear packets first
    continuous_packets.clear()
    
    # Start monitoring if not already
    if not st.session_state.get("monitoring"):
        try:
            from packet_sniffer import continuous_sniffing
            continuous_sniffing(interface=selected_interface)
            st.session_state["monitoring"] = True
            time.sleep(2)  # Wait for capture to start
        except Exception as e:
            st.sidebar.error(f"Failed to start monitoring: {e}")
            st.stop()
    
    # Make test requests
    try:
        st.sidebar.write("Making HTTP requests...")
        response = requests.get('http://httpbin.org/json', timeout=5)
        st.sidebar.write(f"✅ httpbin.org: {response.status_code}")
        time.sleep(2)
        
        response = requests.get('http://jsonplaceholder.typicode.com/posts/1', timeout=5)
        st.sidebar.write(f"✅ jsonplaceholder: {response.status_code}")
        time.sleep(2)
        
        # Check results
        websites = set()
        for pkt in continuous_packets:
            website = pkt.get('website_visited', 'N/A')
            if website != 'N/A':
                websites.add(website)
        
        st.sidebar.write(f"**Captured {len(continuous_packets)} packets**")
        st.sidebar.write(f"**Websites detected: {len(websites)}**")
        for website in sorted(websites):
            st.sidebar.write(f"- {website}")
        
    except Exception as e:
        st.sidebar.error(f"Test failed: {e}")


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
    st.info(f"📡 Dashboard auto-refreshing every {refresh_interval} seconds...")
    
    # Import capture stats
    try:
        from packet_sniffer import get_capture_stats
        stats = get_capture_stats()
        
        # Display capture statistics
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Packets Captured", stats['total_packets'])
        with col2:
            st.metric("Packets in Memory", len(continuous_packets))
        with col3:
            last_time = stats['last_packet_time']
            if last_time:
                if isinstance(last_time, str):
                    # If it's a string, try to parse it
                    try:
                        last_time_dt = datetime.strptime(last_time, "%Y-%m-%d %H:%M:%S")
                        time_diff = (datetime.now() - last_time_dt).total_seconds()
                    except:
                        time_diff = 0
                else:
                    # If it's already a datetime object
                    time_diff = (datetime.now() - last_time).total_seconds()
                st.metric("Last Packet", f"{time_diff:.1f}s ago")
            else:
                st.metric("Last Packet", "None")
        
        # Show any capture errors
        if stats['errors']:
            st.error("⚠️ Capture Errors:")
            for error in stats['errors'][-3:]:  # Show last 3 errors
                st.error(error)
    except ImportError:
        pass

    # Get fresh packet data
    packet_snapshot = list(continuous_packets)  # Create a proper copy
    filtered_packets = filter_by_time(packet_snapshot)
    
    # Debug information
    st.info(f"🔍 Debug: Total packets in memory: {len(packet_snapshot)}, After time filter: {len(filtered_packets)}")
    
    if filtered_packets:
        df = pd.DataFrame(filtered_packets)
        df["S.No"] = range(1, len(df) + 1)

        for field in available_fields.values():
            if field not in df.columns:
                df[field] = "N/A"

        # Use the selected fields from session state
        mapped_columns = [available_fields[field] for field in st.session_state.selected_fields if field in available_fields]

        if mapped_columns:
            st.subheader(f"📊 Live Packet Data ({len(filtered_packets)} packets)")
            st.dataframe(df[mapped_columns], use_container_width=True, height=400)
        else:
            st.warning("⚠️ No fields selected for display. Please select fields from the sidebar.")

        st.session_state["packets"] = packet_snapshot
    else:
        st.info("🔍 No packets captured yet. Make sure:")
        st.info("• You have network traffic (try browsing websites)")
        st.info("• Application is running as Administrator (on Windows)")
        st.info("• Windows Defender/Firewall is not blocking packet capture")
        st.info("• The correct network interface is selected")
        
        # Show raw packet count for debugging
        if len(packet_snapshot) > 0:
            st.warning(f"⚠️ {len(packet_snapshot)} packets are captured but filtered out by time range. Try 'Show All Packets' or increase the time range.")

    # Only show analysis if we have packets
    if filtered_packets:
        st.divider()
        st.subheader("📊 Live Packet Analysis")

        proto_stats, data_by_src, top_src, top_dst, ddos_list = analyze_packets(filtered_packets)

        with st.expander("📌 Protocol Usage", expanded=True):
            if proto_stats:
                st.table(pd.DataFrame(proto_stats.items(), columns=["Protocol", "Count"]))
            else:
                st.info("No protocol data available yet")

        with st.expander("📦 Data Volume by Source IP", expanded=True):
            if data_by_src:
                st.table(pd.DataFrame(data_by_src.items(), columns=["Source IP", "Total Data (bytes)"]))
            else:
                st.info("No data volume information available yet")

        with st.expander("🌐 Top Source IPs", expanded=True):
            if top_src:
                st.table(pd.DataFrame(top_src, columns=["Source IP", "Packet Count"]))
            else:
                st.info("No source IP data available yet")

        with st.expander("🌐 Top Destination IPs", expanded=True):
            if top_dst:
                st.table(pd.DataFrame(top_dst, columns=["Destination IP", "Packet Count"]))
            else:
                st.info("No destination IP data available yet")

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

    mapped_columns = [available_fields[field] for field in st.session_state.selected_fields if field in available_fields]
    if mapped_columns:
        st.dataframe(filtered_df[mapped_columns], use_container_width=True)
        
        download_link = generate_csv_download_link(filtered_df[mapped_columns].to_dict(orient="records"), filename="filtered_packets.csv")
        st.markdown(download_link, unsafe_allow_html=True)
    else:
        st.warning("⚠️ No fields selected for display. Please select fields from the sidebar.")

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
