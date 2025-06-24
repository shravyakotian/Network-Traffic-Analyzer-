# 🌐 Network Traffic Analyzer (Streamlit + CLI Version)

## 📌 Project Overview

This project is a Python-based **Network Traffic Analyzer** that captures live packets on the local network and provides real-time traffic insights such as:

✔ Protocol distribution (TCP, UDP, ICMP, ARP, etc.)
✔ Source and destination IP statistics
✔ Data volume transmitted per device
✔ Suspicious traffic detection (e.g., potential DDoS indicators)
✔ Filtering packets by protocol or IP for targeted analysis
✔ Data export options for captured packets and analysis reports

Implemented using **Scapy** for packet sniffing and **Streamlit** for an interactive web interface.

---

## 🔠 Features

✅ Capture live network packets (Ethernet, IP, TCP, UDP, ICMP, ARP)
✅ Extract details: timestamp, MAC addresses, IP addresses, ports, protocol, packet size
✅ Analyze traffic:

* Protocol usage statistics
* Data volume by source IP
* Top sender and receiver IPs
* Detect possible DDoS attacks
  ✅ Interactive Streamlit Dashboard
  ✅ Filter captured packets by Protocol or IP
  ✅ Download filtered packet data as CSV
  ✅ Automatically saves captured data and analysis report to CSV files for future reference

---

## 📂 Project Structure

```
network_traffic_analyzer/
├── appui.py               # Streamlit Web UI for live monitoring and filtering
├── packet_sniffer.py      # Captures and parses network packets
├── analyzer.py            # Analyzes captured packet data
├── exporter.py            # Handles CSV export functionality
├── requirements.txt       # Project dependencies
```

---

## 💻 Installation & Setup

### Prerequisites

✔ Python 3.8+
✔ Administrator/root privileges for packet capture
✔ [Npcap](https://nmap.org/npcap/) (Windows users - required by Scapy)

---

### Steps to Run

```bash
# Clone the repository
git clone https://github.com/your-username/network_traffic_analyzer.git
cd network_traffic_analyzer

# Optional: Create a virtual environment
python -m venv .venv
.\.venv\Scripts\activate   # For Windows

# Install dependencies
pip install -r requirements.txt

# Run the Streamlit Dashboard
streamlit run appui.py
```

---

## 📊 Usage & Output

* Click **"Start Packet Capture"** to begin monitoring
* View captured packets in a clean, scrollable table
* Apply filters by protocol or IP to isolate specific traffic
* Download filtered packets as CSV
* Automatically saves:

  * Full captured packets: `auto_saved_packets.csv`
  * Traffic analysis report: `analysis_report.csv`
* Analysis includes:

  * Protocol usage breakdown
  * Data sent per device
  * Top source/destination IPs
  * Suspicious traffic alerts (DDoS indicators)

---

## 🛠 Dependencies

```bash
pip install scapy streamlit pandas
```

---

## 📚 Future Enhancements

* Real-time traffic graphs and charts
* Filtering by port numbers
* PDF export for reports
* Live traffic alerts within UI
* More advanced anomaly detection

---

**Note:** Always run with admin/root access to enable proper packet sniffing.
