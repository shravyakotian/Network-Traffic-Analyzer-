# 🌐 Enhanced Network Traffic Analyzer (Streamlit + CLI Version)

## 📌 Project Overview

This project is a comprehensive **Enhanced Network Traffic Analyzer** built with Python. It captures, monitors, and analyzes real-time traffic on the system using advanced techniques and offers:

✔ Deep inspection of HTTP, DNS, and QUIC/HTTP3 traffic  
✔ Browser-aware connection monitoring  
✔ Bandwidth and protocol-level traffic analysis  
✔ IP-wise traffic and Top Talker tracking  
✔ Exportable reports in **JSON, CSV, and PDF formats**  
✔ Interactive visualizations via **Streamlit Dashboard**

Implemented using **Scapy** for packet sniffing, **Psutil** for process inspection, and **Streamlit + Plotly** for web-based analytics.

---

## 🔠 Features

✅ Capture and analyze live packets (TCP, UDP, HTTP, DNS, QUIC)  
✅ Detect and display:

* Websites and domains visited
* Browser-based connections (Chrome, Firefox, etc.)
* QUIC/HTTP3 connections and usage
* DNS queries and resolved domains
* Per-IP traffic and Top Talkers
* HTTP methods and endpoints accessed

✅ Streamlit Dashboard:

* Real-time protocol and IP metrics
* Interactive filtering and session statistics
* Export buttons for CSV and PDF

✅ CLI Logging:

* Human-readable activity logs
* JSON, CSV, PDF report summaries

✅ Export Capabilities:

* 📄 `enhanced_network_summary_*.json` – JSON Summary
* 📄 `enhanced_network_summary_*.csv` – CSV Report
* 📄 `enhanced_network_summary_*.pdf` – Visual PDF Summary

---

## 📂 Project Structure

```
enhanced_network_analyzer/
├── enhanced_network_monitor.py   # Core traffic analysis engine
├── ui_app.py                     # Streamlit dashboard UI
├── README.md                     # Documentation file
├── requirements.txt              # Python dependencies
└── outputs/                      # (Auto-generated reports and logs)
```

---

## 💻 Installation & Setup

### Prerequisites

✔ Python 3.8+  
✔ Administrator/root privileges for packet sniffing  
✔ [Npcap](https://nmap.org/npcap/) (for Windows users)  

---

### Steps to Run

```bash
# Clone the repository
git clone https://github.com/your-username/enhanced_network_analyzer.git
cd enhanced_network_analyzer

# (Optional) Create a virtual environment
python -m venv .venv
.\.venv\Scriptsctivate    # On Windows

# Install dependencies
pip install -r requirements.txt

# Run in CLI mode
python enhanced_network_monitor.py

# Run the Streamlit dashboard
streamlit run ui_app.py
```

---

## 📊 Usage & Output

### CLI Mode
* Run the script and choose between Terminal or Streamlit UI
* Logs saved in: `enhanced_network_log_*.log`
* Summary JSON: `enhanced_network_summary_*.json`

### Streamlit Dashboard
* Launches a fully interactive UI
* Sections include:
  * Websites Visited
  * Protocol Distribution (pie & bar charts)
  * DNS Queries
  * Top Talkers (by bandwidth)
  * IP address list and live stats
* Filters available for time range and traffic type
* Export options for CSV and PDF reports

---

## 🛠 Dependencies

```bash
pip install scapy psutil requests fpdf streamlit plotly pandas streamlit-autorefresh
```

---

## 📚 Future Enhancements

* Time-series traffic charts
* Email alerts on anomaly detection
* GeoIP mapping of IP addresses
* Real-time port scanning & service detection
* Historical session replay

---

**Note:** Admin/root access is required to enable full packet sniffing and process inspection.
