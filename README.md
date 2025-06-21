
# Network Traffic Analyzer (CLI Version)

## 📌 Project Overview

This project is a Python-based **Network Traffic Analyzer** that captures live packets on the local network and provides analytical insights such as:

* Protocol distribution (TCP, UDP, ICMP, ARP)
* Source and destination IP statistics
* Data volume transmitted
* Detection of unusual traffic patterns (e.g., potential DDoS attempts)

It is implemented using **Scapy** and runs via the command line. Future versions can include a GUI or web dashboard.

---

## 💠 Features

* Capture live packets using `scapy`
* Extract essential fields: timestamp, source IP, destination IP, protocol, and size
* Analyze:

  * Top protocols used
  * Data volume by source IP
  * Top sender/receiver IPs
  * Suspected DDoS IPs based on packet volume
* Print all output in a well-formatted console view

---

## 📂 Project Structure

```
network_traffic_analyzer/
├── app.py                # Main driver script (run this)
├── packet_sniffer.py     # Captures and parses packets
├── analyzer.py           # Analyzes captured packet data
├── requirements.txt      # Python dependencies
```

---

## 💻 Installation and Setup

### Prerequisites

* Python 3.8+
* Run with **administrator privileges**
* For Windows users: Install [Npcap](https://nmap.org/npcap/) (required by Scapy)

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/network_traffic_analyzer.git
cd network_traffic_analyzer
```

### 2. Create Virtual Environment (Optional but Recommended)

```bash
python -m venv .venv
.\.venv\Scripts\activate   # Windows
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the Application

```bash
python app.py
```

---

## 🔐 Notes

* Run the script with administrator/root access to allow raw packet capture.
* To sniff indefinitely (instead of limiting to 1000 packets), modify `start_sniffing(packet_count=1000)` in `app.py`.

---

## 📚 Dependencies

* `scapy`

Install using:

```bash
pip install scapy
```

---

## 📊 Future Enhancements

* Add GUI/web dashboard using Streamlit or Dash
* Enable filtering by protocol or IP
* Allow saving analysis results in CSV or PDF format
* Include port-level analysis

---


