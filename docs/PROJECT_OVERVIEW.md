# 🛡️ Project Overview: Apex Packet Sniffer & Threat Detector

## 1. ⚡ The 30-Second Elevator Pitch
> *"Apex is a real-time Network Packet Sniffer and Intrusion Detection System (NIDS). It captures live network traffic directly from physical network interfaces (Ethernet/Wi-Fi), decodes protocols (IPv4, IPv6, TCP, UDP, ARP, DNS, HTTP), detects cyber threats in real-time (Port Scans, SYN Floods, ARP Poisoning), and visualizes the results on an interactive, dark-mode web dashboard."*

---

## 2. 🎯 Key Problem Solved & Target Audience
* **Problem**: Traditional packet sniffers like Wireshark are powerful but complex for quick threat visualization. Conversely, basic loggers lack real-time threat intelligence.
* **Solution**: Apex combines **low-level raw packet inspection (Scapy)** with an **automated rule-based Intrusion Detection Engine (IDS)** and a **modern responsive UI (FastAPI + WebSockets + HTML5/JS)**.
* **Target Audience**: Network Administrators, Cybersecurity Analysts, Developers, and Students learning network protocols.

---

## 3. 🏗️ Tech Stack & Architecture Breakdown

### **Backend Stack (Python)**
* **Scapy**: Binds directly to network interface drivers (Npcap on Windows / `libpcap` on Linux) to capture raw Ethernet frames and IP packets.
* **FastAPI & Uvicorn**: Serves asynchronous REST APIs (`/api/start`, `/api/stop`, `/api/download-pcap`, `/api/interfaces`) and manages persistent WebSockets.
* **Psutil**: Queries active network adapters (Wi-Fi, Ethernet, Loopback, VPNs).
* **PyWebView**: Wraps the web interface into a native Windows/Linux desktop application window.

### **Frontend Stack (Web Dashboard)**
* **Core**: HTML5, Vanilla CSS3 (glassmorphic dark design system), Vanilla JavaScript (ES6+).
* **Real-time Data Stream**: WebSockets (`/ws`) stream live packet batches and metric updates with sub-second latency.
* **Visualizations**: Chart.js (dynamic throughput line chart & protocol ratio donut chart), Lucide Icons.

---

## 4. ⚙️ Core Modules & Features

| Module | Location | Responsibilities |
| :--- | :--- | :--- |
| **Packet Sniffer Engine** | `backend/sniffer.py` | Controls multi-threaded live socket sniffing, interface selection, BPF filtering (`tcp port 80`, `udp`), and PCAP file export. |
| **Threat & Packet Analyzer** | `backend/analyzer.py` | Parses Ethernet, IP, TCP, UDP, ARP, DNS, HTTP layers; executes IDS threat detection algorithms; generates statistics. |
| **Web & WebSocket Server** | `backend/server.py` | Exposes REST endpoints, maintains WebSocket broadcast queues, serves static UI files. |
| **Client Application Logic** | `frontend/app.js` | Handles WebSocket ingestion, table rendering, packet search filtering, chart updates, and hex dump formatting. |

---

## 5. 🛡️ Intrusion Detection System (IDS) Engine

Apex actively monitors captured traffic for 4 major network attack vectors:

1. **Port Scanning Detection**:
   * *How it works*: Tracks unique destination ports requested by each IP address.
   * *Trigger*: If a single source IP connects to **> 15 unique ports within a 10-second window**, a high-severity **Port Scanning Alert** is triggered.

2. **TCP SYN Flood Anomaly**:
   * *How it works*: Tracks TCP `SYN` flags sent without corresponding `ACK` handshakes.
   * *Trigger*: If a source IP transmits **> 50 SYN-only packets within 5 seconds**, a critical **SYN Flood DoS Alert** is logged.

3. **ARP Spoofing / Cache Poisoning**:
   * *How it works*: Maintains an internal IP-to-MAC mapping table (`arp_table`).
   * *Trigger*: If an IP address suddenly advertises a different MAC address mid-session, a critical **ARP Poisoning Alert** is generated.

4. **Data Exfiltration / Suspicious Payloads**:
   * *How it works*: Inspects payload byte lengths and raw string headers.
   * *Trigger*: Flags single payloads exceeding **1,400 bytes** or containing unencrypted HTTP basic authorization credentials.

---

## 6. 🔄 Data Flow (How a Packet Travels)

```text
1. Physical NIC (Network Interface Card)
   └── Captures raw packet (Npcap / libpcap)
       └── 2. Scapy Sniffer Thread (backend/sniffer.py)
           └── Passes packet to callback
               └── 3. Packet Analyzer (backend/analyzer.py)
                   ├── Extracts IP, MAC, Ports, Flags, Payload
                   ├── Runs IDS Threat Rules
                   └── Calculates B/s and Packets/sec
                       └── 4. Thread-Safe Queue -> FastAPI Server (backend/server.py)
                           └── Broadcasts JSON via WebSocket (/ws)
                               └── 5. Frontend Dashboard (frontend/app.js)
                                   ├── Updates live packet table
                                   ├── Animates throughput chart
                                   └── Displays red threat alert banner
```

---

## 7. 🌐 Flexible Deployment Modes

1. **Desktop Application Mode**:
   Run `python main.py` as Administrator. Launches a native standalone GUI window via `pywebview`.
2. **Local Area Network (LAN) Mode**:
   Run `uvicorn backend.server:app --host 0.0.0.0 --port 8000`. Any device on the same Wi-Fi/LAN can access `http://<YOUR_IP>:8000`.
3. **Decoupled Cloud Mode (Vercel + Docker)**:
   - **Frontend**: Deployed on **Vercel** (`https://your-app.vercel.app`).
   - **Backend**: Containerized via **Docker** and hosted on **Render/Railway**.

---

## 8. ❓ Frequently Asked Questions (FAQ) for Demos/Interviews

#### **Q: Why does the app require Administrator / Root privileges?**
* **A**: Operating systems block normal applications from reading raw socket network frames for privacy/security reasons. Capturing promiscuous mode network packets requires system elevated privileges (Administrator on Windows, `sudo` / `CAP_NET_RAW` on Linux).

#### **Q: What is the difference between Wireshark and Apex Sniffer?**
* **A**: Wireshark is a generic packet inspection tool requiring manual packet filtering. Apex includes **automated threat detection algorithms (IDS)**, **built-in bandwidth meters**, **unencrypted credential scanning**, and a **customizable web interface**.

#### **Q: Can Apex save captured packets for analysis later?**
* **A**: Yes! Apex provides a **Download PCAP** endpoint (`/api/download-pcap`). Captured in-memory packets can be exported directly to standard `.pcap` format and opened in Wireshark.
