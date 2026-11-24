# OSI Sentinel

A Python-based seven-layer network security monitoring and threat detection system with a web dashboard.
Course: CySE 228 Network and Internet Security Sessional, Department of Cyber Security Engineering, University of Frontier Technology, Bangladesh.
Team: Mahi Uddin Alif (2304007), Md. Raju Ahmed (2304020), Kazi Md. Munem Shahriar Kabir (2304033).

## Quick start (Windows 11)

1. Install Python 3.10 or newer from python.org and tick "Add python.exe to PATH".
2. Install Npcap from https://npcap.com (see section 3). Skip this step if you only want Demo mode.
3. Unzip the project, double-click `run.bat` and accept the administrator prompt.
4. The browser opens at http://127.0.0.1:5000. Sign in with `admin` / `Sentinel@2026`.

No Npcap or no administrator rights? Double-click `run_demo.bat`. The whole dashboard works with synthetic traffic.

> Educational project. Use it only on networks and devices you own or are authorised to monitor.

## 1. Overview

OSI Sentinel captures live packets with Scapy, classifies them into the seven OSI layers, runs rule-based detectors on each layer, stores alerts and packet metadata in SQLite, and shows everything on a login-protected web dashboard. It also includes a Crypto Lab (SHA-256, AES-256-GCM, RSA, digital signatures), an interactive HTML report generator and a lab attack simulator.

## 2. Tech stack

| Part | Technology |
|---|---|
| Packet capture | Scapy with Npcap |
| Interface monitoring | psutil |
| Backend | Flask |
| Database | SQLite |
| Frontend | HTML, CSS, JavaScript, Chart.js (bundled, works offline) |
| Cryptography | `cryptography` library |
| Detection | Rule-based with sliding windows (no machine learning) |

## 3. Setup

### 3.1 Npcap (live capture)
1. Download the installer from https://npcap.com and run it as administrator.
2. Tick **Install Npcap in WinPcap API-compatible Mode**.
3. Tick **Support loopback traffic** so traffic to 127.0.0.1 can be captured (needed for the simulator).
4. Do not tick "Restrict Npcap driver's access to Administrators only" unless you always run as administrator.

### 3.2 Run
* `run.bat` starts live mode (falls back to Demo automatically if capture is unavailable).
* `run_demo.bat` starts Demo mode.
* Manual start: open a terminal in the project folder and run

```
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py --mode auto
```

Options: `--mode auto|live|demo`, `--iface "<adapter name>"`, `--port 5000`.

### 3.3 Check your machine
```
.venv\Scripts\python tools\check_system.py
```
It reports the Python version, installed modules, administrator rights, Npcap, interfaces and a 3 second capture test.

### 3.4 Python 3.14 note
The project is written for Python 3.10 and newer. If `pip install` fails on Python 3.14 for one of the packages, install Python 3.12, delete the `.venv` folder and run `run.bat` again.

## 4. Folder structure

```
osi-sentinel/
  app.py                  Flask app, login, API, entry point
  config.py               settings and detection thresholds
  requirements.txt
  run.bat                 live mode (asks for administrator rights)
  run_demo.bat            demo mode
  run_custom.bat          choose capture adapters (hotspot setup)
  run_simulator.bat       menu for the attack simulator
  run_selftest.bat        runs the detection self-test
  sentinel/               capture, engine, detectors, crypto, report, database
  templates/              dashboard pages and the report template
  static/                 CSS, JavaScript, Chart.js
  tools/                  attack_simulator.py, check_system.py
  tests/selftest.py       checks all 16 detection rules and false alerts
  docs/                   ARCHITECTURE.md, LAYER_MAPPING.md, DEMO_SCRIPT.md, USER_GUIDE.md
  instance/               created at first run: database, reports, secret key
```

## 5. Dashboard pages

| Page | Purpose |
|---|---|
| Overview | Counters, OSI layer stack, packet rate, severity chart, protocols, top talkers, latest alerts, attack scenario lab |
| Layer Monitor | One card per OSI layer with its own metrics, plus the Layer 1 interface table |
| Alerts | Filter by layer, severity or text, click a row for evidence |
| Packet Inspector | Latest 200 packets with layer, protocol and info, filterable and pausable |
| Crypto Lab | SHA-256 with avalanche comparison, AES-256-GCM with tamper detection, RSA-2048 encryption, RSA-PSS signatures |
| Reports | Generates a single self-contained interactive HTML report |
| Layer pages (`/layer/1` to `/layer/7`) | Captured frames of one layer with layer-specific columns, filter, tools and a frame decoder |
| Devices | Scan results: name, IP, MAC, vendor, type, OS guess, traffic, open ports, trust and rename |
| Topology | Visual map of the router and devices with traffic-weighted lines |
| Conversations | Flows and TCP sessions, stream follow, PCAP export |
| Rules | Enable or disable each rule and edit thresholds without touching files |

## 6. How to test the main features

1. **Self-test (no network needed):** double-click `run_selftest.bat`. All lines must show PASS.
2. **Scenario lab:** on Overview click "Run all scenarios". Alerts appear on every layer within about 20 seconds.
3. **Real traffic:** start the dashboard with `run.bat`, then run `run_simulator.bat` and choose 7. The simulator scans and floods only your own machine (127.0.0.1 or private addresses) and starts its own small web server on port 8080. Expect Port Scan, SYN Flood, TCP RST Burst and the five HTTP alerts.
4. **ARP spoofing:** the simulator injects it into the detection engine and sends nothing on your network.
5. **Crypto Lab:** encrypt with AES, change one character of the package, decrypt and see the integrity failure. Sign a message, edit it, verify and see the signature fail.
6. **Report:** Reports, Generate report, open it, use the layer and severity chips, sort columns, export CSV, print to PDF.
7. **Login protection:** enter a wrong password five times. The client is locked for one minute and a Layer 7 alert is raised.

### 6.1 Testing the advanced features
8. **Layer pages:** Layer Monitor, click Layer 4, click any row. The right panel shows the Ethernet, IP and TCP headers and the hex bytes.
9. **Filter:** in Packet Inspector type `tcp.flags == S and tcp.port == 80`.
10. **Devices:** open Devices and press Scan now. Phones connected to the same Wi-Fi or hotspot appear with IP, MAC and vendor.
11. **New device alert:** on Overview run the scenario "Rogue Device Joins" (Demo mode) or connect a new phone after the first scan (live).
12. **Conversations:** run the simulator, open Conversations and click a row to follow the stream.
13. **Evidence:** open an alert that has the label evidence and press View evidence packets, then Export PCAP and open it in Wireshark.
14. **Rules:** lower the Port Scan threshold to 5, save, and trigger a port scan again.

See `docs/USER_GUIDE.md` for the filter language and the hotspot setup (other devices' traffic is only visible when it passes through this computer).

## 7. Detection summary

See `docs/LAYER_MAPPING.md` for the full table. Thresholds live in `config.py`. If a demo triggers too many or too few alerts, adjust the numbers in `THRESHOLDS` and restart.

## 8. Important notes and limitations

* Run this only on networks and machines you own or are authorised to monitor.
* On Wi-Fi, Windows normally shows only your own machine's traffic, not other devices. Device discovery still works. For other devices' traffic use the Windows Mobile hotspot setup in `docs/USER_GUIDE.md`.
* Device scans send ARP, ICMP, NetBIOS and connection probes. Scan only networks you own or are authorised to test. Port scans are restricted to devices inside your own subnet.
* Frames are kept in memory only (latest 5000). Alert evidence keeps up to 12 frames per alert in the database.
* Payloads are visible in the decoder, including cleartext passwords of unencrypted protocols. Use this only on your own lab traffic.
* Traffic to 127.0.0.1 is captured only when Npcap was installed with loopback support. Capture listens on your default adapter and the Npcap loopback adapter.
* Layers 1, 5 and 6 are monitored indirectly (interface counters, TCP session tracking, TLS and cleartext analysis). The reasoning is in `docs/LAYER_MAPPING.md`.
* TLS payloads are not decrypted. Only record headers are inspected.
* Detection is rule-based, so unusual legitimate traffic can occasionally trigger an alert. Tune the thresholds.
* The dashboard listens on 127.0.0.1 only. Change the default password from the account page.
* Packet metadata is kept in SQLite and trimmed automatically. Use "Reset all data" on Overview to clear everything.
* Machine learning anomaly detection is not included in this version.
