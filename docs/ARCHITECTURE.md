# Architecture

```
 +---------------------+      +----------------------+
 |  Npcap + Scapy      |      |  Demo traffic        |
 |  (live capture)     |      |  generator / scenario|
 +----------+----------+      +----------+-----------+
            |  normalised packet dict    |
            +-------------+--------------+
                          v
                 +------------------+        +-----------------+
                 |  Engine          | <----- | psutil (L1)     |
                 |  classify layer  |        | interface stats |
                 |  counters        |        +-----------------+
                 +--------+---------+
                          v
                 +------------------+
                 |  Detectors       |  sliding windows, cooldown
                 |  L2 .. L7 rules  |
                 +--------+---------+
                          v
                 +------------------+
                 |  SQLite          |  alerts, packet metadata, stats
                 +--------+---------+
                          v
                 +------------------+       +-------------------------+
                 |  Flask app       | ----> | Dashboard (HTML, JS,    |
                 |  login, JSON API |       | Chart.js, polling 2 s)  |
                 +--------+---------+       +-------------------------+
                          |
                          +--> Crypto Lab (cryptography library)
                          +--> Report builder -> single interactive HTML file
```

## Modules

| File | Purpose |
|---|---|
| `app.py` | Flask application, authentication, CSRF protection, JSON API, command line options |
| `config.py` | Ports, thresholds, default admin account, footer text, persistent secret and API token |
| `sentinel/capture.py` | Scapy sniffer thread and conversion of Scapy packets to a plain dictionary |
| `sentinel/engine.py` | Layer classification, counters, rate calculation, packet batching to the database |
| `sentinel/detectors.py` | All rule-based detectors with sliding time windows |
| `sentinel/interfaces.py` | Layer 1 interface monitor based on psutil |
| `sentinel/scenarios.py` | Synthetic attack scenarios used by the demo lab and the ARP simulator |
| `sentinel/demo.py` | Normal background traffic for Demo mode |
| `sentinel/crypto_lab.py` | SHA-256, AES-256-GCM, RSA-OAEP, RSA-PSS |
| `sentinel/report.py` | Builds the interactive HTML report from the database |
| `sentinel/db.py` | SQLite access with a lock and size pruning |
| `sentinel/decoder.py` | Byte-accurate decoder (Ethernet, ARP, IPv4/IPv6, ICMP, TCP, UDP, DNS, DHCP, NBNS, SSDP, HTTP, TLS) with checksum checks |
| `sentinel/synth.py` | Builds real Ethernet frames for demo and scenario traffic |
| `sentinel/filtering.py` | Wireshark-style display filter language |
| `sentinel/flows.py` | Conversations, TCP session states, stream chunks |
| `sentinel/devices.py` | ARP scan, passive learning, name discovery, port scan, per-device bandwidth |
| `sentinel/rules.py` | Rule metadata and threshold limits for the Rules page |
| `sentinel/web_extra.py` | API for layer pages, decoder, flows, devices, rules, tools, PCAP export |
| `tools/attack_simulator.py` | Real localhost traffic generator for lab testing |

## Design decisions

* **Normalised packets.** Capture and demo both produce the same dictionary, so the detectors are independent of Scapy and can be tested without any network.
* **Polling instead of WebSockets.** The dashboard refreshes every two seconds. This is simpler and cannot break during a live demo.
* **Offline friendly.** Chart.js is bundled in `static/`. Reports embed Chart.js so they open anywhere without internet.
* **Fallback.** If live capture cannot start, `--mode auto` switches to Demo mode and shows why.
* **Security of the dashboard itself.** Passwords are stored as PBKDF2-SHA256 hashes, sessions are HttpOnly cookies, every POST needs a CSRF token, five wrong passwords lock the client IP for one minute and raise a Layer 7 alert, and the server listens on 127.0.0.1 only.
* **Privacy.** Only packet metadata is stored. Payloads are inspected in memory and discarded.
