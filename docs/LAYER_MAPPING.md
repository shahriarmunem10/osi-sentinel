# OSI layer mapping

OSI Sentinel assigns every observation to one of the seven OSI layers. Layers 2, 3, 4 and 7 map directly to what a packet contains. Layers 1, 5 and 6 are not fully visible in a captured packet, so they are monitored through the closest observable evidence. The reasoning is given below so it can be explained during the demo.

| Layer | Data source | What is monitored | Detections (severity) |
|---|---|---|---|
| L1 Physical | psutil interface counters (not packets) | Link up or down, speed, MTU, bytes, packets, errors, drops per interface | Network Interface Down (High), Interface Errors or Drops (Medium) |
| L2 Data Link | ARP packets | IP to MAC bindings, ARP rate per MAC | ARP Spoofing (Critical), ARP Flood (Medium) |
| L3 Network | IP and ICMP headers | Echo requests, destinations per source, TTL, fragmentation flags, packet size | ICMP Flood (High), Ping Sweep (Medium), IP Fragmentation Anomaly (Medium), Oversized ICMP Packet (Medium), Suspicious Low TTL Traffic (Low) |
| L4 Transport | TCP flags and ports | SYN rate per destination port, distinct ports per source and target | SYN Flood (Critical), Port Scan (High) |
| L5 Session | TCP session control flags (SYN, FIN, RST) | Handshake completion tracking, half-open sessions, reset bursts | Half-Open Session Buildup (Medium), TCP RST Burst (Medium) |
| L6 Presentation | TLS record headers and cleartext protocol ports | Encrypted versus plaintext traffic, TLS version in the handshake, use of Telnet, FTP, POP3, IMAP | Deprecated SSL/TLS Version (Medium), Cleartext Protocol in Use (Medium) |
| L7 Application | HTTP requests, DNS queries | Request line and headers, query names and rates | SQL Injection (High), XSS (High), Path Traversal (High), Command Injection (Critical), Scanner User-Agent (Medium), Possible DNS Tunneling (Medium), DNS Query Flood (Medium), Dashboard Brute-Force Attempt (High) |

## Why Layers 1, 5 and 6 are handled this way

**Layer 1.** Bits on a wire or radio signal never reach Scapy. What an operating system does expose is the state and counters of each network adapter, so Layer 1 monitoring reads them through psutil and alerts on link loss or rising error counts.

**Layer 5.** TCP is not a session layer protocol, but a TCP connection is the practical session in the TCP/IP world. Tracking the handshake (SYN, SYN-ACK, ACK) and its teardown (FIN, RST) gives real session-level visibility. A packet is counted at Layer 5 when it carries a session control flag.

**Layer 6.** Presentation is about data representation, encryption and encoding. Without breaking encryption, the visible facts are whether a TLS record is present, which protocol version the handshake offers, and whether data travels in cleartext. The Crypto Lab page demonstrates the Layer 6 operations themselves: SHA-256, AES-256-GCM, RSA-OAEP and RSA-PSS signatures.

## How a packet is classified

A packet is counted once, at the highest layer the engine could identify: ARP is L2, plain IP or ICMP is L3, TCP or UDP is L4, TCP with SYN, FIN or RST is L5, a TLS record is L6, and HTTP, DNS or a known cleartext application protocol is L7.

## Tuning

All thresholds are in `config.py` under `THRESHOLDS`. The detection window is `WINDOW_SECONDS` (10 s) and repeated alerts of the same kind are suppressed for `ALERT_COOLDOWN` (30 s).
