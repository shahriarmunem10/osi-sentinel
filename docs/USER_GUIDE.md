# User guide for the new features

## Layer pages
Open **Layer Monitor** and click any layer card, or go to `/layer/1` to `/layer/7`.

| Layer | Page content |
|---|---|
| 1 | Adapter table (state, speed, rates, errors) and a chosen frame shown as bits, with the preamble the network card adds |
| 2 | Every captured frame with source MAC, vendor of the source MAC, destination MAC, EtherType |
| 3 | IP packets: addresses, protocol, TTL, length, IP flags |
| 4 | TCP and UDP segments: ports, flags, sequence, acknowledgment, window |
| 5 | Live TCP session table with states, plus the SYN, FIN and RST control frames |
| 6 | TLS records: version, handshake type, server name (SNI), cipher suites, and cleartext protocols |
| 7 | HTTP, DNS, DHCP, NetBIOS and SSDP messages in readable form |

Each page has a filter box, a PCAP export button, and a **Tools** tab (MAC lookup, IP information, subnet calculator, port lookup, TCP flags decoder, URL and Base64 decoder, paste-a-frame decoder).

## Breaking a frame apart
Click any row anywhere in the dashboard. The right-hand panel has three tabs:

* **Decode**: every layer with all its header fields. Click a field to highlight its bytes in the hex dump. Hex colours match the layer colours.
* **Decapsulation**: the nested boxes (frame, packet, segment, data) and the step-by-step receiving process.
* **Extract**: source and destination MAC, IP and ports, with the vendor of each MAC, and the checksum verification results.

## Filter language
Used in the Packet Inspector and in every layer page. Combine with `and`, `or`, `not` and parentheses.

| Example | Meaning |
|---|---|
| `ip == 192.168.1.5` | Packets from or to this address |
| `ip.src == 10.0.0.0/24` | Source inside a subnet |
| `tcp.port == 80` / `udp.port == 53` | Either port equals |
| `tcp.flags == S` | SYN only. Others: SA, A, PA, FA, R |
| `mac == aa:bb:cc:dd:ee:ff` / `eth.src == ...` | MAC address |
| `dns`, `http`, `tls`, `arp`, `icmp`, `tcp`, `udp` | Protocol present |
| `len > 200` | Frame length |
| `http.request.uri contains passwd` | Text inside a field |
| `tls.sni contains google` | Server name in a TLS handshake |
| `dns.qry.name contains example` | DNS query name |
| `frame contains "select"` | Text anywhere in the frame bytes |

## Devices
Press **Scan now** (or leave auto scan on). The scan sends an ARP broadcast on your own subnet, reads the ARP cache, then asks each device for its name (NetBIOS, mDNS, reverse DNS), reply time and TTL. While monitoring, DHCP, mDNS, NetBIOS and SSDP packets add more names. **Details** shows everything known and a port scan button that checks 34 common ports on that device only. New devices are marked **new** and raise a Layer 2 alert until you press **Trust**. Two devices claiming one IP are marked **IP conflict**.

**Fresh start:** press **Reset and rescan** (on the Devices or Topology page) to forget every stored device and list only what is on the network right now. **Show online devices only** hides devices that did not answer the latest scan, so old devices from previous networks disappear from the list and from the Topology map.

## Visibility rule (important for the demo)
A normal Wi-Fi adapter only receives frames addressed to this computer plus broadcasts. Therefore:

* Device discovery works on any network.
* Bandwidth, conversations and decoding of **other** devices only work when their traffic passes through this computer.

To show all connected devices' traffic: turn on **Settings, Network and internet, Mobile hotspot** in Windows 11, connect the phones to the laptop's hotspot, and give the laptop internet through USB tethering or Ethernet. Start OSI Sentinel, open Devices, choose the hotspot network in "Network to scan", and capture on the hotspot adapter with `run.bat` (or `python app.py --iface "<adapter name>"`). Use `tools\check_system.py` to see adapter names.

## Conversations
Lists every TCP, UDP and ICMP conversation with bytes in each direction. Click one to follow the stream (client data in blue, server data in red), see its frames, or export it as PCAP.

## Alerts and evidence
Alerts with the label **evidence** keep the frames that triggered them. Open an alert and press **View evidence packets**. The frames stay available even after they leave memory, and can be exported as PCAP for Wireshark.

## Rules
The **Rules** page switches each detection on or off and edits every threshold. Values are saved in `instance/settings.json`.
