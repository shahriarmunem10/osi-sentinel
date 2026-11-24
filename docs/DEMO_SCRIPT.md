# Suggested live demo flow (about 8 minutes)

1. Start with `run.bat` (administrator). Show the console: mode LIVE, interfaces, login.
2. Sign in. On **Overview** point out the OSI layer stack, packet rate and the Live capture indicator.
3. Open **Layer Monitor** and explain how Layers 1, 5 and 6 are covered (see `LAYER_MAPPING.md`).
4. Open a second console and run `run_simulator.bat`, choose option 1 (port scan). Switch to **Alerts** and show the Port Scan alert with its evidence.
5. Run option 3 (malicious HTTP). Show SQL injection, XSS, path traversal, command injection and scanner alerts at Layer 7.
6. Run option 2 (connection flood) and option 4 (ICMP flood). Show the Layer 4 and Layer 3 alerts.
7. Back on the dashboard use **Attack scenario lab** to trigger ARP Spoofing, DNS Tunneling and Legacy SSL/TLS, which cannot be generated safely on a real network.
8. Open **Packet Inspector**, filter by layer 7 and show the captured requests.
9. Open **Crypto Lab**: hash two almost identical messages, encrypt with AES, change one character and show the integrity failure, generate RSA keys, sign a message, edit it and show the signature fail.
10. Open **Reports**, generate a report, open it, filter by layer and severity, export CSV.

If live capture fails on the day, run `run_demo.bat`. Everything above except the real simulator traffic works the same in Demo mode.
