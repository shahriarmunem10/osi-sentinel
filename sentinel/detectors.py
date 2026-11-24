import re
from collections import Counter, deque
from urllib.parse import unquote_plus

import config

T = config.THRESHOLDS

SQLI = re.compile(
    r"(union\s+(all\s+)?select|\bor\s+1\s*=\s*1|'\s*or\s*'|'\s*or\s+\d|sleep\s*\(|benchmark\s*\(|information_schema|;\s*drop\s+table|xp_cmdshell)",
    re.I,
)
XSS = re.compile(r"(<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img[^>]*src|<\s*svg[^>]*onload|alert\s*\()", re.I)
TRAVERSAL = re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|boot\.ini|win\.ini|c:\\windows)", re.I)
CMDI = re.compile(r"(;|\|\||&&|\|)\s*(cat|ls|whoami|wget|curl|nc|netcat|bash|powershell|cmd(\.exe)?)\b", re.I)
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|hydra|dirbuster|gobuster|wfuzz|acunetix|nessus)", re.I)
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")


class Detectors:
    def __init__(self, alert):
        self.alert = alert
        self.arp_table = {}
        self.arp_rate = {}
        self.icmp_rate = {}
        self.icmp_dsts = {}
        self.frag = {}
        self.low_ttl = {}
        self.syn_dst = {}
        self.scan = {}
        self.rst = {}
        self.dns = {}
        self.half = {}
        self.half_cnt = Counter()
        self.last = {}
        self.m = Counter()

    def _push(self, store, key, ts, item=None):
        d = store.get(key)
        if d is None:
            d = store[key] = deque(maxlen=5000)
        d.append((ts, item))
        cut = ts - T["window_seconds"]
        while d and d[0][0] < cut:
            d.popleft()
        return d

    def _fire(self, key, ts, layer, threat, severity, src, dst, detail):
        if config.DISABLED_THREATS and any(threat.startswith(x) for x in config.DISABLED_THREATS):
            return False
        if ts - self.last.get(key, 0) < T["alert_cooldown"]:
            return False
        self.last[key] = ts
        self.alert(layer, threat, severity, src, dst, detail)
        return True

    def handle(self, p):
        ts = p["ts"]
        proto = p["proto"]
        if proto == "ARP":
            self._arp(p, ts)
            return
        src, dst = p["src"], p["dst"]
        ttl = p.get("ttl")
        if ttl is not None and ttl <= T["low_ttl"]:
            d = self._push(self.low_ttl, src, ts)
            if len(d) >= T["low_ttl_count"]:
                self._fire(("ttl", src), ts, 3, "Suspicious Low TTL Traffic", "Low", src, dst,
                           "%d packets with TTL <= %d from %s (possible traceroute or evasion)" % (len(d), T["low_ttl"], src))
        if p.get("frag"):
            self.m["frag"] += 1
            d = self._push(self.frag, src, ts)
            if len(d) >= T["frag"]:
                self._fire(("frag", src), ts, 3, "IP Fragmentation Anomaly", "Medium", src, dst,
                           "%d fragmented packets from %s within %ds" % (len(d), src, T["window_seconds"]))
        if proto == "ICMP":
            self._icmp(p, ts)
        elif proto == "TCP":
            self._tcp(p, ts)
        app = p.get("app")
        if app == "HTTP":
            self._http(p, ts)
        elif app == "TLS":
            self._tls(p, ts)
        elif app == "DNS":
            self._dns(p, ts)
        elif app in ("FTP", "Telnet", "POP3", "IMAP"):
            self.m["cleartext"] += 1
            self._fire(("clear", app, src, dst), ts, 6, "Cleartext Protocol in Use (%s)" % app, "Medium", src, dst,
                       "%s traffic without encryption between %s and %s" % (app, src, dst))

    def _arp(self, p, ts):
        self.m["arp"] += 1
        ip, mac = p["arp_psrc"], p["arp_hwsrc"]
        if ip and ip != "0.0.0.0" and mac:
            old = self.arp_table.get(ip)
            if old and old != mac:
                self._fire(("arp", ip), ts, 2, "ARP Spoofing", "Critical", ip, p["dst"],
                           "IP %s changed MAC address from %s to %s" % (ip, old, mac))
            self.arp_table[ip] = mac
        if mac:
            d = self._push(self.arp_rate, mac, ts)
            if len(d) >= T["arp_flood"]:
                self._fire(("arpflood", mac), ts, 2, "ARP Flood", "Medium", ip, p["dst"],
                           "%d ARP packets from %s within %ds" % (len(d), mac, T["window_seconds"]))

    def _icmp(self, p, ts):
        src, dst = p["src"], p["dst"]
        if p.get("icmp_type") != 8:
            return
        self.m["icmp_echo"] += 1
        d = self._push(self.icmp_rate, src, ts)
        if len(d) >= T["icmp_flood"]:
            self._fire(("icmpflood", src), ts, 3, "ICMP Flood", "High", src, dst,
                       "%d echo requests from %s within %ds" % (len(d), src, T["window_seconds"]))
        d2 = self._push(self.icmp_dsts, src, ts, dst)
        distinct = len({i for _, i in d2})
        if distinct >= T["ping_sweep"]:
            self._fire(("sweep", src), ts, 3, "Ping Sweep", "Medium", src, dst,
                       "%s sent echo requests to %d different hosts within %ds" % (src, distinct, T["window_seconds"]))
        if p["length"] >= T["big_icmp"]:
            self._fire(("bigicmp", src), ts, 3, "Oversized ICMP Packet", "Medium", src, dst,
                       "ICMP packet of %d bytes from %s" % (p["length"], src))

    def _drop_half(self, key):
        v = self.half.pop(key, None)
        if v:
            self.half_cnt[v[1]] -= 1
            if self.half_cnt[v[1]] <= 0:
                del self.half_cnt[v[1]]

    def _tcp(self, p, ts):
        f = p["flags"]
        src, dst, sp, dp = p["src"], p["dst"], p["sport"], p["dport"]
        key = (src, sp, dst, dp)
        rkey = (dst, dp, src, sp)
        if "S" in f and "A" not in f:
            self.m["syn"] += 1
            d = self._push(self.syn_dst, (dst, dp), ts, src)
            if len(d) >= T["syn_flood"]:
                self._fire(("synflood", dst, dp), ts, 4, "SYN Flood", "Critical", src, "%s:%s" % (dst, dp),
                           "%d SYN packets towards %s:%s within %ds" % (len(d), dst, dp, T["window_seconds"]))
            d2 = self._push(self.scan, (src, dst), ts, dp)
            ports = len({i for _, i in d2})
            if ports >= T["port_scan"]:
                self._fire(("scan", src, dst), ts, 4, "Port Scan", "High", src, dst,
                           "%s probed %d different ports on %s within %ds" % (src, ports, dst, T["window_seconds"]))
            if key not in self.half:
                self.half[key] = (ts, dst)
                self.half_cnt[dst] += 1
            if self.half_cnt[dst] >= T["half_open"]:
                self._fire(("half", dst), ts, 5, "Half-Open Session Buildup", "Medium", src, dst,
                           "%d TCP sessions towards %s never completed the handshake" % (self.half_cnt[dst], dst))
        elif "R" in f:
            self._drop_half(key)
            self._drop_half(rkey)
            d = self._push(self.rst, src, ts)
            if len(d) >= T["rst_burst"]:
                self._fire(("rst", src), ts, 5, "TCP RST Burst", "Medium", src, dst,
                           "%d TCP reset packets from %s within %ds" % (len(d), src, T["window_seconds"]))
        elif "F" in f:
            self._drop_half(key)
            self._drop_half(rkey)
        elif "A" in f:
            self._drop_half(key)

    def _http(self, p, ts):
        text = p.get("http") or ""
        if not text.startswith(HTTP_METHODS):
            return
        self.m["http_req"] += 1
        src, dst = p["src"], p["dst"]
        decoded = unquote_plus(unquote_plus(text))
        line = text.split("\r\n", 1)[0][:140]
        for rx, name, sev in (
            (SQLI, "SQL Injection Attempt", "High"),
            (XSS, "Cross-Site Scripting Attempt", "High"),
            (TRAVERSAL, "Path Traversal Attempt", "High"),
            (CMDI, "Command Injection Attempt", "Critical"),
        ):
            if rx.search(decoded):
                self.m["http_bad"] += 1
                self._fire((name, src), ts, 7, name, sev, src, dst, "Request: %s" % line)
        ua = re.search(r"user-agent:\s*([^\r\n]+)", text, re.I)
        if ua and SCANNER_UA.search(ua.group(1)):
            self.m["http_bad"] += 1
            self._fire(("ua", src), ts, 7, "Scanner User-Agent Detected", "Medium", src, dst,
                       "User-Agent: %s" % ua.group(1)[:100])

    def _tls(self, p, ts):
        pl = p["payload"]
        self.m["tls_records"] += 1
        if len(pl) < 5:
            return
        old = pl[2] == 0
        if pl[0] == 22 and len(pl) > 10 and pl[5] == 1 and pl[9] == 3 and pl[10] <= 2:
            old = True
        if old:
            self._fire(("tls", p["src"], p["dst"]), ts, 6, "Deprecated SSL/TLS Version", "Medium", p["src"], p["dst"],
                       "Handshake offering SSLv3/TLS 1.0/1.1 observed between %s and %s" % (p["src"], p["dst"]))

    def _dns(self, p, ts):
        self.m["dns"] += 1
        src = p["src"]
        q = p.get("dns_q") or ""
        labels = q.strip(".").split(".") if q else []
        if q and (len(q) >= T["dns_long"] or any(len(x) >= T["dns_label"] for x in labels)):
            self._fire(("dnstun", src), ts, 7, "Possible DNS Tunneling", "Medium", src, p["dst"],
                       "Unusually long query name (%d chars): %s" % (len(q), q[:70]))
        d = self._push(self.dns, src, ts)
        if len(d) >= T["dns_flood"]:
            self._fire(("dnsflood", src), ts, 7, "DNS Query Flood", "Medium", src, p["dst"],
                       "%d DNS queries from %s within %ds" % (len(d), src, T["window_seconds"]))

    def sweep(self, now):
        cut = now - T["window_seconds"]
        for store in (self.arp_rate, self.icmp_rate, self.icmp_dsts, self.frag, self.low_ttl, self.syn_dst, self.scan, self.rst, self.dns):
            for k in list(store.keys()):
                d = store[k]
                while d and d[0][0] < cut:
                    d.popleft()
                if not d:
                    del store[k]
        for k, (t, dst) in list(self.half.items()):
            if now - t > 15:
                self._drop_half(k)
        for k in list(self.last.keys()):
            if now - self.last[k] > T["alert_cooldown"] * 4:
                del self.last[k]
        self.m["half_open"] = sum(self.half_cnt.values())
        self.m["arp_entries"] = len(self.arp_table)
