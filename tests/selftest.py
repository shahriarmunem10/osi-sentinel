import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import config

config.DB_PATH = os.path.join(tempfile.mkdtemp(), "selftest.db")

from sentinel import db, scenarios
from sentinel.engine import Engine

EXPECTED = {
    "arp_spoof": "ARP Spoofing",
    "arp_flood": "ARP Flood",
    "ping_sweep": "Ping Sweep",
    "icmp_flood": "ICMP Flood",
    "frag": "IP Fragmentation Anomaly",
    "port_scan": "Port Scan",
    "syn_flood": "SYN Flood",
    "rst_burst": "TCP RST Burst",
    "tls_legacy": "Deprecated SSL/TLS Version",
    "cleartext": "Cleartext Protocol in Use",
    "sqli": "SQL Injection Attempt",
    "xss": "Cross-Site Scripting Attempt",
    "traversal": "Path Traversal Attempt",
    "cmdi": "Command Injection Attempt",
    "scanner": "Scanner User-Agent Detected",
    "dns_tunnel": "Possible DNS Tunneling",
}


def extra_checks():
    from sentinel import decoder, filtering, synth
    from sentinel.flows import FlowTable

    bad = 0

    def check(name, ok):
        nonlocal bad
        print("[%s] %s" % ("PASS" if ok else "FAIL", name))
        bad += 0 if ok else 1

    p = scenarios.tcp("10.0.0.1", "10.0.0.2", 40000, 80, "PA", b"GET /x HTTP/1.1\r\nHost: a\r\n\r\n")
    raw = synth.build(p)
    res = decoder.parse(raw)
    check("decoder finds Ethernet, IPv4, TCP, HTTP", [l["name"] for l in res["layers"]] == ["Ethernet II", "IPv4", "TCP", "HTTP"])
    check("decoder extracts MAC and IP addresses", "Source MAC" in res["extract"] and res["extract"]["Source IP"] == "10.0.0.1")
    check("IP header checksum is valid", any(f["n"] == "Header checksum" and f["d"] == "valid" for f in res["layers"][1]["f"]))
    fl = filtering.compile_filter("ip == 10.0.0.1 and tcp.port == 80 and http")
    check("packet filter matches", bool(fl(res["flat"], raw)))
    check("packet filter rejects", not filtering.compile_filter("udp or arp")(res["flat"], raw))
    ft = FlowTable()
    for flags, s, d, sp, dp in [("S", "1.1.1.1", "2.2.2.2", 5000, 80), ("SA", "2.2.2.2", "1.1.1.1", 80, 5000), ("A", "1.1.1.1", "2.2.2.2", 5000, 80)]:
        ft.update(scenarios.tcp(s, d, sp, dp, flags), 1)
    check("TCP session reaches ESTABLISHED", ft.listing()[0]["state"] == "ESTABLISHED")
    engine = Engine()
    engine.reset()
    scenarios.SCENARIOS["port_scan"][2](lambda q: engine.process(q, sim=True))
    row = db.query("SELECT evidence FROM alerts WHERE threat='Port Scan'")
    check("alert stores evidence frames", bool(row) and bool(row[0]["evidence"]))
    return bad


def main():
    db.init()
    engine = Engine()
    failed = 0
    for name, threat in EXPECTED.items():
        engine.reset()
        item = scenarios.SCENARIOS[name]
        item[2](lambda p: engine.process(p, sim=True))
        rows = db.query("SELECT threat FROM alerts")
        hit = any(r["threat"].startswith(threat) for r in rows)
        print("[%s] %-12s -> %s" % ("PASS" if hit else "FAIL", name, threat))
        failed += 0 if hit else 1
    engine.reset()
    from sentinel import scenarios as sc

    quiet = 0
    for _ in range(300):
        import random

        engine.process(sc.tcp("192.168.1.5", "142.250.190.46", random.randint(30000, 60000), 443, "PA", b"\x17\x03\x03\x00\x40" + os.urandom(40)))
        engine.process(sc.http("192.168.1.5", "93.184.216.34", sc.req("/index.html")))
    quiet = db.query("SELECT COUNT(*) c FROM alerts")[0]["c"]
    print("[%s] normal traffic produced %d false alerts" % ("PASS" if quiet == 0 else "FAIL", quiet))
    failed += 0 if quiet == 0 else 1
    failed += extra_checks()
    print("\nAll checks passed." if not failed else "\n%d check(s) failed." % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
