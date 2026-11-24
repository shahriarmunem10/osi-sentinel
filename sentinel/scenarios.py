import os
import random
import threading
import time

ATTACKER = "192.168.56.66"
VICTIM = "192.168.56.10"
GATEWAY = "192.168.56.1"
GW_MAC = "52:54:00:aa:00:01"
EVIL_MAC = "de:ad:be:ef:66:66"


def base(**kw):
    p = {
        "ts": time.time(),
        "length": 74,
        "src": None,
        "dst": None,
        "proto": "OTHER",
        "sport": None,
        "dport": None,
        "flags": "",
        "ttl": 64,
        "frag": False,
        "arp_op": None,
        "arp_psrc": None,
        "arp_hwsrc": None,
        "icmp_type": None,
        "payload": b"",
        "dns_q": None,
    }
    p.update(kw)
    p["ts"] = time.time()
    return p


def tcp(src, dst, sport, dport, flags, payload=b"", ttl=64):
    return base(src=src, dst=dst, proto="TCP", sport=sport, dport=dport, flags=flags, payload=payload, length=54 + len(payload), ttl=ttl)


def udp(src, dst, sport, dport, payload=b"", dns_q=None):
    return base(src=src, dst=dst, proto="UDP", sport=sport, dport=dport, payload=payload, dns_q=dns_q, length=42 + len(payload))


def icmp(src, dst, itype=8, length=74, ttl=64):
    return base(src=src, dst=dst, proto="ICMP", icmp_type=itype, length=length, ttl=ttl)


def arp(op, psrc, hwsrc, pdst):
    return base(src=psrc, dst=pdst, proto="ARP", arp_op=op, arp_psrc=psrc, arp_hwsrc=hwsrc, length=42, ttl=None)


def http(src, dst, request, sport=None):
    return tcp(src, dst, sport or random.randint(40000, 60000), 80, "PA", request.encode("latin-1"))


def req(path, ua="Mozilla/5.0", method="GET"):
    return "%s %s HTTP/1.1\r\nHost: victim.local\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n" % (method, path, ua)


def s_arp_spoof(emit):
    emit(arp(2, GATEWAY, GW_MAC, VICTIM))
    time.sleep(0.3)
    for _ in range(3):
        emit(arp(2, GATEWAY, EVIL_MAC, VICTIM))
        time.sleep(0.2)


def s_arp_flood(emit):
    for i in range(60):
        emit(arp(1, ATTACKER, EVIL_MAC, "192.168.56.%d" % (i % 250 + 2)))
        time.sleep(0.01)


def s_port_scan(emit):
    for port in range(1, 41):
        emit(tcp(ATTACKER, VICTIM, 44444, port, "S"))
        emit(tcp(VICTIM, ATTACKER, port, 44444, "RA"))
        time.sleep(0.02)


def s_syn_flood(emit):
    for _ in range(160):
        emit(tcp("10.%d.%d.%d" % (random.randint(1, 250), random.randint(1, 250), random.randint(1, 250)), VICTIM, random.randint(1024, 65000), 80, "S"))
        time.sleep(0.005)


def s_icmp_flood(emit):
    for _ in range(60):
        emit(icmp(ATTACKER, VICTIM, 8))
        time.sleep(0.01)


def s_ping_sweep(emit):
    for i in range(1, 16):
        emit(icmp(ATTACKER, "192.168.56.%d" % i, 8))
        time.sleep(0.05)


def s_rst_burst(emit):
    for i in range(40):
        emit(tcp(VICTIM, ATTACKER, 80, 40000 + i, "R"))
        time.sleep(0.01)


def s_frag(emit):
    for _ in range(30):
        p = icmp(ATTACKER, VICTIM, 8, length=1500)
        p["frag"] = True
        emit(p)
        time.sleep(0.01)


def s_sqli(emit):
    emit(http(ATTACKER, VICTIM, req("/products.php?id=1%27%20OR%20%271%27=%271")))
    time.sleep(0.2)
    emit(http(ATTACKER, VICTIM, req("/search?q=1+UNION+SELECT+username,password+FROM+users--")))


def s_xss(emit):
    emit(http(ATTACKER, VICTIM, req("/comment?text=%3Cscript%3Ealert(1)%3C/script%3E")))


def s_traversal(emit):
    emit(http(ATTACKER, VICTIM, req("/download?file=../../../../etc/passwd")))


def s_cmdi(emit):
    emit(http(ATTACKER, VICTIM, req("/ping?host=8.8.8.8;cat%20/etc/passwd")))


def s_scanner(emit):
    emit(http(ATTACKER, VICTIM, req("/admin/", ua="sqlmap/1.7.2#stable (https://sqlmap.org)")))


def s_dns_tunnel(emit):
    for _ in range(3):
        label = "".join(random.choice("abcdef0123456789") for _ in range(56))
        emit(udp(ATTACKER, "8.8.8.8", 53211, 53, b"\x00" * 40, dns_q="%s.c2.example.net." % label))
        time.sleep(0.1)


def s_tls_legacy(emit):
    hello = b"\x16\x03\x00\x00\x2f\x01\x00\x00\x2b\x03\x00" + os.urandom(32)
    emit(tcp(ATTACKER, VICTIM, 50505, 443, "PA", hello))


def s_cleartext(emit):
    emit(tcp(ATTACKER, VICTIM, 50506, 23, "PA", b"login: admin\r\n"))
    time.sleep(0.2)
    emit(tcp(ATTACKER, VICTIM, 50507, 21, "PA", b"USER anonymous\r\n"))


SCENARIOS = {
    "arp_spoof": ("ARP Spoofing", 2, s_arp_spoof),
    "arp_flood": ("ARP Flood", 2, s_arp_flood),
    "ping_sweep": ("Ping Sweep", 3, s_ping_sweep),
    "icmp_flood": ("ICMP Flood", 3, s_icmp_flood),
    "frag": ("IP Fragmentation", 3, s_frag),
    "port_scan": ("Port Scan", 4, s_port_scan),
    "syn_flood": ("SYN Flood", 4, s_syn_flood),
    "rst_burst": ("TCP RST Burst", 5, s_rst_burst),
    "tls_legacy": ("Legacy SSL/TLS", 6, s_tls_legacy),
    "cleartext": ("Cleartext Protocols", 6, s_cleartext),
    "sqli": ("SQL Injection", 7, s_sqli),
    "xss": ("XSS", 7, s_xss),
    "traversal": ("Path Traversal", 7, s_traversal),
    "cmdi": ("Command Injection", 7, s_cmdi),
    "scanner": ("Scanner User-Agent", 7, s_scanner),
    "dns_tunnel": ("DNS Tunneling", 7, s_dns_tunnel),
}


def listing():
    return [{"id": k, "label": v[0], "layer": v[1]} for k, v in SCENARIOS.items()] + [{"id": "new_device", "label": "Rogue Device Joins", "layer": 2}]


def run(engine, name):
    if name == "new_device":
        threading.Thread(target=engine.devices.demo_join, daemon=True).start()
        return True
    if name == "all":
        def worker_all():
            for key, (_, _, fn) in SCENARIOS.items():
                fn(lambda p: engine.process(p, sim=True))
                time.sleep(1.2)
            engine.devices.demo_join()

        threading.Thread(target=worker_all, daemon=True).start()
        return True
    item = SCENARIOS.get(name)
    if not item:
        return False
    threading.Thread(target=lambda: item[2](lambda p: engine.process(p, sim=True)), daemon=True).start()
    return True
