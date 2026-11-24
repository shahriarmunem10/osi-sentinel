import time

import config


def from_scapy(pkt):
    from scapy.all import ARP, ICMP, IP, TCP, UDP, DNSQR, Ether, IPv6

    p = {
        "ts": time.time(),
        "length": len(pkt),
        "src": None,
        "dst": None,
        "proto": "OTHER",
        "sport": None,
        "dport": None,
        "flags": "",
        "ttl": None,
        "frag": False,
        "arp_op": None,
        "arp_psrc": None,
        "arp_hwsrc": None,
        "icmp_type": None,
        "payload": b"",
        "dns_q": None,
        "raw": bytes(pkt)[:1600],
        "link": "ethernet" if pkt.haslayer(Ether) else "null" if pkt.__class__.__name__ == "Loopback" else "ip",
    }
    if pkt.haslayer(ARP):
        a = pkt[ARP]
        p.update(proto="ARP", src=a.psrc, dst=a.pdst, arp_op=int(a.op), arp_psrc=a.psrc, arp_hwsrc=a.hwsrc)
        return p
    if pkt.haslayer(IP):
        ip = pkt[IP]
        p["ttl"] = int(ip.ttl)
        p["frag"] = "MF" in str(ip.flags) or int(ip.frag) > 0
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        p["ttl"] = int(ip.hlim)
    else:
        return None
    p["src"], p["dst"] = str(ip.src), str(ip.dst)
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        p.update(proto="TCP", sport=int(t.sport), dport=int(t.dport), flags=str(t.flags), payload=bytes(t.payload)[:2000])
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        p.update(proto="UDP", sport=int(u.sport), dport=int(u.dport), payload=bytes(u.payload)[:2000])
        if pkt.haslayer(DNSQR):
            try:
                p["dns_q"] = pkt[DNSQR].qname.decode("latin-1", errors="replace")
            except Exception:
                p["dns_q"] = ""
    elif pkt.haslayer(ICMP):
        p.update(proto="ICMP", icmp_type=int(pkt[ICMP].type))
    else:
        p["proto"] = "IP"
    return p


class Capture:
    def __init__(self, engine, iface=None):
        self.engine = engine
        self.iface = iface
        self.error = None
        self.description = ""
        self.sniffer = None
        self._start()

    def _resolve(self):
        from scapy.all import conf

        if self.iface and self.iface != "auto":
            names = [x.strip() for x in str(self.iface).split(",") if x.strip()]
            return (names if len(names) > 1 else names[0]), ", ".join(names)
        found = []
        names = []
        try:
            found.append(conf.iface)
            names.append(str(getattr(conf.iface, "name", conf.iface)))
        except Exception:
            pass
        try:
            for i in conf.ifaces.values():
                n = str(getattr(i, "name", "") or getattr(i, "description", ""))
                if "loopback" in n.lower() or n == "lo":
                    if i not in found:
                        found.append(i)
                        names.append(n)
        except Exception:
            pass
        if not found:
            return None, "default"
        return (found if len(found) > 1 else found[0]), ", ".join(names)

    def _start(self):
        try:
            from scapy.all import AsyncSniffer

            target, desc = self._resolve()
            self.description = desc
            kwargs = {"prn": self._handle, "store": False}
            if target is not None:
                kwargs["iface"] = target
            self.sniffer = AsyncSniffer(**kwargs)
            self.sniffer.start()
            for _ in range(20):
                time.sleep(0.15)
                if self.sniffer.exception is not None:
                    raise self.sniffer.exception
                if self.sniffer.running:
                    break
            if self.sniffer.exception is not None:
                raise self.sniffer.exception
        except Exception as exc:
            self.error = "%s: %s" % (type(exc).__name__, exc)

    def _handle(self, pkt):
        try:
            p = from_scapy(pkt)
            if p is None:
                return
            if config.DASHBOARD_PORT_IGNORE and p["proto"] == "TCP":
                if config.PORT in (p["sport"], p["dport"]) and p["src"] in ("127.0.0.1", "::1") and p["dst"] in ("127.0.0.1", "::1"):
                    return
            self.engine.process(p)
        except Exception:
            pass

    def stop(self):
        try:
            if self.sniffer is not None and self.sniffer.running:
                self.sniffer.stop()
        except Exception:
            pass
