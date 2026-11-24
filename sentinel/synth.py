import random

GATEWAY = "192.168.56.1"
GW_MAC = "52:54:00:aa:00:01"


def mac_for(ip):
    if ip == GATEWAY:
        return GW_MAC
    try:
        a = [int(x) for x in ip.split(".")]
        return "52:54:00:%02x:%02x:%02x" % (a[1] & 255, a[2] & 255, a[3] & 255)
    except Exception:
        return "52:54:00:00:00:01"


def build(p):
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, Raw

    if p["proto"] == "ARP":
        bc = p["arp_op"] == 1
        frame = Ether(src=p["arp_hwsrc"], dst="ff:ff:ff:ff:ff:ff" if bc else mac_for(p["dst"])) / ARP(
            op=p["arp_op"], hwsrc=p["arp_hwsrc"], psrc=p["arp_psrc"], pdst=p["dst"], hwdst="00:00:00:00:00:00" if bc else mac_for(p["dst"])
        )
        return bytes(frame)[:1600]
    ip = IP(src=p["src"], dst=p["dst"], ttl=p.get("ttl") or 64, flags="MF" if p.get("frag") else 0)
    payload = p.get("payload") or b""
    if p["proto"] == "TCP":
        l4 = TCP(sport=p["sport"], dport=p["dport"], flags=p["flags"], seq=random.randint(1, 4000000000), ack=random.randint(0, 4000000000) if "A" in p["flags"] else 0, window=64240) / Raw(payload)
    elif p["proto"] == "UDP":
        body = bytes(DNS(rd=1, qd=DNSQR(qname=p["dns_q"]))) if p.get("dns_q") else payload
        l4 = UDP(sport=p["sport"], dport=p["dport"]) / Raw(body)
    elif p["proto"] == "ICMP":
        size = max(8, (p.get("length") or 74) - 42)
        body = (bytes(range(97, 123)) * (size // 26 + 1))[:size]
        l4 = ICMP(type=p.get("icmp_type") or 8, id=random.randint(1, 60000), seq=random.randint(1, 500)) / Raw(body)
    else:
        l4 = Raw(payload)
    return bytes(Ether(src=mac_for(p["src"]), dst=mac_for(p["dst"])) / ip / l4)[:1600]
