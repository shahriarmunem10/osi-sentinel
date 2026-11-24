import base64
import ipaddress
import socket
import struct

ETHERTYPES = {0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "802.1Q VLAN", 0x88CC: "LLDP", 0x888E: "EAPOL"}
IP_PROTOS = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 58: "ICMPv6"}
ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 5: "Redirect", 8: "Echo request", 11: "Time exceeded", 30: "Traceroute"}
TCP_FLAGS = [("FIN", 0x01, "F"), ("SYN", 0x02, "S"), ("RST", 0x04, "R"), ("PSH", 0x08, "P"), ("ACK", 0x10, "A"), ("URG", 0x20, "U"), ("ECE", 0x40, "E"), ("CWR", 0x80, "C")]
SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP server", 68: "DHCP client", 80: "HTTP",
    110: "POP3", 123: "NTP", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 587: "SMTP submission", 993: "IMAPS", 995: "POP3S", 1900: "SSDP/UPnP", 3306: "MySQL", 3389: "RDP",
    5000: "Dashboard / UPnP", 5353: "mDNS", 5432: "PostgreSQL", 5900: "VNC", 8008: "Chromecast HTTP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}
TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
TLS_RECORDS = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data"}
TLS_HS = {1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket", 11: "Certificate", 12: "Server Key Exchange", 14: "Server Hello Done", 16: "Client Key Exchange", 20: "Finished"}
CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256", 0xC02F: "ECDHE-RSA-AES128-GCM-SHA256", 0xC02C: "ECDHE-ECDSA-AES256-GCM-SHA384",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384", 0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305", 0xCCA9: "ECDHE-ECDSA-CHACHA20-POLY1305",
    0x009C: "RSA-AES128-GCM-SHA256", 0x002F: "RSA-AES128-SHA", 0x0035: "RSA-AES256-SHA", 0x000A: "RSA-3DES-EDE-SHA",
}
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}
DHCP_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
HTTP_STARTS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/")
CLEAR = {21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP"}


def mac_str(b):
    return ":".join("%02x" % x for x in b)


def mac_kind(b):
    if all(x == 0xFF for x in b):
        return "Broadcast"
    kind = "Multicast" if b[0] & 1 else "Unicast"
    scope = "locally administered (random or virtual)" if b[0] & 2 else "globally unique (assigned to a manufacturer)"
    return "%s, %s" % (kind, scope)


def csum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ascii_preview(b, n=60):
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b[:n])


class _P:
    def __init__(self, raw):
        self.raw = raw
        self.layers = []
        self.flat = {}
        self.protos = []
        self.info = ""
        self.end = len(raw)
        self.link = "ethernet"

    def layer(self, osi, name, off, ln):
        L = {"osi": osi, "name": name, "o": off, "l": ln, "s": "", "f": []}
        self.layers.append(L)
        return L

    def add(self, L, n, v, o, l, d=""):
        L["f"].append({"n": n, "v": str(v), "o": o, "l": l, "d": d})

    def proto(self, name):
        if name not in self.protos:
            self.protos.append(name)
        self.flat[name] = 1


def detect_link(raw):
    if len(raw) >= 14 and struct.unpack("!H", raw[12:14])[0] in ETHERTYPES:
        return "ethernet"
    if len(raw) > 4 and raw[:4] in (b"\x02\x00\x00\x00", b"\x00\x00\x00\x02", b"\x17\x00\x00\x00", b"\x18\x00\x00\x00", b"\x1e\x00\x00\x00") and raw[4] >> 4 in (4, 6):
        return "null"
    if raw and raw[0] >> 4 in (4, 6):
        return "ip"
    return "ethernet"


def parse(raw, link=None):
    p = _P(raw)
    try:
        p.link = link or detect_link(raw)
        if p.link == "ethernet":
            _ethernet(p, 0)
        elif p.link == "null":
            _null(p)
        else:
            _ip_any(p, 0)
    except Exception as exc:
        p.info = (p.info + " " if p.info else "") + "(decode stopped: %s)" % exc
    return _result(p)


def _top(p):
    f = p.flat
    if f.get("tls"):
        return "TLS", 6
    for name, label in (("http", "HTTP"), ("mdns", "mDNS"), ("dns", "DNS"), ("dhcp", "DHCP"), ("nbns", "NBNS"), ("ssdp", "SSDP")):
        if f.get(name):
            return label, 7
    if f.get("app.cleartext"):
        return f["app.cleartext"], 7
    if f.get("tcp"):
        flags = f.get("tcp.flags", "")
        return "TCP", 5 if any(c in flags for c in "SFR") else 4
    if f.get("udp"):
        return "UDP", 4
    if f.get("icmp"):
        return "ICMP", 3
    if f.get("arp"):
        return "ARP", 2
    if f.get("ip") or f.get("ipv6"):
        return "IP", 3
    return "Frame", 2


def _result(p):
    label, layer = _top(p)
    p.flat["proto"] = label
    p.flat["frame.len"] = len(p.raw)
    p.flat["frame.layer"] = layer
    if p.link == "ethernet":
        p.flat["eth"] = 1
    ext = {}
    f = p.flat

    def pick(*keys):
        for k in keys:
            v = f.get(k)
            if v not in (None, "", []):
                return v if not isinstance(v, list) else v[0]
        return None

    ext["Source MAC"] = f.get("eth.src")
    ext["Destination MAC"] = f.get("eth.dst")
    ext["Source IP"] = pick("ip.src", "arp.src.ip")
    ext["Destination IP"] = pick("ip.dst", "arp.dst.ip")
    ext["Protocol"] = label
    ext["Source Port"] = pick("tcp.srcport", "udp.srcport")
    ext["Destination Port"] = pick("tcp.dstport", "udp.dstport")
    ext["TTL"] = f.get("ip.ttl")
    ext["Frame length"] = len(p.raw)
    return {
        "link": p.link,
        "length": len(p.raw),
        "layers": p.layers,
        "flat": p.flat,
        "protos": p.protos,
        "info": p.info,
        "proto": label,
        "top_layer": layer,
        "hex": p.raw.hex(),
        "end": p.end,
        "extract": {k: v for k, v in ext.items() if v not in (None, "")},
    }


def breakdown(res):
    out = []
    for L in res["layers"]:
        start = L["o"] + L["l"]
        out.append({"osi": L["osi"], "name": L["name"], "hdr": [L["o"], L["l"]], "payload": [start, max(0, res["end"] - start)], "s": L["s"]})
    return out


def _ethernet(p, off):
    raw = p.raw
    if len(raw) < off + 14:
        return
    dst, src = raw[off:off + 6], raw[off + 6:off + 12]
    et = struct.unpack("!H", raw[off + 12:off + 14])[0]
    hl = 14
    L = p.layer(2, "Ethernet II", off, 14)
    p.add(L, "Destination MAC", mac_str(dst), off, 6, mac_kind(dst))
    p.add(L, "Source MAC", mac_str(src), off + 6, 6, mac_kind(src))
    p.flat["eth.src"], p.flat["eth.dst"] = mac_str(src), mac_str(dst)
    p.flat["eth.addr"] = [mac_str(src), mac_str(dst)]
    if et == 0x8100 and len(raw) >= off + 18:
        tci, et = struct.unpack("!HH", raw[off + 14:off + 18])
        p.add(L, "VLAN priority", tci >> 13, off + 14, 2)
        p.add(L, "VLAN ID", tci & 0xFFF, off + 14, 2)
        hl = 18
        L["l"] = 18
    p.add(L, "EtherType", "0x%04x" % et, off + hl - 2, 2, ETHERTYPES.get(et, "unknown"))
    p.flat["eth.type"] = "0x%04x" % et
    L["s"] = "%s -> %s" % (mac_str(src), mac_str(dst))
    nxt = off + hl
    if et == 0x0800:
        _ipv4(p, nxt)
    elif et == 0x86DD:
        _ipv6(p, nxt)
    elif et == 0x0806:
        _arp(p, nxt)
    else:
        p.info = "EtherType 0x%04x" % et
        _data(p, nxt, len(p.raw))


def _null(p):
    fam = struct.unpack("<I", p.raw[:4])[0]
    L = p.layer(2, "Null/Loopback header", 0, 4)
    p.add(L, "Address family", fam, 0, 4, "IPv4" if fam == 2 else "IPv6")
    L["s"] = "loopback"
    p.flat["eth.src"] = p.flat["eth.dst"] = "loopback"
    _ip_any(p, 4)


def _ip_any(p, off):
    if len(p.raw) <= off:
        return
    ver = p.raw[off] >> 4
    if ver == 4:
        _ipv4(p, off)
    elif ver == 6:
        _ipv6(p, off)


def _ipv4(p, off):
    raw = p.raw
    if len(raw) < off + 20:
        return
    ihl = (raw[off] & 0xF) * 4
    tos = raw[off + 1]
    tl, ident, ff = struct.unpack("!HHH", raw[off + 2:off + 8])
    ttl, proto, ck = raw[off + 8], raw[off + 9], struct.unpack("!H", raw[off + 10:off + 12])[0]
    src, dst = socket.inet_ntoa(raw[off + 12:off + 16]), socket.inet_ntoa(raw[off + 16:off + 20])
    L = p.layer(3, "IPv4", off, ihl)
    flags = []
    if ff & 0x4000:
        flags.append("DF")
    if ff & 0x2000:
        flags.append("MF")
    frag_off = (ff & 0x1FFF) * 8
    valid = csum(raw[off:off + ihl]) == 0 if len(raw) >= off + ihl else None
    p.add(L, "Version", 4, off, 1)
    p.add(L, "Header length", "%d bytes" % ihl, off, 1, "IHL=%d" % (ihl // 4))
    p.add(L, "Type of service", "0x%02x" % tos, off + 1, 1, "DSCP %d, ECN %d" % (tos >> 2, tos & 3))
    p.add(L, "Total length", tl, off + 2, 2)
    p.add(L, "Identification", "0x%04x" % ident, off + 4, 2)
    p.add(L, "Flags", ",".join(flags) or "none", off + 6, 2, "DF = do not fragment, MF = more fragments")
    p.add(L, "Fragment offset", frag_off, off + 6, 2)
    p.add(L, "Time to live", ttl, off + 8, 1, "hops left before the packet is dropped")
    p.add(L, "Protocol", proto, off + 9, 1, IP_PROTOS.get(proto, "unknown"))
    p.add(L, "Header checksum", "0x%04x" % ck, off + 10, 2, "valid" if valid else ("invalid (possible checksum offload)" if valid is False else "not verifiable"))
    p.add(L, "Source IP", src, off + 12, 4)
    p.add(L, "Destination IP", dst, off + 16, 4)
    L["s"] = "%s -> %s" % (src, dst)
    f = p.flat
    f.update({"ip.src": src, "ip.dst": dst, "ip.addr": [src, dst], "ip.ttl": ttl, "ip.proto": proto, "ip.len": tl, "ip.id": ident,
              "ip.flags": ",".join(flags), "ip.frag": 1 if (ff & 0x2000 or frag_off) else 0, "ip.version": 4, "ip.hdr_len": ihl})
    p.proto("ip")
    end = min(len(raw), off + tl) if tl >= ihl else len(raw)
    complete = len(raw) >= off + tl
    p.end = end
    pay = off + ihl
    if frag_off > 0:
        p.info = "IP fragment (offset %d)" % frag_off
        _data(p, pay, end)
        return
    ctx = (raw[off + 12:off + 16], raw[off + 16:off + 20], proto, complete)
    if proto == 6:
        _tcp(p, pay, end, ctx)
    elif proto == 17:
        _udp(p, pay, end, ctx)
    elif proto == 1:
        _icmp(p, pay, end)
    else:
        p.info = IP_PROTOS.get(proto, "protocol %d" % proto)
        _data(p, pay, end)


def _ipv6(p, off):
    raw = p.raw
    if len(raw) < off + 40:
        return
    vtf, plen, nh, hl = struct.unpack("!IHBB", raw[off:off + 8])
    src, dst = str(ipaddress.IPv6Address(raw[off + 8:off + 24])), str(ipaddress.IPv6Address(raw[off + 24:off + 40]))
    L = p.layer(3, "IPv6", off, 40)
    p.add(L, "Version", 6, off, 1)
    p.add(L, "Traffic class", (vtf >> 20) & 0xFF, off, 2)
    p.add(L, "Flow label", "0x%05x" % (vtf & 0xFFFFF), off + 1, 3)
    p.add(L, "Payload length", plen, off + 4, 2)
    p.add(L, "Next header", nh, off + 6, 1, IP_PROTOS.get(nh, "unknown"))
    p.add(L, "Hop limit", hl, off + 7, 1)
    p.add(L, "Source IP", src, off + 8, 16)
    p.add(L, "Destination IP", dst, off + 24, 16)
    L["s"] = "%s -> %s" % (src, dst)
    p.flat.update({"ip.src": src, "ip.dst": dst, "ip.addr": [src, dst], "ip.ttl": hl, "ip.proto": nh, "ip.len": plen, "ip.version": 6, "ip.frag": 0})
    p.proto("ipv6")
    p.proto("ip")
    end = min(len(raw), off + 40 + plen)
    p.end = end
    ctx = (None, None, nh, False)
    if nh == 6:
        _tcp(p, off + 40, end, ctx)
    elif nh == 17:
        _udp(p, off + 40, end, ctx)
    elif nh == 58 and end > off + 40:
        L2 = p.layer(3, "ICMPv6", off + 40, min(4, end - off - 40))
        p.add(L2, "Type", raw[off + 40], off + 40, 1)
        p.flat["icmp"] = 1
        p.flat["icmp.type"] = raw[off + 40]
        p.info = "ICMPv6 type %d" % raw[off + 40]
    else:
        _data(p, off + 40, end)


def _arp(p, off):
    raw = p.raw
    if len(raw) < off + 28:
        return
    htype, ptype, hl, pl, op = struct.unpack("!HHBBH", raw[off:off + 8])
    smac, sip, tmac, tip = raw[off + 8:off + 14], socket.inet_ntoa(raw[off + 14:off + 18]), raw[off + 18:off + 24], socket.inet_ntoa(raw[off + 24:off + 28])
    L = p.layer(2, "ARP", off, 28)
    p.add(L, "Hardware type", htype, off, 2, "Ethernet" if htype == 1 else "")
    p.add(L, "Protocol type", "0x%04x" % ptype, off + 2, 2, "IPv4" if ptype == 0x0800 else "")
    p.add(L, "Hardware size", hl, off + 4, 1)
    p.add(L, "Protocol size", pl, off + 5, 1)
    p.add(L, "Operation", op, off + 6, 2, "request (who-has)" if op == 1 else "reply (is-at)" if op == 2 else "")
    p.add(L, "Sender MAC", mac_str(smac), off + 8, 6)
    p.add(L, "Sender IP", sip, off + 14, 4)
    p.add(L, "Target MAC", mac_str(tmac), off + 18, 6)
    p.add(L, "Target IP", tip, off + 24, 4)
    p.flat.update({"arp.op": op, "arp.src.mac": mac_str(smac), "arp.src.ip": sip, "arp.dst.mac": mac_str(tmac), "arp.dst.ip": tip})
    p.proto("arp")
    p.info = "Who has %s? Tell %s" % (tip, sip) if op == 1 else "%s is at %s" % (sip, mac_str(smac))
    L["s"] = p.info
    p.end = off + 28


def _tcp(p, off, end, ctx):
    raw = p.raw
    if end - off < 20 or len(raw) < off + 20:
        return
    sp, dp, seq, ack, doff, fl, win, ck, urg = struct.unpack("!HHIIBBHHH", raw[off:off + 20])
    hl = (doff >> 4) * 4
    names = [n for n, bit, _ in TCP_FLAGS if fl & bit]
    compact = "".join(c for _, bit, c in TCP_FLAGS if fl & bit)
    L = p.layer(4, "TCP", off, hl)
    valid = None
    if ctx[0] and ctx[3] and end <= len(raw):
        pseudo = ctx[0] + ctx[1] + b"\x00\x06" + struct.pack("!H", end - off)
        valid = csum(pseudo + raw[off:end]) == 0
    p.add(L, "Source port", sp, off, 2, SERVICES.get(sp, ""))
    p.add(L, "Destination port", dp, off + 2, 2, SERVICES.get(dp, ""))
    p.add(L, "Sequence number", seq, off + 4, 4)
    p.add(L, "Acknowledgment number", ack, off + 8, 4)
    p.add(L, "Header length", "%d bytes" % hl, off + 12, 1)
    p.add(L, "Flags", ",".join(names) or "none", off + 13, 1, "0x%02x" % fl)
    p.add(L, "Window size", win, off + 14, 2)
    p.add(L, "Checksum", "0x%04x" % ck, off + 16, 2, "valid" if valid else ("invalid (possible checksum offload)" if valid is False else "not verifiable"))
    p.add(L, "Urgent pointer", urg, off + 18, 2)
    opts, i = [], off + 20
    while i < off + hl and i < len(raw):
        k = raw[i]
        if k == 0:
            break
        if k == 1:
            opts.append("NOP")
            i += 1
            continue
        if i + 1 >= len(raw):
            break
        ln = raw[i + 1] or 2
        if k == 2 and i + 4 <= len(raw):
            opts.append("MSS=%d" % struct.unpack("!H", raw[i + 2:i + 4])[0])
        elif k == 3 and i + 3 <= len(raw):
            opts.append("WindowScale=%d" % raw[i + 2])
        elif k == 4:
            opts.append("SACK-permitted")
        elif k == 5:
            opts.append("SACK")
        elif k == 8:
            opts.append("Timestamps")
        else:
            opts.append("opt%d" % k)
        i += ln
    if opts:
        p.add(L, "Options", ", ".join(opts), off + 20, hl - 20)
    pay = off + hl
    plen = max(0, end - pay)
    f = p.flat
    f.update({"tcp.srcport": sp, "tcp.dstport": dp, "tcp.port": [sp, dp], "tcp.flags": compact, "tcp.seq": seq, "tcp.ack": ack, "tcp.win": win, "tcp.len": plen})
    for n, bit, _ in TCP_FLAGS:
        f["tcp.flags.%s" % n.lower()] = 1 if fl & bit else 0
    p.proto("tcp")
    p.info = "%d -> %d [%s] Seq=%d Ack=%d Win=%d Len=%d" % (sp, dp, ",".join(names), seq, ack, win, plen)
    L["s"] = "%d -> %d [%s]" % (sp, dp, ",".join(names))
    if plen > 0:
        _tcp_app(p, pay, end, sp, dp)


def _udp(p, off, end, ctx):
    raw = p.raw
    if end - off < 8 or len(raw) < off + 8:
        return
    sp, dp, ln, ck = struct.unpack("!HHHH", raw[off:off + 8])
    L = p.layer(4, "UDP", off, 8)
    valid = None
    if ck and ctx[0] and ctx[3] and end <= len(raw):
        pseudo = ctx[0] + ctx[1] + b"\x00\x11" + struct.pack("!H", end - off)
        valid = csum(pseudo + raw[off:end]) == 0
    p.add(L, "Source port", sp, off, 2, SERVICES.get(sp, ""))
    p.add(L, "Destination port", dp, off + 2, 2, SERVICES.get(dp, ""))
    p.add(L, "Length", ln, off + 4, 2)
    p.add(L, "Checksum", "0x%04x" % ck, off + 6, 2, "valid" if valid else ("invalid (possible checksum offload)" if valid is False else "not used or not verifiable"))
    p.flat.update({"udp.srcport": sp, "udp.dstport": dp, "udp.port": [sp, dp], "udp.len": ln})
    p.proto("udp")
    p.info = "%d -> %d Len=%d" % (sp, dp, max(0, ln - 8))
    L["s"] = "%d -> %d" % (sp, dp)
    pay = off + 8
    if end <= pay:
        return
    ports = (sp, dp)
    if 53 in ports or 5353 in ports:
        _dns(p, pay, end, 5353 in ports)
    elif 67 in ports and 68 in ports:
        _dhcp(p, pay, end)
    elif 137 in ports:
        _nbns(p, pay, end)
    elif 1900 in ports:
        _ssdp(p, pay, end)
    else:
        _data(p, pay, end)


def _icmp(p, off, end):
    raw = p.raw
    if end - off < 4 or len(raw) < off + 4:
        return
    t, c, ck = raw[off], raw[off + 1], struct.unpack("!H", raw[off + 2:off + 4])[0]
    L = p.layer(3, "ICMP", off, 8 if t in (0, 8) else 4)
    valid = csum(raw[off:end]) == 0 if end <= len(raw) else None
    p.add(L, "Type", t, off, 1, ICMP_TYPES.get(t, ""))
    p.add(L, "Code", c, off + 1, 1)
    p.add(L, "Checksum", "0x%04x" % ck, off + 2, 2, "valid" if valid else ("invalid (possible checksum offload)" if valid is False else "not verifiable"))
    p.flat.update({"icmp.type": t, "icmp.code": c})
    p.proto("icmp")
    name = ICMP_TYPES.get(t, "type %d" % t)
    if t in (0, 8) and len(raw) >= off + 8:
        ident, sq = struct.unpack("!HH", raw[off + 4:off + 8])
        p.add(L, "Identifier", ident, off + 4, 2)
        p.add(L, "Sequence number", sq, off + 6, 2)
        p.info = "%s id=%d seq=%d" % (name, ident, sq)
    else:
        p.info = name
    L["s"] = name
    _data(p, off + L["l"], end)


def _data(p, off, end):
    if end > off:
        L = p.layer(7, "Data", off, end - off)
        p.add(L, "Payload", "%d bytes" % (end - off), off, end - off, ascii_preview(p.raw[off:end]))
        L["s"] = "%d bytes" % (end - off)


def _tcp_app(p, off, end, sp, dp):
    pl = p.raw[off:end]
    if len(pl) >= 5 and pl[0] in (20, 21, 22, 23) and pl[1] == 3 and pl[2] <= 4:
        _tls(p, off, end, sp, dp)
    elif pl.startswith(HTTP_STARTS):
        _http(p, off, end)
    elif sp in CLEAR or dp in CLEAR:
        name = CLEAR.get(dp) or CLEAR.get(sp)
        L = p.layer(7, name, off, len(pl))
        line = pl.split(b"\n", 1)[0].decode("latin-1", errors="replace").strip()
        p.add(L, "Cleartext line", line[:120], off, len(pl), "sent without encryption")
        p.flat["app.cleartext"] = name
        p.proto(name.lower())
        p.info = "%s: %s" % (name, line[:60])
        L["s"] = line[:60]
    else:
        _data(p, off, end)


def _http(p, off, end):
    raw = p.raw
    text = raw[off:end].decode("latin-1", errors="replace")
    head = text.split("\r\n\r\n", 1)[0]
    lines = head.split("\r\n")
    L = p.layer(7, "HTTP", off, len(head))
    pos = off
    first = lines[0]
    parts = first.split(" ", 2)
    if first.startswith("HTTP/"):
        p.add(L, "Status line", first, pos, len(first), "response")
        if len(parts) > 1 and parts[1].isdigit():
            p.flat["http.response.code"] = int(parts[1])
    else:
        p.add(L, "Request line", first, pos, len(first), "request")
        p.flat["http.request.method"] = parts[0]
        if len(parts) > 1:
            p.flat["http.request.uri"] = parts[1]
    pos += len(first) + 2
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            p.add(L, k.strip(), v.strip(), pos, len(ln))
            lk = k.strip().lower()
            if lk == "host":
                p.flat["http.host"] = v.strip()
            elif lk == "user-agent":
                p.flat["http.user_agent"] = v.strip()
            elif lk == "content-type":
                p.flat["http.content_type"] = v.strip()
        pos += len(ln) + 2
    p.flat["http.text"] = head
    p.proto("http")
    p.info = first[:90]
    L["s"] = first[:70]


def _dns_name(raw, off, base):
    labels, jumped, end, hops = [], False, None, 0
    while True:
        if off >= len(raw):
            raise ValueError("name overruns packet")
        ln = raw[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            ptr = ((ln & 0x3F) << 8) | raw[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = base + ptr
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
            continue
        labels.append(raw[off + 1:off + 1 + ln].decode("latin-1"))
        off += 1 + ln
    return ".".join(labels), (end if jumped else off)


def _dns(p, off, end, mdns):
    raw = p.raw
    if end - off < 12:
        return
    tid, fl, qd, an, ns, ar = struct.unpack("!HHHHHH", raw[off:off + 12])
    L = p.layer(7, "mDNS" if mdns else "DNS", off, end - off)
    resp = bool(fl & 0x8000)
    p.add(L, "Transaction ID", "0x%04x" % tid, off, 2)
    p.add(L, "Flags", "0x%04x" % fl, off + 2, 2, "response" if resp else "query")
    p.add(L, "Questions / Answers", "%d / %d" % (qd, an), off + 4, 4)
    pos = off + 12
    qnames, anames, ips = [], [], []
    try:
        for _ in range(min(qd, 5)):
            name, np = _dns_name(raw, pos, off)
            t, c = struct.unpack("!HH", raw[np:np + 4])
            p.add(L, "Question", "%s %s" % (name, DNS_TYPES.get(t, t)), pos, np + 4 - pos)
            qnames.append(name)
            p.flat.setdefault("dns.qry.type", DNS_TYPES.get(t, str(t)))
            pos = np + 4
        for _ in range(min(an + ns + ar, 20)):
            if pos >= end:
                break
            name, np = _dns_name(raw, pos, off)
            t, c, ttl, rl = struct.unpack("!HHIH", raw[np:np + 10])
            rd = np + 10
            if t == 1 and rl == 4:
                val = socket.inet_ntoa(raw[rd:rd + 4])
                ips.append(val)
            elif t == 28 and rl == 16:
                val = str(ipaddress.IPv6Address(raw[rd:rd + 16]))
                ips.append(val)
            elif t in (5, 12, 2):
                val, _ = _dns_name(raw, rd, off)
                anames.append(val)
            else:
                val = "%d bytes" % rl
            anames.append(name)
            p.add(L, "Record", "%s %s %s" % (name, DNS_TYPES.get(t, t), val), pos, rd + rl - pos)
            pos = rd + rl
    except Exception:
        pass
    p.flat["dns.qry.name"] = qnames
    p.flat["dns.a"] = ips
    p.flat["dns.resp.name"] = anames
    p.flat["dns.response"] = 1 if resp else 0
    p.proto("mdns" if mdns else "dns")
    if mdns:
        p.flat["mdns.name"] = anames + qnames
    q = qnames[0] if qnames else ""
    p.info = ("Response %s -> %s" % (q, ", ".join(ips)[:60]) if resp else "Query %s" % q)
    L["s"] = p.info


def _dhcp(p, off, end):
    raw = p.raw
    if end - off < 240:
        return
    op, htype, hlen = raw[off], raw[off + 1], raw[off + 2]
    xid = struct.unpack("!I", raw[off + 4:off + 8])[0]
    yi, chaddr = socket.inet_ntoa(raw[off + 16:off + 20]), raw[off + 28:off + 28 + 6]
    L = p.layer(7, "DHCP", off, end - off)
    p.add(L, "Operation", op, off, 1, "request" if op == 1 else "reply")
    p.add(L, "Transaction ID", "0x%08x" % xid, off + 4, 4)
    p.add(L, "Your IP", yi, off + 16, 4)
    p.add(L, "Client MAC", mac_str(chaddr), off + 28, 6)
    p.flat["dhcp.chaddr"] = mac_str(chaddr)
    p.flat["dhcp.yiaddr"] = yi
    i = off + 240
    while i + 2 <= end:
        code = raw[i]
        if code == 255:
            break
        if code == 0:
            i += 1
            continue
        ln = raw[i + 1]
        val = raw[i + 2:i + 2 + ln]
        if code == 53 and val:
            p.flat["dhcp.type"] = DHCP_TYPES.get(val[0], str(val[0]))
            p.add(L, "Message type", p.flat["dhcp.type"], i, 2 + ln)
        elif code == 12:
            p.flat["dhcp.hostname"] = val.decode("latin-1", errors="replace")
            p.add(L, "Hostname", p.flat["dhcp.hostname"], i, 2 + ln)
        elif code == 60:
            p.flat["dhcp.vendor"] = val.decode("latin-1", errors="replace")
            p.add(L, "Vendor class", p.flat["dhcp.vendor"], i, 2 + ln)
        elif code == 50 and ln == 4:
            p.flat["dhcp.requested_ip"] = socket.inet_ntoa(val)
            p.add(L, "Requested IP", p.flat["dhcp.requested_ip"], i, 2 + ln)
        i += 2 + ln
    p.proto("dhcp")
    p.info = "DHCP %s" % p.flat.get("dhcp.type", "")
    L["s"] = p.info


def _nbns(p, off, end):
    raw = p.raw
    if end - off < 46:
        return
    L = p.layer(7, "NBNS", off, end - off)
    p.flat["nbns.opcode"] = (struct.unpack("!H", raw[off + 2:off + 4])[0] >> 11) & 0xF
    enc = raw[off + 13:off + 45]
    try:
        dec = bytes(((enc[i] - 65) << 4) | (enc[i + 1] - 65) for i in range(0, 32, 2))
        name, suffix = dec[:15].decode("latin-1").strip(), dec[15]
        p.add(L, "Name", name, off + 13, 32, "suffix 0x%02x" % suffix)
        p.flat["nbns.name"] = name
        p.flat["nbns.suffix"] = suffix
    except Exception:
        pass
    p.proto("nbns")
    p.info = "NetBIOS name %s" % p.flat.get("nbns.name", "")
    L["s"] = p.info


def _ssdp(p, off, end):
    text = p.raw[off:end].decode("latin-1", errors="replace")
    lines = text.split("\r\n")
    L = p.layer(7, "SSDP", off, end - off)
    p.add(L, "Start line", lines[0][:100], off, len(lines[0]))
    p.flat["ssdp.method"] = lines[0].split(" ")[0]
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            k = k.strip().lower()
            if k in ("server", "usn", "nt", "st", "location"):
                p.flat["ssdp.%s" % k] = v.strip()
                p.add(L, k.upper(), v.strip()[:120], off, 0)
    p.proto("ssdp")
    p.info = "SSDP %s" % lines[0][:60]
    L["s"] = p.info


def _tls(p, off, end, sp, dp):
    raw = p.raw
    L = p.layer(6, "TLS", off, 0)
    pos, count = off, 0
    f = p.flat
    while pos + 5 <= end and count < 4:
        ct, ver, ln = raw[pos], struct.unpack("!H", raw[pos + 1:pos + 3])[0], struct.unpack("!H", raw[pos + 3:pos + 5])[0]
        p.add(L, "Record type", ct, pos, 1, TLS_RECORDS.get(ct, "unknown"))
        p.add(L, "Record version", "0x%04x" % ver, pos + 1, 2, TLS_VERSIONS.get(ver, "unknown"))
        p.add(L, "Record length", ln, pos + 3, 2)
        f.setdefault("tls.record_type", TLS_RECORDS.get(ct, "unknown"))
        f.setdefault("tls.version", TLS_VERSIONS.get(ver, "0x%04x" % ver))
        if ct == 22 and pos + 9 <= end:
            ht = raw[pos + 5]
            f["tls.handshake_type"] = TLS_HS.get(ht, str(ht))
            p.add(L, "Handshake type", ht, pos + 5, 1, TLS_HS.get(ht, ""))
            try:
                if ht == 1:
                    _client_hello(p, L, pos + 9, min(end, pos + 5 + ln))
                elif ht == 2:
                    _server_hello(p, L, pos + 9, min(end, pos + 5 + ln))
            except Exception:
                pass
        pos += 5 + ln
        count += 1
    L["l"] = max(0, min(pos, end) - off)
    p.proto("tls")
    p.info = "TLS %s %s%s" % (f.get("tls.version", ""), f.get("tls.handshake_type") or f.get("tls.record_type", ""), (" SNI=" + f["tls.sni"]) if f.get("tls.sni") else "")
    L["s"] = p.info


def _client_hello(p, L, o, end):
    raw = p.raw
    cv = struct.unpack("!H", raw[o:o + 2])[0]
    p.add(L, "Client version", "0x%04x" % cv, o, 2, TLS_VERSIONS.get(cv, ""))
    p.flat["tls.client_version"] = TLS_VERSIONS.get(cv, "0x%04x" % cv)
    i = o + 2 + 32
    sl = raw[i]
    i += 1 + sl
    cl = struct.unpack("!H", raw[i:i + 2])[0]
    suites = [struct.unpack("!H", raw[i + 2 + k:i + 4 + k])[0] for k in range(0, cl, 2)]
    names = [CIPHERS.get(s, "0x%04x" % s) for s in suites[:6]]
    p.add(L, "Cipher suites", "%d offered" % len(suites), i, 2 + cl, ", ".join(names) + (" ..." if len(suites) > 6 else ""))
    p.flat["tls.cipher_suites_count"] = len(suites)
    i += 2 + cl
    i += 1 + raw[i]
    if i + 2 > end:
        return
    el = struct.unpack("!H", raw[i:i + 2])[0]
    i += 2
    stop = min(end, i + el)
    while i + 4 <= stop:
        et, elen = struct.unpack("!HH", raw[i:i + 4])
        d = raw[i + 4:i + 4 + elen]
        if et == 0 and len(d) > 5:
            nl = struct.unpack("!H", d[3:5])[0]
            sni = d[5:5 + nl].decode("latin-1", errors="replace")
            p.flat["tls.sni"] = sni
            p.add(L, "Server name (SNI)", sni, i + 4, elen, "the site the client wants to reach, sent in clear")
        elif et == 43 and d:
            vs = [TLS_VERSIONS.get(struct.unpack("!H", d[1 + k:3 + k])[0], "?") for k in range(0, d[0], 2)]
            p.flat["tls.supported_versions"] = ",".join(vs)
            p.add(L, "Supported versions", ", ".join(vs), i + 4, elen)
        elif et == 16 and len(d) > 3:
            p.flat["tls.alpn"] = d[3:3 + d[2]].decode("latin-1", errors="replace")
        i += 4 + elen


def _server_hello(p, L, o, end):
    raw = p.raw
    sv = struct.unpack("!H", raw[o:o + 2])[0]
    p.add(L, "Server version", "0x%04x" % sv, o, 2, TLS_VERSIONS.get(sv, ""))
    i = o + 2 + 32
    i += 1 + raw[i]
    cs = struct.unpack("!H", raw[i:i + 2])[0]
    p.add(L, "Selected cipher", CIPHERS.get(cs, "0x%04x" % cs), i, 2)
    p.flat["tls.selected_cipher"] = CIPHERS.get(cs, "0x%04x" % cs)


def from_text(text, link=None):
    t = text.strip()
    cleaned = "".join(c for c in t if c in "0123456789abcdefABCDEF")
    if len(cleaned) >= 20 and len(cleaned) % 2 == 0 and all(c in "0123456789abcdefABCDEF: \n\r\t-" for c in t.replace("0x", "")):
        return parse(bytes.fromhex(cleaned), link)
    return parse(base64.b64decode(t), link)
