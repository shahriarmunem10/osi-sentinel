import concurrent.futures
import ipaddress
import json
import platform
import random
import re
import socket
import struct
import subprocess
import threading
import time
from collections import deque

import psutil

from . import db
from .decoder import SERVICES
from .synth import mac_for

IS_WINDOWS = platform.system() == "Windows"
TOP_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 631, 993, 995, 1900, 3306, 3389, 5000, 5353, 5432, 5555, 5900, 7000, 8000, 8008, 8009, 8080, 8443, 9100, 62078]
MOBILE = ("samsung", "xiaomi", "huawei", "oneplus", "oppo", "vivo", "realme", "motorola", "google", "tecno", "infinix", "nokia", "honor", "zte")
PC = ("intel", "realtek", "dell", "lenovo", "hewlett", "hp inc", "asustek", "acer", "msi", "micro-star", "gigabyte", "liteon", "azurewave", "murata", "qualcomm", "mediatek", "microsoft")
NET = ("tp-link", "d-link", "tenda", "netgear", "mikrotik", "ubiquiti", "zyxel", "cisco", "totolink", "linksys")
ARP_LINE = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})")


def norm_mac(m):
    return m.lower().replace("-", ":")


def vendor_of(mac):
    try:
        from scapy.all import conf

        v = conf.manufdb._get_manuf(mac)
        if v and v.lower() != mac.lower() and not re.match(r"^[0-9a-f:]{17}$", v.lower()):
            return v
    except Exception:
        pass
    return ""


def is_random_mac(mac):
    try:
        return bool(int(mac[:2], 16) & 2)
    except Exception:
        return False


def os_guess(ttl):
    if not ttl:
        return ""
    if ttl <= 64:
        return "Linux / Android / iOS / macOS (TTL 64)"
    if ttl <= 128:
        return "Windows (TTL 128)"
    return "Router or network device (TTL 255)"


def type_guess(d):
    v = (d.get("vendor") or "").lower()
    if d.get("is_gateway"):
        return "Router / Gateway"
    if d.get("is_self"):
        return "This computer"
    if "apple" in v:
        return "Apple device (iPhone, iPad or Mac)"
    if any(k in v for k in NET):
        return "Network equipment"
    if any(k in v for k in MOBILE):
        return "Phone or tablet (likely)"
    if any(k in v for k in PC):
        return "Computer (likely)"
    if d.get("random_mac"):
        return "Phone or tablet with private MAC (likely)"
    if "Windows" in (d.get("os") or ""):
        return "Windows computer (likely)"
    return "Unknown"


def local_networks():
    out = []
    gw = default_gateway()
    try:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
    except Exception:
        return out
    for name, al in addrs.items():
        st = stats.get(name)
        if not st or not st.isup:
            continue
        for a in al:
            if a.family != socket.AF_INET or not a.netmask:
                continue
            try:
                ip = ipaddress.ip_address(a.address)
                if ip.is_loopback or ip.is_link_local or not ip.is_private:
                    continue
                net = ipaddress.ip_network("%s/%s" % (a.address, a.netmask), strict=False)
            except ValueError:
                continue
            mac = ""
            for b in al:
                if b.family == psutil.AF_LINK:
                    mac = norm_mac(b.address)
            has_gw = bool(gw and ipaddress.ip_address(gw) in net)
            out.append({"iface": name, "ip": a.address, "cidr": str(net), "mac": mac, "gateway": gw if has_gw else None, "hosts": net.num_addresses - 2})
    out.sort(key=lambda n: (not n["gateway"], n["iface"]))
    return out


def default_gateway():
    try:
        from scapy.all import conf

        gw = conf.route.route("0.0.0.0")[2]
        if gw and gw != "0.0.0.0":
            return gw
    except Exception:
        pass
    try:
        if not IS_WINDOWS:
            out = subprocess.run(["ip", "route"], capture_output=True, text=True, timeout=3).stdout
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", out)
            return m.group(1) if m else None
        out = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)", out)
        return m.group(1) if m else None
    except Exception:
        return None


def read_arp_cache():
    try:
        out = subprocess.run(["arp", "-a"] if IS_WINDOWS else ["ip", "neigh"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return {}
    res = {}
    for line in out.splitlines():
        m = ARP_LINE.search(line) if IS_WINDOWS else re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]{17})", line)
        if m:
            ip, mac = m.group(1), norm_mac(m.group(2))
            if mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") and not mac.startswith("01:00:5e"):
                res[ip] = mac
    return res


def ping(ip, timeout_ms=700):
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip] if IS_WINDOWS else ["ping", "-c", "1", "-W", "1", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=4).stdout
    except Exception:
        return None, None
    ttl = re.search(r"ttl[=:](\d+)", out, re.I)
    ms = re.search(r"time[=<]\s*([\d.]+)\s*ms", out, re.I)
    return (int(ttl.group(1)) if ttl else None), (float(ms.group(1)) if ms else None)


def netbios_name(ip):
    q = b"\x12\x34\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.8)
    try:
        s.sendto(q, (ip, 137))
        data, _ = s.recvfrom(1024)
        n = data[56]
        for i in range(n):
            e = data[57 + i * 18:57 + (i + 1) * 18]
            if len(e) == 18 and e[15] == 0x00 and not (struct.unpack("!H", e[16:18])[0] & 0x8000):
                return e[:15].decode("latin-1").strip()
    except Exception:
        pass
    finally:
        s.close()
    return ""


def mdns_name(ip):
    rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    q = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + b"".join(bytes([len(x)]) + x.encode() for x in rev.split(".")) + b"\x00" + struct.pack("!HH", 12, 0x8001)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.8)
    try:
        s.sendto(q, (ip, 5353))
        data, _ = s.recvfrom(2048)
        from .decoder import _dns_name

        an = struct.unpack("!H", data[6:8])[0]
        if an:
            _, pos = _dns_name(data, 12, 0)
            pos += 4
            _, pos = _dns_name(data, pos, 0)
            rl = struct.unpack("!H", data[pos + 8:pos + 10])[0]
            name, _ = _dns_name(data, pos + 10, 0)
            return name
    except Exception:
        pass
    finally:
        s.close()
    return ""


def reverse_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def scan_ports(ip, ports=None):
    ports = ports or TOP_PORTS
    found = []

    def probe(port):
        s = socket.socket()
        s.settimeout(0.45)
        try:
            if s.connect_ex((ip, port)) == 0:
                return port
        except Exception:
            pass
        finally:
            s.close()
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=48) as ex:
        for r in ex.map(probe, ports):
            if r:
                found.append({"port": r, "service": SERVICES.get(r, "unknown")})
    return found


class BandwidthTable:
    def __init__(self):
        self.lock = threading.Lock()
        self.ips = {}

    def reset(self):
        with self.lock:
            self.ips.clear()

    def update(self, src, dst, length):
        with self.lock:
            for ip, key in ((src, "tx"), (dst, "rx")):
                if not ip:
                    continue
                e = self.ips.get(ip)
                if e is None:
                    if len(self.ips) > 600:
                        self.ips.pop(min(self.ips, key=lambda k: self.ips[k]["tx"] + self.ips[k]["rx"]))
                    e = self.ips[ip] = {"tx": 0, "rx": 0, "tx_pk": 0, "rx_pk": 0, "tx_rate": 0.0, "rx_rate": 0.0, "_tx": 0, "_rx": 0, "hist": deque(maxlen=60)}
                e[key] += length
                e[key + "_pk"] += 1

    def tick(self, dt):
        with self.lock:
            for e in self.ips.values():
                e["tx_rate"] = (e["tx"] - e["_tx"]) / dt
                e["rx_rate"] = (e["rx"] - e["_rx"]) / dt
                e["_tx"], e["_rx"] = e["tx"], e["rx"]
                e["hist"].append(round(e["tx_rate"] + e["rx_rate"], 1))

    def get(self, ip):
        with self.lock:
            e = self.ips.get(ip)
            if not e:
                return {"tx": 0, "rx": 0, "tx_pk": 0, "rx_pk": 0, "tx_rate": 0, "rx_rate": 0, "hist": []}
            return {k: (list(v) if k == "hist" else v) for k, v in e.items() if not k.startswith("_")}


class DeviceManager:
    def __init__(self, engine):
        self.engine = engine
        self.lock = threading.RLock()
        self.devices = {}
        self.dirty = set()
        self.scan_state = {"running": False, "progress": 0, "total": 0, "found": 0, "started": None, "finished": None, "mode": "", "message": ""}
        self.baseline_done = False
        self.auto = False
        self.auto_interval = 60
        self.cidr = None
        self.iface = None
        self.demo = False
        self._last_scan = 0
        self._load()
        threading.Thread(target=self._auto_loop, daemon=True).start()

    def _load(self):
        try:
            for r in db.query("SELECT * FROM devices"):
                d = json.loads(r["extra"] or "{}")
                d.update(mac=r["mac"], ip=r["ip"], hostname=r["hostname"] or "", vendor=r["vendor"] or "", custom_name=r["custom_name"] or "",
                         known=bool(r["known"]), first_seen=r["first_seen"], last_seen=r["last_seen"], online=False)
                self.devices[r["mac"]] = d
            if self.devices:
                self.baseline_done = True
        except Exception:
            pass

    def flush(self):
        with self.lock:
            macs, self.dirty = list(self.dirty), set()
            rows = [self.devices[m] for m in macs if m in self.devices]
        for d in rows:
            extra = {k: d.get(k) for k in ("os", "ttl", "latency", "ports", "random_mac", "sources", "dhcp_vendor", "ssdp", "names", "is_gateway", "is_self")}
            db.execute(
                "INSERT INTO devices(mac,ip,hostname,vendor,custom_name,known,first_seen,last_seen,extra) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,hostname=excluded.hostname,vendor=excluded.vendor,custom_name=excluded.custom_name,known=excluded.known,last_seen=excluded.last_seen,extra=excluded.extra",
                (d["mac"], d["ip"], d.get("hostname", ""), d.get("vendor", ""), d.get("custom_name", ""), 1 if d.get("known") else 0, d["first_seen"], d["last_seen"], json.dumps(extra)),
            )

    def reset(self):
        with self.lock:
            self.devices.clear()
            self.dirty.clear()
            self.baseline_done = False
            self._last_scan = 0
        db.execute("DELETE FROM devices")

    def upsert(self, mac, ip=None, source="", name=None, **extra):
        mac = norm_mac(mac)
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") or mac.startswith(("01:00:5e", "33:33")) or mac == "loopback":
            return None
        now = time.time()
        new = False
        with self.lock:
            d = self.devices.get(mac)
            if d is None:
                new = True
                d = self.devices[mac] = {"mac": mac, "ip": ip or "", "hostname": "", "vendor": vendor_of(mac), "custom_name": "", "first_seen": now, "last_seen": now,
                                         "known": not self.baseline_done, "sources": [], "names": [], "ports": [], "os": "", "ttl": None, "latency": None,
                                         "random_mac": is_random_mac(mac), "online": True}
            if ip:
                d["ip"] = ip
            d["last_seen"] = now
            d["online"] = True
            d["stale"] = False
            if source and source not in d["sources"]:
                d["sources"].append(source)
            if name and name not in d["names"]:
                d["names"].append(name)
                if not d["hostname"] or source in ("dhcp", "mdns", "nbns"):
                    d["hostname"] = name
            d.update({k: v for k, v in extra.items() if v})
            self.dirty.add(mac)
            alert = new and self.baseline_done
        if alert:
            self.engine.alert(2, "New Device Joined Network", "Medium", ip or "", mac, "New device %s (%s) appeared on the network" % (mac, d.get("vendor") or "unknown vendor"))
        return d

    def observe(self, p, res=None):
        proto = p["proto"]
        smac = p.get("smac")
        if not smac or smac == "loopback":
            return
        ip = p.get("src")
        if proto == "ARP":
            if p.get("arp_hwsrc") and p.get("arp_psrc") and p["arp_psrc"] != "0.0.0.0":
                self.upsert(p["arp_hwsrc"], p["arp_psrc"], "arp")
            return
        if ip and self._local(ip) and not self._multicast(p.get("dst")):
            self.upsert(smac, ip, "traffic")
        elif ip and self._local(ip):
            self.upsert(smac, ip, "traffic")
        if res is not None:
            f = res["flat"]
            if f.get("dhcp.hostname"):
                self.upsert(f.get("dhcp.chaddr") or smac, ip if ip and ip != "0.0.0.0" else None, "dhcp", f["dhcp.hostname"], dhcp_vendor=f.get("dhcp.vendor"))
            nb = f.get("nbns.name", "")
            if nb and ip and f.get("nbns.opcode") in (5, 8, 9) and nb.isprintable() and not nb.startswith("*"):
                self.upsert(smac, ip, "nbns", nb)
            if f.get("mdns.name") and ip and f.get("dns.response"):
                names = [n for n in f["mdns.name"] if n.endswith(".local") and not n.startswith("_") and "._" not in n]
                if names:
                    self.upsert(smac, ip, "mdns", names[0])
            if f.get("ssdp.server") and ip:
                self.upsert(smac, ip, "ssdp", ssdp=f["ssdp.server"][:80])

    def _local(self, ip):
        if not self.cidr:
            return False
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(self.cidr)
        except ValueError:
            return False

    @staticmethod
    def _multicast(ip):
        try:
            return ipaddress.ip_address(ip).is_multicast or ip.endswith(".255")
        except Exception:
            return False

    def networks(self):
        return local_networks()

    def choose(self, cidr=None):
        nets = local_networks()
        pick = None
        for n in nets:
            if cidr and n["cidr"] == cidr:
                pick = n
        if not pick and nets:
            pick = nets[0]
        if pick:
            self.cidr, self.iface = pick["cidr"], pick["iface"]
        return pick

    def start_scan(self, cidr=None):
        with self.lock:
            if self.scan_state["running"]:
                return False
            if time.time() - self._last_scan < 5:
                return False
            self.scan_state.update(running=True, progress=0, total=0, found=0, started=time.time(), finished=None, message="")
        if self.demo:
            threading.Thread(target=self._demo_scan, daemon=True).start()
        else:
            threading.Thread(target=self._scan, args=(cidr,), daemon=True).start()
        return True

    def _scan(self, cidr):
        try:
            net = self.choose(cidr)
            if not net:
                self.scan_state.update(message="No private IPv4 network found. Connect to Wi-Fi or a hotspot first.")
                return
            network = ipaddress.ip_network(net["cidr"])
            hosts = list(network.hosts())
            if len(hosts) > 1022:
                me = ipaddress.ip_address(net["ip"])
                network = ipaddress.ip_network("%s/22" % me, strict=False)
                hosts = list(network.hosts())
            self.scan_state.update(total=len(hosts), mode="ARP")
            gw = net.get("gateway")
            found = {}
            try:
                from scapy.all import ARP, Ether, conf, srp

                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)), timeout=2.5, retry=1, verbose=0)
                for _, r in ans:
                    found[r[ARP].psrc] = norm_mac(r[ARP].hwsrc)
                self.scan_state["mode"] = "ARP broadcast (Scapy)"
            except Exception as exc:
                self.scan_state["mode"] = "ping sweep and ARP cache (Scapy unavailable: %s)" % type(exc).__name__
                with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
                    for i, _ in enumerate(ex.map(lambda h: ping(str(h), 400), hosts)):
                        self.scan_state["progress"] = i + 1
            for ip, mac in read_arp_cache().items():
                try:
                    if ipaddress.ip_address(ip) in network:
                        found.setdefault(ip, mac)
                except ValueError:
                    pass
            found.setdefault(net["ip"], net["mac"]) if net["mac"] else None
            for ip, mac in found.items():
                d = self.upsert(mac, ip, "scan")
                if d is not None:
                    d["is_self"] = ip == net["ip"]
                    d["is_gateway"] = bool(gw and ip == gw)
            self.scan_state.update(found=len(found), progress=len(hosts))
            began = self.scan_state.get("started") or 0
            with self.lock:
                for d in self.devices.values():
                    d["stale"] = d["last_seen"] < began
            self._enrich(list(found))
            self.baseline_done = True
        except Exception as exc:
            self.scan_state["message"] = "Scan failed: %s" % exc
        finally:
            with self.lock:
                self.scan_state.update(running=False, finished=time.time())
                self._last_scan = time.time()
            self.flush()

    def _enrich(self, ips):
        by_ip = {d["ip"]: d for d in self.devices.values() if d["ip"] in ips}

        def work(ip):
            d = by_ip.get(ip)
            if not d:
                return
            ttl, ms = ping(ip)
            names = []
            if not d.get("is_self"):
                names = [("nbns", netbios_name(ip)), ("mdns", mdns_name(ip))]
            rdns = reverse_dns(ip)
            with self.lock:
                if ttl:
                    d["ttl"], d["os"] = ttl, os_guess(ttl)
                if ms is not None:
                    d["latency"] = ms
                if d.get("is_self"):
                    d["hostname"] = d["hostname"] or socket.gethostname()
                    d["os"] = d["os"] or platform.system()
                for src, n in names + [("dns", rdns)]:
                    if n and n not in d["names"]:
                        d["names"].append(n)
                        if not d["hostname"] or src in ("mdns", "nbns"):
                            d["hostname"] = n
                self.dirty.add(d["mac"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
            list(ex.map(work, ips))

    def port_scan(self, mac):
        d = self.devices.get(norm_mac(mac))
        if not d or not d["ip"]:
            return None
        try:
            ip = ipaddress.ip_address(d["ip"])
        except ValueError:
            return None
        if not ip.is_private and not self.demo:
            return None
        if self.demo:
            ports = d.get("demo_ports", [])
            time.sleep(0.8)
        else:
            if not self._local(d["ip"]):
                return None
            ports = scan_ports(d["ip"])
        with self.lock:
            d["ports"] = ports
            d["ports_at"] = time.time()
            self.dirty.add(d["mac"])
        return ports

    def rename(self, mac, name):
        with self.lock:
            d = self.devices.get(norm_mac(mac))
            if not d:
                return False
            d["custom_name"] = name[:60]
            self.dirty.add(d["mac"])
        return True

    def trust(self, mac, known=True):
        with self.lock:
            d = self.devices.get(norm_mac(mac))
            if not d:
                return False
            d["known"] = known
            self.dirty.add(d["mac"])
        return True

    def _auto_loop(self):
        while True:
            time.sleep(5)
            try:
                if self.auto and not self.scan_state["running"] and time.time() - self._last_scan >= self.auto_interval and (self.cidr or self.demo):
                    self.start_scan(self.cidr)
                self.flush()
            except Exception:
                pass

    def snapshot(self):
        now = time.time()
        offline_after = max(150, self.auto_interval * 3)
        out = []
        with self.lock:
            for d in self.devices.values():
                row = {k: v for k, v in d.items() if k != "demo_ports"}
                row["online"] = (not d.get("stale")) and now - d["last_seen"] < offline_after
                row["type"] = type_guess(d)
                row["name"] = d.get("custom_name") or d.get("hostname") or ""
                row["bw"] = self.engine.bandwidth.get(d["ip"]) if d["ip"] else self.engine.bandwidth.get("")
                out.append(row)
            ips = {}
            for r in out:
                ips.setdefault(r["ip"], []).append(r)
            for r in out:
                r["ip_conflict"] = bool(r["ip"]) and len([x for x in ips[r["ip"]] if x["online"]]) > 1
        out.sort(key=lambda r: (not r.get("is_gateway"), not r["online"], tuple(int(x) for x in r["ip"].split(".")) if re.match(r"^\d+\.\d+\.\d+\.\d+$", r["ip"] or "") else (999,)))
        return out

    def load_demo(self):
        self.demo = True
        self.cidr = "192.168.56.0/24"
        self.iface = "demo0"
        self.baseline_done = False
        base = [
            ("52:54:00:aa:00:01", "192.168.56.1", "Router", "TP-Link", True, False, 64, [{"port": 53, "service": "DNS"}, {"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]),
            ("52:54:00:56:00:0a", "192.168.56.10", "SHAHRIAR-LAPTOP", "Dell", False, True, 128, [{"port": 135, "service": "unknown"}, {"port": 445, "service": "SMB"}]),
            ("52:54:00:56:00:0b", "192.168.56.11", "Galaxy-S23", "Samsung Electronics", False, False, 64, []),
            ("52:54:00:56:00:0c", "192.168.56.12", "Raju-iPhone", "Apple", False, False, 64, [{"port": 62078, "service": "unknown"}]),
            ("52:54:00:56:00:0d", "192.168.56.13", "Alif-Redmi", "Xiaomi Communications", False, False, 64, []),
            ("52:54:00:56:00:0e", "192.168.56.14", "LG-SmartTV", "LG Electronics", False, False, 64, [{"port": 8008, "service": "Chromecast HTTP"}, {"port": 9100, "service": "unknown"}]),
        ]
        for mac, ip, name, vendor, gw, me, ttl, ports in base:
            d = self.upsert(mac_for(ip), ip, "scan", name)
            d.update(vendor=vendor, is_gateway=gw, is_self=me, ttl=ttl, os=os_guess(ttl), latency=round(random.uniform(1, 12), 1), demo_ports=ports, known=True, random_mac=False)
            d["sources"] = ["arp", "scan", "dhcp"] if not me else ["scan"]
        self.baseline_done = True

    def _demo_scan(self):
        time.sleep(1.2)
        now = time.time()
        with self.lock:
            for d in self.devices.values():
                d["last_seen"], d["online"] = now, True
            self.scan_state.update(running=False, progress=254, total=254, found=len(self.devices), finished=now, mode="demo simulation", message="")
            self._last_scan = now

    def demo_join(self):
        n = random.randint(40, 90)
        mac = "9a:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))
        d = self.upsert(mac, "192.168.56.%d" % n, "arp", "Simulated-Device")
        if d:
            d.update(known=False, random_mac=True, ttl=64, os=os_guess(64), demo_ports=[], latency=round(random.uniform(2, 20), 1))
        return d
