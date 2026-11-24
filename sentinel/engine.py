import base64
import json
import threading
import time
from collections import Counter, deque

import config
from . import db, decoder, synth
from .detectors import Detectors
from .devices import BandwidthTable, DeviceManager
from .flows import FlowTable
from .interfaces import InterfaceMonitor

LAYER_NAMES = {
    1: "Physical",
    2: "Data Link",
    3: "Network",
    4: "Transport",
    5: "Session",
    6: "Presentation",
    7: "Application",
}
HTTP_STARTS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"HTTP/")
PORT_APPS = {21: "FTP", 23: "Telnet", 25: "SMTP", 110: "POP3", 143: "IMAP"}
PLAIN_PORTS = {80, 8080, 21, 23, 25, 110, 143}
ICMP_NAMES = {0: "echo-reply", 3: "dest-unreachable", 8: "echo-request", 11: "time-exceeded"}
EVIDENCE_PROTOS = {2: {"ARP"}, 3: {"ICMP"}, 4: {"TCP", "UDP"}, 5: {"TCP"}, 6: {"TLS", "FTP", "Telnet", "POP3", "IMAP"}, 7: {"HTTP", "DNS", "FTP", "Telnet"}}
DEVICE_UDP_PORTS = (67, 68, 137, 1900, 5353)


class Engine:
    def __init__(self):
        self.lock = threading.RLock()
        self.started = time.time()
        self.mode = "idle"
        self.error = None
        self.iface_desc = "-"
        self.recent = deque(maxlen=5000)
        self.pending = []
        self.layer_pkts = {i: 0 for i in range(2, 8)}
        self.proto = Counter()
        self.talkers = Counter()
        self.total = 0
        self.total_bytes = 0
        self.tls = 0
        self.plain = 0
        self.rate = deque(maxlen=90)
        self._last = (time.time(), 0, 0)
        self.pps = 0.0
        self.bps = 0.0
        self.seq = 0
        self.detectors = Detectors(self.alert)
        self.ifmon = InterfaceMonitor(self.alert)
        self.flows = FlowTable()
        self.bandwidth = BandwidthTable()
        self.devices = DeviceManager(self)
        self.if_snapshot = []
        self.capture = None
        self.demo = None
        self.stop_evt = threading.Event()
        self._ticks = 0
        threading.Thread(target=self._tick_loop, daemon=True).start()

    def alert(self, layer, threat, severity, src="", dst="", detail="", evidence=True):
        ev = self._evidence(layer, src, dst) if evidence and layer > 1 else None
        db.add_alert(layer, threat, severity, src, dst, detail, ev)

    def _evidence(self, layer, src, dst):
        cutoff = time.time() - config.THRESHOLDS["window_seconds"] - 2
        wanted = EVIDENCE_PROTOS.get(layer, set())
        host = (dst or "").split(":")[0]
        with self.lock:
            rows = list(self.recent)[-1500:]
        hits = []
        for row in reversed(rows):
            if row["ts"] < cutoff:
                break
            if not row.get("raw"):
                continue
            if src and row["src"] != src and row["dst"] != src and not (host and row["dst"] == host):
                continue
            if wanted and row["proto"] not in wanted:
                continue
            hits.append(row)
            if len(hits) >= 12:
                break
        if not hits:
            return None
        items = [{"id": r["id"], "ts": r["ts"], "link": r["link"], "info": r["info"], "raw": base64.b64encode(r["raw"][:700]).decode()} for r in reversed(hits)]
        return json.dumps(items)

    def _classify(self, p):
        proto = p["proto"]
        payload = p.get("payload") or b""
        app = None
        layer = 3
        if proto == "ARP":
            layer = 2
        elif proto in ("TCP", "UDP"):
            layer = 4
            if proto == "TCP" and any(c in p["flags"] for c in "SFR"):
                layer = 5
            ports = (p["sport"], p["dport"])
            if proto == "UDP" and 53 in ports:
                app, layer = "DNS", 7
            elif payload:
                if len(payload) >= 5 and payload[0] in (20, 21, 22, 23) and payload[1] == 3 and payload[2] <= 4:
                    app, layer = "TLS", 6
                elif payload.startswith(HTTP_STARTS):
                    app, layer = "HTTP", 7
                    p["http"] = payload[:2000].decode("latin-1", errors="replace")
                else:
                    for port in ports:
                        if port in PORT_APPS:
                            app, layer = PORT_APPS[port], 7
                            break
        p["app"] = app
        p["layer"] = layer
        if proto == "ARP":
            p["info"] = ("who-has %s tell %s" % (p["dst"], p["src"])) if p["arp_op"] == 1 else ("%s is-at %s" % (p["arp_psrc"], p["arp_hwsrc"]))
        elif proto == "ICMP":
            p["info"] = ICMP_NAMES.get(p.get("icmp_type"), "type %s" % p.get("icmp_type"))
        elif app == "HTTP":
            p["info"] = (p.get("http") or "").split("\r\n", 1)[0][:90]
        elif app == "DNS":
            p["info"] = "query %s" % (p.get("dns_q") or "")
        elif proto in ("TCP", "UDP"):
            flags = "[%s] " % p["flags"] if proto == "TCP" else ""
            p["info"] = "%s -> %s %s%s" % (p["sport"], p["dport"], flags, app or "")
        else:
            p["info"] = p["proto"]

    def process(self, p, sim=False):
        p["sim"] = sim
        p.setdefault("payload", b"")
        self._classify(p)
        raw = p.get("raw")
        if not raw:
            try:
                raw = p["raw"] = synth.build(p)
            except Exception:
                raw = p["raw"] = b""
        link = p.setdefault("link", "ethernet")
        if link == "ethernet" and len(raw) >= 14:
            p["smac"], p["dmac"] = decoder.mac_str(raw[6:12]), decoder.mac_str(raw[:6])
        elif link == "null":
            p["smac"] = p["dmac"] = "loopback"
        else:
            p.setdefault("smac", None)
            p.setdefault("dmac", None)
        with self.lock:
            self.seq += 1
            self.total += 1
            self.total_bytes += p["length"]
            self.layer_pkts[p["layer"]] += 1
            label = p.get("app") or p["proto"]
            self.proto[label] += 1
            if p["src"]:
                self.talkers[p["src"]] += 1
            if p.get("app") == "TLS":
                self.tls += 1
            elif p["proto"] == "TCP" and p["payload"] and (p["sport"] in PLAIN_PORTS or p["dport"] in PLAIN_PORTS):
                self.plain += 1
            row = {
                "id": self.seq,
                "ts": p["ts"],
                "src": p["src"],
                "dst": p["dst"],
                "proto": label,
                "sport": p.get("sport"),
                "dport": p.get("dport"),
                "length": p["length"],
                "layer": p["layer"],
                "info": ("[SIM] " if sim else "") + p["info"],
                "sim": sim,
                "smac": p.get("smac"),
                "dmac": p.get("dmac"),
                "raw": raw,
                "link": link,
            }
            self.recent.append(row)
            self.pending.append(row)
            self.detectors.handle(p)
            self.flows.update(p, self.seq)
            self.bandwidth.update(p["src"], p["dst"], p["length"])
        res = None
        if p["proto"] == "UDP" and (p["sport"] in DEVICE_UDP_PORTS or p["dport"] in DEVICE_UDP_PORTS) and raw:
            try:
                res = decoder.parse(raw, link)
            except Exception:
                res = None
        try:
            self.devices.observe(p, res)
        except Exception:
            pass

    def _tick_loop(self):
        while not self.stop_evt.is_set():
            time.sleep(2)
            try:
                self._tick()
            except Exception:
                pass

    def _tick(self):
        now = time.time()
        with self.lock:
            t0, n0, b0 = self._last
            dt = max(now - t0, 0.001)
            self.pps = (self.total - n0) / dt
            self.bps = (self.total_bytes - b0) / dt
            self._last = (now, self.total, self.total_bytes)
            self.rate.append({"t": now, "pps": round(self.pps, 1), "bps": round(self.bps, 1)})
            rows, self.pending = self.pending, []
            self.detectors.sweep(now)
            self.bandwidth.tick(dt)
        db.add_packets(rows)
        db.add_stat(now, self.pps, self.bps)
        self.if_snapshot = self.ifmon.update()
        self._ticks += 1
        if self._ticks % 30 == 0:
            db.prune()

    def start(self, mode="auto", iface=None):
        self.stop_sources()
        self.error = None
        if mode in ("live", "auto"):
            from .capture import Capture

            cap = Capture(self, iface)
            self.capture = cap
            if cap.error:
                self.error = cap.error
                self.capture = None
                if mode == "auto":
                    self._start_demo()
                else:
                    self.mode = "error"
            else:
                self.mode = "live"
                self.iface_desc = cap.description
        else:
            self._start_demo()
        if self.mode == "live":
            self.devices.demo = False
            self.devices.choose()
            self.devices.auto = True
            self.devices.start_scan()

    def _start_demo(self):
        from .demo import TrafficGenerator

        self.devices.devices.clear()
        self.devices.load_demo()
        self.devices.auto = True

        self.demo = TrafficGenerator(self)
        self.demo.start()
        self.mode = "demo"
        self.iface_desc = "synthetic traffic generator"

    def stop_sources(self):
        if self.capture:
            self.capture.stop()
            self.capture = None
        if self.demo:
            self.demo.stop()
            self.demo = None
        self.mode = "idle"

    def reset(self):
        with self.lock:
            self.recent.clear()
            self.pending = []
            self.layer_pkts = {i: 0 for i in range(2, 8)}
            self.proto.clear()
            self.talkers.clear()
            self.total = 0
            self.total_bytes = 0
            self.tls = 0
            self.plain = 0
            self.rate.clear()
            self._last = (time.time(), 0, 0)
            self.detectors = Detectors(self.alert)
        self.flows.reset()
        self.bandwidth.reset()
        db.clear_all()
