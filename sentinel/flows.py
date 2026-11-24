import threading
import time
from collections import deque

from .decoder import SERVICES

MAX_FLOWS = 3000
MAX_CHUNK_BYTES = 65536


class FlowTable:
    def __init__(self):
        self.lock = threading.RLock()
        self.flows = {}
        self.seq = 0

    def reset(self):
        with self.lock:
            self.flows.clear()
            self.seq = 0

    def update(self, p, frame_id):
        proto = p["proto"]
        if proto not in ("TCP", "UDP", "ICMP") or not p.get("src"):
            return
        sp, dp = p.get("sport") or 0, p.get("dport") or 0
        a, b = (p["src"], sp), (p["dst"], dp)
        key = (proto,) + (a + b if a <= b else b + a)
        now = p["ts"]
        with self.lock:
            f = self.flows.get(key)
            if f is None:
                if len(self.flows) >= MAX_FLOWS:
                    oldest = min(self.flows, key=lambda k: self.flows[k]["last"])
                    del self.flows[oldest]
                self.seq += 1
                svc = SERVICES.get(dp) or SERVICES.get(sp) or ""
                f = self.flows[key] = {
                    "id": self.seq, "proto": proto, "a": p["src"], "ap": sp, "b": p["dst"], "bp": dp, "packets": 0, "bytes": 0,
                    "a2b": 0, "b2a": 0, "start": now, "last": now, "state": "" if proto != "TCP" else None, "service": svc,
                    "chunks": [], "chunk_bytes": 0, "frames": deque(maxlen=400), "app": None,
                }
            fwd = (p["src"], sp) == (f["a"], f["ap"])
            f["packets"] += 1
            f["bytes"] += p["length"]
            f["a2b" if fwd else "b2a"] += p["length"]
            f["last"] = now
            f["frames"].append(frame_id)
            if p.get("app"):
                f["app"] = p["app"]
            if proto == "TCP":
                self._state(f, p["flags"], fwd)
                pl = p.get("payload") or b""
                if pl and f["chunk_bytes"] < MAX_CHUNK_BYTES and len(f["chunks"]) < 250:
                    f["chunks"].append((0 if fwd else 1, now, pl[:1200]))
                    f["chunk_bytes"] += len(pl[:1200])

    def _state(self, f, flags, fwd):
        s = f["state"]
        if "R" in flags:
            f["state"] = "RESET"
        elif "S" in flags and "A" not in flags:
            f["state"] = s if s in ("SYN_SENT",) else "SYN_SENT" if s is None else s
        elif "S" in flags and "A" in flags:
            f["state"] = "SYN_RECEIVED"
        elif "F" in flags:
            f["state"] = "CLOSED" if s in ("CLOSING", "CLOSED") else "CLOSING"
        elif "A" in flags:
            if s in (None, "SYN_RECEIVED", "SYN_SENT"):
                f["state"] = "ESTABLISHED" if s != "SYN_SENT" or not fwd or True else s
            elif s == "CLOSING":
                f["state"] = "CLOSING"

    def listing(self, state=None, limit=300, text=""):
        with self.lock:
            rows = []
            for f in self.flows.values():
                if state and f["state"] != state:
                    continue
                row = {k: f[k] for k in ("id", "proto", "a", "ap", "b", "bp", "packets", "bytes", "a2b", "b2a", "start", "last", "state", "service", "app")}
                if text and text.lower() not in ("%s %s %s %s %s %s" % (row["a"], row["b"], row["ap"], row["bp"], row["service"], row["proto"])).lower():
                    continue
                rows.append(row)
        rows.sort(key=lambda r: r["last"], reverse=True)
        return rows[:limit]

    def get(self, fid):
        with self.lock:
            for f in self.flows.values():
                if f["id"] == fid:
                    return f
        return None

    def sessions(self, limit=300):
        rows = [r for r in self.listing(limit=5000) if r["proto"] == "TCP"]
        return rows[:limit]
