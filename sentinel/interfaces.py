import socket
import time

import psutil

import config

T = config.THRESHOLDS


class InterfaceMonitor:
    def __init__(self, alert):
        self.alert = alert
        self.prev = {}
        self.up = {}
        self.cool = {}

    def update(self):
        now = time.time()
        try:
            stats = psutil.net_if_stats()
            io = psutil.net_io_counters(pernic=True)
            addrs = psutil.net_if_addrs()
        except Exception:
            return []
        out = []
        for name, st in stats.items():
            c = io.get(name)
            if c is None:
                continue
            prev = self.prev.get(name)
            rx = tx = 0.0
            d_err = d_drop = 0
            if prev:
                dt = max(now - prev["t"], 0.001)
                rx = max(0.0, (c.bytes_recv - prev["recv"]) / dt)
                tx = max(0.0, (c.bytes_sent - prev["sent"]) / dt)
                d_err = (c.errin + c.errout) - prev["err"]
                d_drop = (c.dropin + c.dropout) - prev["drop"]
            self.prev[name] = {
                "t": now,
                "recv": c.bytes_recv,
                "sent": c.bytes_sent,
                "err": c.errin + c.errout,
                "drop": c.dropin + c.dropout,
            }
            ip = ""
            for a in addrs.get(name, []):
                if a.family == socket.AF_INET:
                    ip = a.address
                    break
            was_up = self.up.get(name)
            self.up[name] = st.isup
            if was_up and not st.isup and self._ok(("down", name), now):
                self.alert(1, "Network Interface Down", "High", "", name, "Link state of %s changed from up to down" % name)
            if (d_err >= T["if_errors"] or d_drop >= T["if_errors"]) and self._ok(("err", name), now):
                self.alert(
                    1,
                    "Interface Errors or Drops",
                    "Medium",
                    "",
                    name,
                    "%s reported %d errors and %d dropped packets in the last interval" % (name, d_err, d_drop),
                )
            out.append(
                {
                    "name": name,
                    "up": bool(st.isup),
                    "speed": st.speed,
                    "mtu": st.mtu,
                    "ip": ip,
                    "rx_bps": rx,
                    "tx_bps": tx,
                    "bytes_recv": c.bytes_recv,
                    "bytes_sent": c.bytes_sent,
                    "packets_recv": c.packets_recv,
                    "packets_sent": c.packets_sent,
                    "errors": c.errin + c.errout,
                    "drops": c.dropin + c.dropout,
                }
            )
        out.sort(key=lambda i: (not i["up"], -(i["rx_bps"] + i["tx_bps"]), i["name"]))
        return out

    def _ok(self, key, now):
        if now - self.cool.get(key, 0) < 60:
            return False
        self.cool[key] = now
        return True
