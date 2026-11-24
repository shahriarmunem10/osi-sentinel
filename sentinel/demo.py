import os
import random
import threading
import time

from . import scenarios as sc

LOCAL = ["192.168.56.%d" % i for i in range(10, 15)]
EXTERNAL = ["142.250.190.46", "151.101.1.69", "104.16.132.229", "93.184.216.34", "13.107.42.14"]
from .synth import mac_for

MACS = {ip: mac_for(ip) for ip in LOCAL + [sc.GATEWAY]}


class TrafficGenerator(threading.Thread):
    def __init__(self, engine):
        super().__init__(daemon=True)
        self.engine = engine
        self.stop_evt = threading.Event()

    def stop(self):
        self.stop_evt.set()

    def run(self):
        while not self.stop_evt.is_set():
            try:
                self._one()
            except Exception:
                pass
            time.sleep(random.uniform(0.02, 0.09))

    def _one(self):
        r = random.random()
        src = random.choice(LOCAL)
        ext = random.choice(EXTERNAL)
        sport = random.randint(30000, 60000)
        if r < 0.45:
            hello = b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03" + os.urandom(24)
            data = hello if random.random() < 0.1 else b"\x17\x03\x03\x00\x40" + os.urandom(40)
            self.engine.process(sc.tcp(src, ext, sport, 443, "PA", data))
        elif r < 0.60:
            self.engine.process(sc.http(src, ext, sc.req(random.choice(["/", "/index.html", "/about", "/images/logo.png"])), sport))
        elif r < 0.75:
            name = random.choice(["www.example.com.", "api.github.com.", "cdn.jsdelivr.net.", "mail.google.com."])
            self.engine.process(sc.udp(src, "8.8.8.8", sport, 53, b"\x00" * 30, dns_q=name))
        elif r < 0.88:
            self.engine.process(sc.tcp(ext, src, 443, sport, "A"))
        elif r < 0.95:
            ip = random.choice(LOCAL + [sc.GATEWAY])
            self.engine.process(sc.arp(2, ip, MACS[ip], random.choice(LOCAL)))
        else:
            self.engine.process(sc.icmp(src, sc.GATEWAY, 8))
