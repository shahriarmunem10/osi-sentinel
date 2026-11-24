import argparse
import http.server
import ipaddress
import os
import platform
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import json

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN_FILE = os.path.join(ROOT, "instance", "api_token.txt")
IS_WINDOWS = platform.system() == "Windows"


class Quiet(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = do_GET
    do_HEAD = do_GET

    def log_message(self, *a):
        pass


def start_target(host, port):
    try:
        srv = http.server.ThreadingHTTPServer((host, port), Quiet)
    except OSError:
        return None
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def check_target(host):
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
    except Exception:
        sys.exit("Cannot resolve target: %s" % host)
    if not (ip.is_loopback or ip.is_private):
        sys.exit("Refusing to run: target %s is not a loopback or private address. This tool is for your own lab only." % ip)
    return str(ip)


def port_scan(ip, count, delay):
    print("[port scan] probing %d ports on %s" % (count, ip))
    for port in range(20, 20 + count):
        s = socket.socket()
        s.settimeout(0.2)
        try:
            s.connect((ip, port))
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(delay)


def syn_flood(ip, port, count, delay):
    print("[connection flood] %d rapid connections to %s:%d" % (count, ip, port))
    for _ in range(count):
        s = socket.socket()
        s.settimeout(0.3)
        try:
            s.connect((ip, port))
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(delay)


def http_attacks(ip, port):
    print("[http] sending malicious-looking requests to %s:%d" % (ip, port))
    reqs = [
        ("/item?id=1%27%20OR%20%271%27=%271", "Mozilla/5.0"),
        ("/search?q=1+UNION+SELECT+username,password+FROM+users", "Mozilla/5.0"),
        ("/c?x=%3Cscript%3Ealert(1)%3C/script%3E", "Mozilla/5.0"),
        ("/file?name=../../../../etc/passwd", "Mozilla/5.0"),
        ("/run?cmd=a;cat%20/etc/passwd", "Mozilla/5.0"),
        ("/admin", "sqlmap/1.7 (https://sqlmap.org)"),
    ]
    for path, ua in reqs:
        try:
            s = socket.create_connection((ip, port), timeout=2)
            s.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nConnection: close\r\n\r\n" % (path, ip, ua)).encode())
            s.recv(256)
            s.close()
        except Exception:
            pass
        time.sleep(0.4)


def ping_cmd(ip, n):
    if IS_WINDOWS:
        return ["ping", "-n", str(n), "-w", "300", ip]
    return ["ping", "-c", str(n), "-i", "0.2", "-W", "1", ip]


def _spawn(cmds):
    out = []
    for c in cmds:
        try:
            out.append(subprocess.Popen(c, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        except FileNotFoundError:
            print("ping command not found on this system, skipping")
            break
    return out


def icmp_flood(ip):
    print("[icmp] parallel pings to %s" % ip)
    procs = _spawn([ping_cmd(ip, 6) for _ in range(10)])
    for p in procs:
        p.wait()


def ping_sweep(base):
    print("[ping sweep] sweeping 127.0.0.1-12" if base == "127.0.0.1" else "[ping sweep] sweeping %s" % base)
    parts = base.split(".")
    procs = []
    for i in range(1, 13):
        target = "%s.%s.%s.%d" % (parts[0], parts[1], parts[2], i) if base != "127.0.0.1" else "127.0.0.%d" % i
        procs.extend(_spawn([ping_cmd(target, 1)]))
    for p in procs:
        p.wait()


def inject(name, dashboard):
    try:
        with open(TOKEN_FILE, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
        req = urllib.request.Request(
            dashboard.rstrip("/") + "/api/inject",
            data=json.dumps({"scenario": name}).encode(),
            headers={"Content-Type": "application/json", "X-Token": token},
        )
        urllib.request.urlopen(req, timeout=5).read()
        print("[inject] scenario '%s' sent to the detection engine (no packets on the wire)" % name)
    except Exception as exc:
        print("[inject] failed: %s (is the dashboard running?)" % exc)


ACTIONS = ["portscan", "synflood", "http", "icmp", "sweep", "arp", "all"]


def main():
    ap = argparse.ArgumentParser(description="OSI Sentinel attack simulator (lab use, loopback and private addresses only)")
    ap.add_argument("scenario", choices=ACTIONS)
    ap.add_argument("--target", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--count", type=int, default=60)
    ap.add_argument("--dashboard", default="http://127.0.0.1:5000")
    ap.add_argument("--no-target", action="store_true")
    a = ap.parse_args()
    ip = check_target(a.target)
    a.count = min(a.count, 400)
    srv = None
    if not a.no_target and ipaddress.ip_address(ip).is_loopback:
        srv = start_target(ip, a.port)
        print("Local test web server on %s:%d %s" % (ip, a.port, "started" if srv else "already in use (using it)"))
    todo = ["portscan", "synflood", "http", "icmp", "sweep", "arp"] if a.scenario == "all" else [a.scenario]
    for name in todo:
        if name == "portscan":
            port_scan(ip, max(a.count, 30), 0.03)
        elif name == "synflood":
            syn_flood(ip, a.port, max(a.count * 3, 150), 0.02)
        elif name == "http":
            http_attacks(ip, a.port)
        elif name == "icmp":
            icmp_flood(ip)
        elif name == "sweep":
            ping_sweep(ip)
        elif name == "arp":
            inject("arp_spoof", a.dashboard)
        time.sleep(1.5)
    print("Done. Check the Alerts page on the dashboard.")
    if srv:
        time.sleep(1)
        srv.shutdown()


if __name__ == "__main__":
    main()
