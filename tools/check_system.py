import ctypes
import os
import platform
import sys

print("Python:", sys.version.split()[0], "| OS:", platform.platform())
try:
    admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
except Exception:
    admin = hasattr(os, "geteuid") and os.geteuid() == 0
print("Administrator rights:", "yes" if admin else "NO")
for mod in ("flask", "scapy", "psutil", "cryptography"):
    try:
        m = __import__(mod)
        print("Module %-12s OK %s" % (mod, getattr(m, "__version__", "")))
    except Exception as exc:
        print("Module %-12s MISSING (%s)" % (mod, exc))
if platform.system() == "Windows":
    path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "Npcap", "wpcap.dll")
    print("Npcap installed:", "yes" if os.path.exists(path) else "NO - install from https://npcap.com")
try:
    from scapy.all import conf, sniff

    print("Interfaces seen by Scapy:")
    for i in conf.ifaces.values():
        print("  -", getattr(i, "name", i), getattr(i, "ip", ""))
    pk = sniff(timeout=3, count=1)
    print("Sniff test (3 seconds): captured %d packet(s)" % len(pk))
except Exception as exc:
    print("Sniff test FAILED:", type(exc).__name__, exc)
    print("The dashboard will still work in Demo mode.")
