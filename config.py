import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
REPORT_DIR = os.path.join(INSTANCE_DIR, "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

DB_PATH = os.path.join(INSTANCE_DIR, "sentinel.db")
HOST = "127.0.0.1"
PORT = 5000

DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD = "Sentinel@2026"

PROJECT_TITLE = "OSI Sentinel"
PROJECT_SUBTITLE = "Seven-Layer Network Security Monitoring and Threat Detection System"
FOOTER_TEXT = (
    "University of Frontier Technology, Bangladesh | Dept. of Cyber Security Engineering | "
    "CySE 228 Network and Internet Security Sessional | "
    "Mahi Uddin Alif (2304007), Md. Raju Ahmed (2304020), Kazi Md. Munem Shahriar Kabir (2304033)"
)


def _persisted(name, factory):
    path = os.path.join(INSTANCE_DIR, name)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            value = fh.read().strip()
            if value:
                return value
    value = factory()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(value)
    return value


SECRET_KEY = _persisted("secret.key", lambda: secrets.token_hex(32))
API_TOKEN = _persisted("api_token.txt", lambda: secrets.token_hex(16))

THRESHOLDS = {
    "window_seconds": 10,
    "alert_cooldown": 30,
    "arp_flood": 30,
    "icmp_flood": 40,
    "ping_sweep": 8,
    "big_icmp": 1000,
    "frag": 20,
    "low_ttl": 2,
    "low_ttl_count": 5,
    "port_scan": 15,
    "syn_flood": 100,
    "half_open": 50,
    "rst_burst": 30,
    "dns_flood": 40,
    "dns_long": 52,
    "dns_label": 40,
    "if_errors": 10,
    "login_fail": 5,
}

DASHBOARD_PORT_IGNORE = True
DEFAULT_THRESHOLDS = dict(THRESHOLDS)
DISABLED_THREATS = set()
SETTINGS_FILE = os.path.join(INSTANCE_DIR, "settings.json")


def load_settings():
    import json

    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return
    for k, v in (data.get("thresholds") or {}).items():
        if k in THRESHOLDS and isinstance(v, int):
            THRESHOLDS[k] = v
    DISABLED_THREATS.clear()
    DISABLED_THREATS.update(data.get("disabled") or [])


def save_settings():
    import json

    with open(SETTINGS_FILE, "w", encoding="utf-8") as fh:
        json.dump({"thresholds": THRESHOLDS, "disabled": sorted(DISABLED_THREATS)}, fh, indent=1)


load_settings()
