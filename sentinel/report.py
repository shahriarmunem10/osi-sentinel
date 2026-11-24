import json
import os
import time
from collections import Counter

import config
from . import db
from .engine import LAYER_NAMES

SEVERITIES = ["Critical", "High", "Medium", "Low"]


def collect(engine, since):
    alerts = db.query("SELECT id,ts,layer,threat,severity,src,dst,detail FROM alerts WHERE ts>=? ORDER BY ts DESC LIMIT 5000", (since,))
    stats = db.query("SELECT ts,pps,bps FROM stats WHERE ts>=? ORDER BY ts", (since,))
    if len(stats) > 400:
        step = len(stats) // 400 + 1
        stats = stats[::step]
    pk = db.query("SELECT COUNT(*) c, COALESCE(SUM(length),0) b FROM packets WHERE ts>=?", (since,))[0]
    layer_pk = db.query("SELECT layer, COUNT(*) c FROM packets WHERE ts>=? GROUP BY layer", (since,))
    proto = db.query("SELECT proto, COUNT(*) c FROM packets WHERE ts>=? GROUP BY proto ORDER BY c DESC LIMIT 10", (since,))
    talkers = db.query("SELECT src, COUNT(*) c FROM packets WHERE ts>=? AND src IS NOT NULL GROUP BY src ORDER BY c DESC LIMIT 10", (since,))
    return {
        "alerts": alerts,
        "stats": stats,
        "packets": {"count": pk["c"], "bytes": pk["b"]},
        "layer_packets": {str(r["layer"]): r["c"] for r in layer_pk},
        "protocols": proto,
        "talkers": talkers,
        "mode": engine.mode,
        "interfaces": engine.if_snapshot[:8],
        "layer_names": {str(k): v for k, v in LAYER_NAMES.items()},
    }


def build(engine, range_key="all"):
    now = time.time()
    since = {"1h": now - 3600, "24h": now - 86400}.get(range_key, 0)
    data = collect(engine, since)
    data["generated"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    data["range"] = {"1h": "Last 1 hour", "24h": "Last 24 hours"}.get(range_key, "All recorded data")
    data["title"] = config.PROJECT_TITLE
    data["subtitle"] = config.PROJECT_SUBTITLE
    data["footer"] = config.FOOTER_TEXT
    with open(os.path.join(config.BASE_DIR, "static", "chart.umd.js"), "r", encoding="utf-8") as fh:
        chart_js = fh.read().replace("</script", "<\\/script")
    with open(os.path.join(config.BASE_DIR, "templates", "report_template.html"), "r", encoding="utf-8") as fh:
        tpl = fh.read()
    payload = json.dumps(data).replace("</", "<\\/")
    html = tpl.replace("/*__CHARTJS__*/", chart_js).replace("/*__DATA__*/null", payload)
    name = "sentinel_report_%s.html" % time.strftime("%Y%m%d_%H%M%S", time.localtime(now))
    with open(os.path.join(config.REPORT_DIR, name), "w", encoding="utf-8") as fh:
        fh.write(html)
    return name


def list_reports():
    out = []
    for f in sorted(os.listdir(config.REPORT_DIR), reverse=True):
        if f.endswith(".html"):
            p = os.path.join(config.REPORT_DIR, f)
            out.append({"name": f, "size": os.path.getsize(p), "mtime": os.path.getmtime(p)})
    return out
