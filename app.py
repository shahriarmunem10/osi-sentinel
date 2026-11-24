import argparse
import ctypes
import hmac
import os
import secrets
import sys
import time
from functools import wraps

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import config
from sentinel import crypto_lab, db, report, scenarios, web_extra
from sentinel.engine import LAYER_NAMES, Engine

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=1024 * 1024)

engine = Engine()
fail_log = {}

OPEN_ENDPOINTS = {"login", "static", "api_inject"}
PAGES = [
    ("overview", "Overview", "/"),
    ("layers", "Layer Monitor", "/layers"),
    ("devices", "Devices", "/devices"),
    ("topology", "Topology", "/topology"),
    ("flows", "Conversations", "/flows"),
    ("packets", "Packet Inspector", "/packets"),
    ("alerts", "Alerts", "/alerts"),
    ("rules", "Rules", "/rules"),
    ("crypto", "Crypto Lab", "/crypto"),
    ("reports", "Reports", "/reports"),
]
ALERT_COLS = "id,ts,layer,threat,severity,src,dst,detail,(evidence IS NOT NULL AND evidence != '[]') AS has_ev"


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.context_processor
def inject_globals():
    return {
        "csrf_token": csrf_token(),
        "pages": PAGES,
        "title": config.PROJECT_TITLE,
        "subtitle": config.PROJECT_SUBTITLE,
        "footer": config.FOOTER_TEXT,
        "user": session.get("user"),
        "layer_names": LAYER_NAMES,
    }


@app.before_request
def guard():
    ep = request.endpoint
    if ep is None or ep == "static":
        return None
    if request.method == "POST" and ep != "api_inject":
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf") or ""
        if not hmac.compare_digest(sent, session.get("csrf", "x")):
            return jsonify(error="Invalid CSRF token. Reload the page."), 400
    if ep in OPEN_ENDPOINTS:
        return None
    if not session.get("user"):
        if request.path.startswith("/api/"):
            return jsonify(error="Not authenticated"), 401
        return redirect(url_for("login"))
    return None


@app.after_request
def headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp


def ensure_admin():
    rows = db.query("SELECT id FROM users WHERE username=?", (config.DEFAULT_ADMIN_USER,))
    if not rows:
        db.execute(
            "INSERT INTO users(username,pw_hash,must_change) VALUES(?,?,1)",
            (config.DEFAULT_ADMIN_USER, generate_password_hash(config.DEFAULT_ADMIN_PASSWORD, method="pbkdf2:sha256")),
        )


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    ip = request.remote_addr or "?"
    if request.method == "POST":
        now = time.time()
        count, until = fail_log.get(ip, (0, 0))
        if until > now:
            error = "Too many failed attempts. Try again in %d seconds." % int(until - now)
        else:
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            rows = db.query("SELECT * FROM users WHERE username=?", (username,))
            if rows and check_password_hash(rows[0]["pw_hash"], password):
                fail_log.pop(ip, None)
                session.clear()
                session["user"] = rows[0]["username"]
                session["must_change"] = bool(rows[0]["must_change"])
                csrf_token()
                return redirect(url_for("overview"))
            count += 1
            until = now + 60 if count >= config.THRESHOLDS["login_fail"] else 0
            fail_log[ip] = (count, until)
            if until:
                engine.alert(7, "Dashboard Brute-Force Attempt", "High", ip, "dashboard", "%d failed logins for user '%s'" % (count, username[:30]))
                fail_log[ip] = (0, until)
            error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
def account():
    msg = None
    ok = False
    if request.method == "POST":
        old = request.form.get("old", "")
        new = request.form.get("new", "")
        rows = db.query("SELECT * FROM users WHERE username=?", (session["user"],))
        if not rows or not check_password_hash(rows[0]["pw_hash"], old):
            msg = "Current password is incorrect."
        elif len(new) < 8:
            msg = "New password must be at least 8 characters."
        else:
            db.execute(
                "UPDATE users SET pw_hash=?, must_change=0 WHERE username=?",
                (generate_password_hash(new, method="pbkdf2:sha256"), session["user"]),
            )
            session["must_change"] = False
            msg, ok = "Password updated.", True
    return render_template("account.html", page="account", msg=msg, ok=ok)


def page(name):
    return render_template("%s.html" % name, page=name, must_change=session.get("must_change", False))


@app.route("/")
def overview():
    return page("overview")


@app.route("/layers")
def layers():
    return page("layers")


@app.route("/alerts")
def alerts_page():
    return page("alerts")


@app.route("/packets")
def packets_page():
    return page("packets")


@app.route("/crypto")
def crypto():
    return page("crypto")


@app.route("/reports")
def reports_page():
    return page("reports")


@app.route("/devices")
def devices_page():
    return page("devices")


@app.route("/topology")
def topology_page():
    return page("topology")


@app.route("/flows")
def flows_page():
    return page("flows")


@app.route("/rules")
def rules_page():
    return page("rules")


@app.route("/layer/<int:n>")
def layer_page(n):
    if n < 1 or n > 7:
        abort(404)
    return render_template("layer_detail.html", page="layers", n=n, lname=LAYER_NAMES[n], must_change=session.get("must_change", False))


def status_block():
    return {
        "mode": engine.mode,
        "error": engine.error,
        "iface": engine.iface_desc,
        "uptime": int(time.time() - engine.started),
    }


@app.route("/api/overview")
def api_overview():
    with engine.lock:
        data = {
            "status": status_block(),
            "total": engine.total,
            "bytes": engine.total_bytes,
            "pps": round(engine.pps, 1),
            "bps": round(engine.bps, 1),
            "layer_pkts": dict(engine.layer_pkts),
            "tls": engine.tls,
            "plain": engine.plain,
            "rate": list(engine.rate)[-60:],
            "talkers": engine.talkers.most_common(6),
            "protocols": engine.proto.most_common(8),
        }
    rows = db.query("SELECT layer, severity, COUNT(*) c FROM alerts GROUP BY layer, severity")
    la = {str(i): 0 for i in range(1, 8)}
    sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in rows:
        la[str(r["layer"])] += r["c"]
        sev[r["severity"]] = sev.get(r["severity"], 0) + r["c"]
    data["layer_alerts"] = la
    data["severity"] = sev
    data["alert_total"] = sum(sev.values())
    data["recent_alerts"] = db.query("SELECT %s FROM alerts ORDER BY id DESC LIMIT 8" % ALERT_COLS)
    return jsonify(data)


@app.route("/api/layers")
def api_layers():
    m = engine.detectors.m
    with engine.lock:
        pk = dict(engine.layer_pkts)
        tls, plain = engine.tls, engine.plain
    la = {r["layer"]: r for r in db.query("SELECT layer, COUNT(*) c, MAX(ts) last FROM alerts GROUP BY layer")}
    last = {}
    for layer in range(1, 8):
        rows = db.query("SELECT threat, severity, ts FROM alerts WHERE layer=? ORDER BY id DESC LIMIT 1", (layer,))
        last[layer] = rows[0] if rows else None
    cards = []
    metrics = {
        1: [("Interfaces up", sum(1 for i in engine.if_snapshot if i["up"])), ("Interfaces total", len(engine.if_snapshot))],
        2: [("ARP packets", m["arp"]), ("ARP table entries", m["arp_entries"])],
        3: [("ICMP echo requests", m["icmp_echo"]), ("Fragmented packets", m["frag"])],
        4: [("TCP SYN packets", m["syn"]), ("Hosts in 10s window", len(engine.detectors.scan))],
        5: [("Half-open sessions", m["half_open"]), ("Tracked resets (10s)", sum(len(d) for d in engine.detectors.rst.values()))],
        6: [("TLS records", tls), ("Cleartext packets", plain)],
        7: [("HTTP requests", m["http_req"]), ("Malicious HTTP", m["http_bad"]), ("DNS queries", m["dns"])],
    }
    for layer in range(1, 8):
        cards.append(
            {
                "layer": layer,
                "name": LAYER_NAMES[layer],
                "packets": pk.get(layer) if layer > 1 else None,
                "alerts": la[layer]["c"] if layer in la else 0,
                "last": last[layer],
                "metrics": [{"label": a, "value": b} for a, b in metrics[layer]],
            }
        )
    return jsonify(cards=cards, interfaces=engine.if_snapshot, status=status_block())


@app.route("/api/alerts")
def api_alerts():
    sql, args = "SELECT %s FROM alerts WHERE 1=1" % ALERT_COLS, []
    layer = request.args.get("layer", "")
    sev = request.args.get("severity", "")
    q = request.args.get("q", "").strip()
    if layer.isdigit():
        sql += " AND layer=?"
        args.append(int(layer))
    if sev in ("Critical", "High", "Medium", "Low"):
        sql += " AND severity=?"
        args.append(sev)
    if q:
        sql += " AND (threat LIKE ? OR src LIKE ? OR dst LIKE ? OR detail LIKE ?)"
        args += ["%" + q + "%"] * 4
    sql += " ORDER BY id DESC LIMIT 300"
    return jsonify(alerts=db.query(sql, args))


@app.route("/api/alerts/clear", methods=["POST"])
def api_alerts_clear():
    db.clear_alerts()
    return jsonify(ok=True)


@app.route("/api/reset", methods=["POST"])
def api_reset():
    engine.reset()
    return jsonify(ok=True)


@app.route("/api/scenarios")
def api_scenarios():
    return jsonify(scenarios=scenarios.listing())


@app.route("/api/scenario/<name>", methods=["POST"])
def api_scenario(name):
    if not scenarios.run(engine, name):
        abort(404)
    return jsonify(ok=True)


@app.route("/api/inject", methods=["POST"])
def api_inject():
    if request.remote_addr not in ("127.0.0.1", "::1"):
        abort(403)
    if not hmac.compare_digest(request.headers.get("X-Token", ""), config.API_TOKEN):
        abort(403)
    name = (request.get_json(silent=True) or {}).get("scenario", "")
    if not scenarios.run(engine, name):
        abort(404)
    return jsonify(ok=True)


@app.route("/api/mode", methods=["POST"])
def api_mode():
    mode = (request.get_json(silent=True) or {}).get("mode")
    if mode not in ("live", "demo"):
        abort(400)
    engine.start(mode)
    return jsonify(status_block())


@app.route("/api/crypto/<op>", methods=["POST"])
def api_crypto(op):
    try:
        return jsonify(crypto_lab.run(op, request.get_json(silent=True) or {}))
    except (ValueError, KeyError) as exc:
        return jsonify(error=str(exc)), 400
    except Exception:
        return jsonify(error="Operation failed. Check the inputs (keys must be valid PEM text)."), 400


@app.route("/api/reports")
def api_reports():
    return jsonify(reports=report.list_reports())


@app.route("/api/reports/generate", methods=["POST"])
def api_reports_generate():
    rng = (request.get_json(silent=True) or {}).get("range", "all")
    return jsonify(name=report.build(engine, rng))


@app.route("/reports/files/<path:name>")
def report_file(name):
    if not name.endswith(".html"):
        abort(404)
    return send_from_directory(config.REPORT_DIR, name, as_attachment=request.args.get("download") == "1")


web_extra.register(app, engine)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        try:
            return os.geteuid() == 0
        except Exception:
            return False


def main():
    parser = argparse.ArgumentParser(description="OSI Sentinel")
    parser.add_argument("--mode", choices=["auto", "live", "demo"], default="auto")
    parser.add_argument("--iface", default="auto")
    parser.add_argument("--host", default=config.HOST)
    parser.add_argument("--port", type=int, default=config.PORT)
    args = parser.parse_args()
    config.PORT = args.port
    db.init()
    ensure_admin()
    print("=" * 64)
    print(" OSI Sentinel - starting")
    print(" Administrator rights:", "yes" if is_admin() else "NO (live capture may fail)")
    engine.start(args.mode, args.iface)
    print(" Mode:", engine.mode.upper(), "|", engine.iface_desc)
    if engine.error:
        print(" Capture note:", engine.error)
    print(" Dashboard: http://%s:%d" % (args.host, args.port))
    print(" Login: %s / %s" % (config.DEFAULT_ADMIN_USER, config.DEFAULT_ADMIN_PASSWORD))
    print("=" * 64)
    app.run(host=args.host, port=args.port, threaded=True, use_reloader=False)


if __name__ == "__main__":
    sys.exit(main())
