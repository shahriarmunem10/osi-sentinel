import base64
import functools
import ipaddress
import json
import struct
import time

from flask import Response, abort, jsonify, request

import config
from . import db, decoder, filtering, rules
from .devices import norm_mac, os_guess, vendor_of
from .engine import LAYER_NAMES

LINK_TYPES = {"ethernet": 1, "null": 0, "ip": 101}


@functools.lru_cache(maxsize=2048)
def vendor_cached(mac):
    return vendor_of(mac) or ""


def pcap_bytes(frames):
    if not frames:
        return b""
    lt = LINK_TYPES.get(frames[0][2], 1)
    out = [struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, lt)]
    for ts, raw, link in frames:
        if LINK_TYPES.get(link, 1) != lt or not raw:
            continue
        out.append(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(raw), len(raw)) + raw)
    return b"".join(out)


def pcap_response(frames, name):
    return Response(pcap_bytes(frames), mimetype="application/vnd.tcpdump.pcap", headers={"Content-Disposition": "attachment; filename=%s.pcap" % name})


def flat_of(row):
    if "_flat" not in row:
        res = decoder.parse(row["raw"], row.get("link"))
        row["_flat"], row["_info"] = res["flat"], res["info"]
    return row["_flat"]


def in_layer(flat, n, scope):
    if scope == "top":
        return flat.get("frame.layer") == n
    if n == 2:
        return True
    if n == 3:
        return bool(flat.get("ip") or flat.get("icmp"))
    if n == 4:
        return bool(flat.get("tcp") or flat.get("udp"))
    if n == 5:
        return bool(flat.get("tcp") and any(c in flat.get("tcp.flags", "") for c in "SFR"))
    if n == 6:
        return bool(flat.get("tls") or flat.get("app.cleartext"))
    if n == 7:
        return any(flat.get(k) for k in ("http", "dns", "mdns", "dhcp", "nbns", "ssdp", "app.cleartext"))
    return False


def endpoint(flat, which):
    ip = flat.get("ip.%s" % which) or flat.get("arp.%s.ip" % which) or ""
    port = flat.get("tcp.%sport" % which) or flat.get("udp.%sport" % which)
    return "%s:%s" % (ip, port) if port else ip


COLUMNS = {
    2: [("time", "Time"), ("smac", "Source MAC"), ("svendor", "Vendor"), ("dmac", "Destination MAC"), ("etype", "EtherType"), ("len", "Length"), ("info", "Info")],
    3: [("time", "Time"), ("src", "Source IP"), ("dst", "Destination IP"), ("proto", "Protocol"), ("ttl", "TTL"), ("len", "Length"), ("flags", "IP flags"), ("info", "Info")],
    4: [("time", "Time"), ("src", "Source"), ("dst", "Destination"), ("proto", "Protocol"), ("flags", "TCP flags"), ("seq", "Seq"), ("ack", "Ack"), ("win", "Window"), ("plen", "Payload")],
    5: [("time", "Time"), ("src", "Source"), ("dst", "Destination"), ("flags", "Flags"), ("seq", "Seq"), ("ack", "Ack"), ("info", "Meaning")],
    6: [("time", "Time"), ("src", "Source"), ("dst", "Destination"), ("tlsver", "TLS version"), ("rec", "Record"), ("sni", "Server name (SNI)"), ("cipher", "Cipher / offered"), ("clear", "Cleartext")],
    7: [("time", "Time"), ("src", "Source"), ("dst", "Destination"), ("proto", "Protocol"), ("info", "Summary"), ("host", "Host / name")],
}
FLAG_MEANING = {"S": "Connection request (handshake step 1)", "SA": "Connection accepted (step 2)", "A": "Acknowledgment", "PA": "Data pushed", "FA": "Closing connection", "F": "Closing connection", "R": "Connection reset", "RA": "Connection reset"}


def cells(n, row, flat):
    info = row.get("_info", "")
    base = {"id": row["id"], "ts": row["ts"], "sim": row.get("sim", False), "time": row["ts"]}
    fl = flat.get("tcp.flags", "")
    if n == 2:
        base.update(smac=flat.get("eth.src", ""), svendor=vendor_cached(flat.get("eth.src", "")) if flat.get("eth.src", "") not in ("", "loopback") else "", dmac=flat.get("eth.dst", ""), etype=flat.get("eth.type", ""), len=row["length"], info=info)
    elif n == 3:
        base.update(src=flat.get("ip.src", ""), dst=flat.get("ip.dst", ""), proto=decoder.IP_PROTOS.get(flat.get("ip.proto"), flat.get("ip.proto", "")), ttl=flat.get("ip.ttl", ""), len=flat.get("ip.len", row["length"]), flags=flat.get("ip.flags", "") or "-", info=info)
    elif n == 4:
        base.update(src=endpoint(flat, "src"), dst=endpoint(flat, "dst"), proto="TCP" if flat.get("tcp") else "UDP", flags=fl or "-", seq=flat.get("tcp.seq", ""), ack=flat.get("tcp.ack", ""), win=flat.get("tcp.win", ""), plen=flat.get("tcp.len", flat.get("udp.len", "")))
    elif n == 5:
        base.update(src=endpoint(flat, "src"), dst=endpoint(flat, "dst"), flags=fl, seq=flat.get("tcp.seq", ""), ack=flat.get("tcp.ack", ""), info=FLAG_MEANING.get(fl, ""))
    elif n == 6:
        base.update(src=endpoint(flat, "src"), dst=endpoint(flat, "dst"), tlsver=flat.get("tls.version", ""), rec=flat.get("tls.handshake_type") or flat.get("tls.record_type", ""), sni=flat.get("tls.sni", ""),
                    cipher=flat.get("tls.selected_cipher") or (("%s suites offered" % flat["tls.cipher_suites_count"]) if flat.get("tls.cipher_suites_count") else ""), clear=flat.get("app.cleartext", ""))
    elif n == 7:
        names = flat.get("dns.qry.name") or flat.get("mdns.name") or []
        base.update(src=endpoint(flat, "src"), dst=endpoint(flat, "dst"), proto=flat.get("proto", ""), info=info, host=flat.get("http.host") or (names[0] if names else "") or flat.get("dhcp.hostname", "") or flat.get("nbns.name", ""))
    return base


def register(app, engine):
    def ring():
        with engine.lock:
            return list(engine.recent)

    def get_frame(fid):
        with engine.lock:
            for row in reversed(engine.recent):
                if row["id"] == fid:
                    return row
        return None

    def decode_row(row):
        res = decoder.parse(row["raw"], row.get("link"))
        res["breakdown"] = decoder.breakdown(res)
        res["id"], res["ts"], res["sim"] = row["id"], row["ts"], row.get("sim", False)
        return res

    @app.route("/api/frame/<int:fid>")
    def api_frame(fid):
        row = get_frame(fid)
        if not row:
            return jsonify(error="This frame is no longer in memory (only the latest 5000 are kept)."), 404
        return jsonify(decode_row(row))

    @app.route("/api/decode", methods=["POST"])
    def api_decode():
        data = request.get_json(silent=True) or {}
        try:
            res = decoder.from_text(data.get("text", ""), data.get("link") or None)
        except Exception:
            return jsonify(error="Could not read the input. Paste a hex string or base64 text of one frame."), 400
        res["breakdown"] = decoder.breakdown(res)
        return jsonify(res)

    def filtered(rows, expr):
        fn = filtering.compile_filter(expr)
        if fn is None:
            return rows
        return [r for r in rows if fn(flat_of(r), r["raw"])]

    @app.route("/api/layer/<int:n>/frames")
    def api_layer_frames(n):
        if n not in COLUMNS:
            abort(404)
        scope = request.args.get("scope", "contains")
        try:
            rows = filtered(ring()[-2500:], request.args.get("filter", ""))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        out = []
        for r in reversed(rows):
            flat = flat_of(r)
            if in_layer(flat, n, scope):
                out.append(cells(n, r, flat))
                if len(out) >= 200:
                    break
        return jsonify(columns=[{"k": k, "t": t} for k, t in COLUMNS[n]], rows=out, layer=n, name=LAYER_NAMES[n])

    @app.route("/api/pcap")
    def api_pcap():
        try:
            rows = filtered(ring(), request.args.get("filter", ""))
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        n = request.args.get("layer", "")
        if n.isdigit():
            rows = [r for r in rows if in_layer(flat_of(r), int(n), "contains")]
        return pcap_response([(r["ts"], r["raw"], r["link"]) for r in rows[-2000:]], "osi-sentinel-capture")

    @app.route("/api/packets")
    def api_packets():
        q = request.args.get("q", "").strip()
        layer = request.args.get("layer", "")
        rows = ring()
        if layer.isdigit():
            rows = [r for r in rows if r["layer"] == int(layer)]
        if q:
            try:
                rows = filtered(rows[-2500:], q)
            except ValueError as exc:
                if any(t in q for t in ("==", "!=", ">", "<", " and ", " or ", "(", " contains ", "&&", "||")):
                    return jsonify(error=str(exc)), 400
                rows = [r for r in rows if q.lower() in ("%s %s %s %s" % (r["src"], r["dst"], r["proto"], r["info"])).lower()]
        keep = ("id", "ts", "src", "dst", "proto", "sport", "dport", "length", "layer", "info", "sim", "smac", "dmac")
        return jsonify(packets=[{k: r[k] for k in keep} for r in rows[-200:][::-1]])

    @app.route("/api/alerts/<int:aid>/evidence")
    def api_alert_evidence(aid):
        rows = db.query("SELECT evidence FROM alerts WHERE id=?", (aid,))
        if not rows:
            abort(404)
        items = json.loads(rows[0]["evidence"] or "[]")
        for it in items:
            res = decoder.parse(base64.b64decode(it["raw"]), it.get("link"))
            it["proto"], it["layer"] = res["proto"], res["top_layer"]
            it["src"] = res["extract"].get("Source IP", "") or res["extract"].get("Source MAC", "")
            it["dst"] = res["extract"].get("Destination IP", "") or res["extract"].get("Destination MAC", "")
            it["info"] = res["info"]
        return jsonify(items=items)

    @app.route("/api/alerts/<int:aid>/pcap")
    def api_alert_pcap(aid):
        rows = db.query("SELECT evidence FROM alerts WHERE id=?", (aid,))
        if not rows:
            abort(404)
        items = json.loads(rows[0]["evidence"] or "[]")
        return pcap_response([(i["ts"], base64.b64decode(i["raw"]), i.get("link", "ethernet")) for i in items], "alert-%d-evidence" % aid)

    @app.route("/api/flows")
    def api_flows():
        return jsonify(flows=engine.flows.listing(state=request.args.get("state") or None, text=request.args.get("q", "")), sessions=request.args.get("sessions") == "1")

    @app.route("/api/sessions")
    def api_sessions():
        return jsonify(sessions=engine.flows.sessions())

    def printable(b):
        return "".join(chr(c) if 32 <= c < 127 or c in (10, 13, 9) else "." for c in b)

    @app.route("/api/flows/<int:fid>")
    def api_flow(fid):
        f = engine.flows.get(fid)
        if not f:
            abort(404)
        frames = []
        for i in list(f["frames"])[-60:]:
            row = get_frame(i)
            if row:
                frames.append({"id": row["id"], "ts": row["ts"], "src": row["src"], "dst": row["dst"], "length": row["length"], "info": row["info"]})
        meta = {k: f[k] for k in ("id", "proto", "a", "ap", "b", "bp", "packets", "bytes", "a2b", "b2a", "start", "last", "state", "service", "app")}
        return jsonify(flow=meta, chunks=[{"dir": d, "ts": t, "len": len(b), "text": printable(b)} for d, t, b in f["chunks"]], frames=frames)

    @app.route("/api/flows/<int:fid>/pcap")
    def api_flow_pcap(fid):
        f = engine.flows.get(fid)
        if not f:
            abort(404)
        frames = [get_frame(i) for i in list(f["frames"])]
        return pcap_response([(r["ts"], r["raw"], r["link"]) for r in frames if r], "flow-%d" % fid)

    @app.route("/api/devices")
    def api_devices():
        dm = engine.devices
        devs = dm.snapshot()
        seen = sum(1 for d in devs if d["bw"]["tx_pk"] + d["bw"]["rx_pk"] > 0)
        if engine.mode == "demo":
            note = "Demo mode: devices and traffic are simulated."
        else:
            note = "Wi-Fi capture normally sees only this computer's own traffic plus broadcasts. To measure other devices, share the connection from this laptop (Windows Mobile hotspot) and capture on that adapter."
        return jsonify(devices=devs, scan=dm.scan_state, auto=dm.auto, interval=dm.auto_interval, cidr=dm.cidr, iface=dm.iface, mode=engine.mode, traffic_seen=seen, note=note)

    @app.route("/api/devices/networks")
    def api_networks():
        if engine.mode == "demo":
            return jsonify(networks=[{"iface": "demo0", "ip": "192.168.56.10", "cidr": "192.168.56.0/24", "mac": "", "gateway": "192.168.56.1", "hosts": 254}], current="192.168.56.0/24")
        return jsonify(networks=engine.devices.networks(), current=engine.devices.cidr)

    @app.route("/api/devices/scan", methods=["POST"])
    def api_scan():
        cidr = (request.get_json(silent=True) or {}).get("cidr")
        return jsonify(started=engine.devices.start_scan(cidr))

    @app.route("/api/devices/reset", methods=["POST"])
    def api_devices_reset():
        dm = engine.devices
        dm.reset()
        if dm.demo:
            dm.load_demo()
        else:
            dm.start_scan(dm.cidr)
        return jsonify(ok=True)

    @app.route("/api/devices/auto", methods=["POST"])
    def api_auto():
        engine.devices.auto = bool((request.get_json(silent=True) or {}).get("enabled"))
        return jsonify(auto=engine.devices.auto)

    @app.route("/api/devices/<mac>/ports", methods=["POST"])
    def api_ports(mac):
        ports = engine.devices.port_scan(norm_mac(mac))
        if ports is None:
            return jsonify(error="Port scan is allowed only for devices inside your own local network."), 400
        return jsonify(ports=ports)

    @app.route("/api/devices/<mac>/rename", methods=["POST"])
    def api_rename(mac):
        return jsonify(ok=engine.devices.rename(mac, str((request.get_json(silent=True) or {}).get("name", ""))))

    @app.route("/api/devices/<mac>/trust", methods=["POST"])
    def api_trust(mac):
        return jsonify(ok=engine.devices.trust(mac, bool((request.get_json(silent=True) or {}).get("known", True))))

    @app.route("/api/rules")
    def api_rules():
        t = config.THRESHOLDS
        out = []
        for r in rules.RULES:
            out.append(dict(r, enabled=not any(r["id"].startswith(x) for x in config.DISABLED_THREATS)))
        lim = {k: {"min": v[0], "max": v[1], "label": v[2], "value": t[k], "default": config.DEFAULT_THRESHOLDS[k]} for k, v in rules.LIMITS.items() if k in t}
        return jsonify(rules=out, limits=lim)

    @app.route("/api/rules", methods=["POST"])
    def api_rules_save():
        data = request.get_json(silent=True) or {}
        for k, v in (data.get("thresholds") or {}).items():
            if k not in rules.LIMITS:
                continue
            lo, hi, label = rules.LIMITS[k]
            try:
                v = int(v)
            except (TypeError, ValueError):
                return jsonify(error="%s must be a whole number" % label), 400
            if not lo <= v <= hi:
                return jsonify(error="%s must be between %d and %d" % (label, lo, hi)), 400
            config.THRESHOLDS[k] = v
        valid = {r["id"] for r in rules.RULES}
        config.DISABLED_THREATS.clear()
        config.DISABLED_THREATS.update(x for x in (data.get("disabled") or []) if x in valid)
        config.save_settings()
        return jsonify(ok=True)

    @app.route("/api/rules/reset", methods=["POST"])
    def api_rules_reset():
        config.THRESHOLDS.update(config.DEFAULT_THRESHOLDS)
        config.DISABLED_THREATS.clear()
        config.save_settings()
        return jsonify(ok=True)

    @app.route("/api/tools/<name>")
    def api_tools(name):
        v = request.args.get("v", "").strip()
        try:
            if name == "mac":
                m = norm_mac(v)
                b = bytes.fromhex(m.replace(":", ""))
                if len(b) != 6:
                    raise ValueError
                return jsonify(mac=m, vendor=vendor_cached(m) or "unknown (private or unregistered)", kind=decoder.mac_kind(b), oui=m[:8], nic=m[9:], multicast=bool(b[0] & 1), local=bool(b[0] & 2))
            if name == "subnet":
                n = ipaddress.ip_network(v, strict=False)
                hosts = list(n.hosts()) if n.num_addresses <= 1 << 16 else []
                return jsonify(network=str(n.network_address), prefix=n.prefixlen, netmask=str(n.netmask), wildcard=str(n.hostmask), broadcast=str(n.broadcast_address), first=str(hosts[0]) if hosts else "-", last=str(hosts[-1]) if hosts else "-", hosts=max(0, n.num_addresses - 2) if n.version == 4 else n.num_addresses, private=n.is_private, version=n.version)
            if name == "ip":
                ip = ipaddress.ip_address(v)
                cls = ""
                if ip.version == 4:
                    f = int(str(ip).split(".")[0])
                    cls = "A" if f < 128 else "B" if f < 192 else "C" if f < 224 else "D (multicast)" if f < 240 else "E"
                return jsonify(ip=str(ip), version=ip.version, private=ip.is_private, loopback=ip.is_loopback, multicast=ip.is_multicast, link_local=ip.is_link_local, klass=cls, reverse=ip.reverse_pointer, binary=".".join(format(int(x), "08b") for x in str(ip).split(".")) if ip.version == 4 else "")
            if name == "port":
                if v.isdigit():
                    p = int(v)
                    return jsonify(matches=[{"port": p, "service": decoder.SERVICES.get(p, "no well-known service")}])
                return jsonify(matches=[{"port": k, "service": s} for k, s in decoder.SERVICES.items() if v.lower() in s.lower()][:15])
            if name == "flags":
                val = int(v, 0) if v[:1].isdigit() else sum(bit for _, bit, c in decoder.TCP_FLAGS if c in v.upper())
                names = [n for n, bit, _ in decoder.TCP_FLAGS if val & bit]
                compact = "".join(c for _, bit, c in decoder.TCP_FLAGS if val & bit)
                return jsonify(value=val, names=names, compact=compact, meaning=FLAG_MEANING.get(compact, ""), binary=format(val, "08b"))
            if name == "ttl":
                return jsonify(os=os_guess(int(v)) or "unknown")
        except Exception:
            return jsonify(error="Could not understand the input."), 400
        abort(404)
