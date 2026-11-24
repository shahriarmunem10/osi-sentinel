(function () {
  "use strict";
  var csrf = (document.querySelector('meta[name="csrf"]') || {}).content || "";
  var page = document.body.dataset.page;
  var LAYERS = {1: "Physical", 2: "Data Link", 3: "Network", 4: "Transport", 5: "Session", 6: "Presentation", 7: "Application"};
  var SEV_COLORS = {Critical: "#e5484d", High: "#ef8a3c", Medium: "#e6b422", Low: "#6fa8dc"};

  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) { return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]; }); }
  function api(url, body) {
    var opt = {headers: {"X-CSRF-Token": csrf}};
    if (body !== undefined) {
      opt.method = "POST";
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body);
    }
    return fetch(url, opt).then(function (r) {
      if (r.status === 401) { location.href = "/login"; throw new Error("auth"); }
      return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || "Request failed"); return j; });
    });
  }
  function fmtTime(ts) { var d = new Date(ts * 1000); return d.toLocaleTimeString([], {hour12: false}); }
  function fmtDate(ts) { var d = new Date(ts * 1000); return d.toLocaleDateString() + " " + d.toLocaleTimeString([], {hour12: false}); }
  function fmtNum(n) { return Number(n || 0).toLocaleString(); }
  function fmtBytes(b) {
    var u = ["B", "KB", "MB", "GB"], i = 0; b = Number(b || 0);
    while (b >= 1024 && i < 3) { b /= 1024; i++; }
    return b.toFixed(i ? 1 : 0) + " " + u[i];
  }
  function badge(s) { return '<span class="badge b-' + esc(s) + '">' + esc(s) + "</span>"; }
  function lay(n) { return '<span class="lay">L' + n + "</span>"; }

  function setStatus(st) {
    if (!st) return;
    $("modeDot").className = "dot " + st.mode;
    var label = {live: "Live capture", demo: "Demo mode", error: "Capture error", idle: "Idle"}[st.mode] || st.mode;
    $("modeText").textContent = label;
    $("modePill").title = st.iface || "";
    var b = $("errBanner");
    if (st.error) {
      b.innerHTML = '<div class="banner err">Live capture is not available: ' + esc(st.error) + ". " + (st.mode === "demo" ? "The dashboard is running in Demo mode instead." : "") + "</div>";
    } else { b.innerHTML = ""; }
  }

  function alertRow(a, detail) {
    return '<tr data-id="' + a.id + '" style="cursor:' + (detail ? "pointer" : "default") + '"><td class="mono">' + fmtTime(a.ts) + "</td><td>" + lay(a.layer) + "</td><td>" + esc(a.threat) + "</td><td>" + badge(a.severity) + '</td><td class="mono">' + esc(a.src) + "</td>" + (detail ? '<td class="mono">' + esc(a.dst) + "</td>" : "") + "</tr>";
  }

  var charts = {};
  function chartDefaults() {
    if (window.Chart) {
      Chart.defaults.color = "#8397ad";
      Chart.defaults.borderColor = "#27384d";
      Chart.defaults.font.family = "Segoe UI, system-ui, sans-serif";
    }
  }

  function initOverview() {
    chartDefaults();
    charts.rate = new Chart($("rateChart"), {
      type: "line",
      data: {labels: [], datasets: [{label: "Packets per second", data: [], borderColor: "#46c2cb", backgroundColor: "rgba(70,194,203,.15)", fill: true, tension: .3, pointRadius: 0, borderWidth: 2}]},
      options: {maintainAspectRatio: false, animation: false, plugins: {legend: {display: false}}, scales: {x: {ticks: {maxTicksLimit: 6}}, y: {beginAtZero: true}}}
    });
    charts.sev = new Chart($("sevChart"), {
      type: "doughnut",
      data: {labels: ["Critical", "High", "Medium", "Low"], datasets: [{data: [0, 0, 0, 0], backgroundColor: ["#e5484d", "#ef8a3c", "#e6b422", "#6fa8dc"], borderWidth: 0}]},
      options: {maintainAspectRatio: false, animation: false, cutout: "62%", plugins: {legend: {position: "right"}}}
    });
    var stack = "";
    for (var i = 7; i >= 1; i--) {
      stack += '<div class="band"><span class="n">L' + i + "</span><span>" + LAYERS[i] + '</span><div class="bar"><i id="bar' + i + '"></i></div><span class="a" id="al' + i + '">0</span></div>';
    }
    $("stack").innerHTML = stack;
    api("/api/scenarios").then(function (d) {
      $("scenarios").innerHTML = d.scenarios.map(function (s) { return '<button class="btn ghost sm" data-s="' + s.id + '">L' + s.layer + " " + esc(s.label) + "</button>"; }).join("");
    });
    $("scenarios").addEventListener("click", function (e) {
      var b = e.target.closest("button"); if (b) api("/api/scenario/" + b.dataset.s, {});
    });
    $("runAll").onclick = function () { api("/api/scenario/all", {}); };
    $("resetBtn").onclick = function () { if (confirm("Delete all alerts, packets and counters?")) api("/api/reset", {}).then(refresh); };
    $("modeBtn").onclick = function () {
      var cur = $("modeText").textContent.indexOf("Live") === 0 ? "demo" : "live";
      api("/api/mode", {mode: cur}).then(function (st) { setStatus(st); setTimeout(refresh, 500); }).catch(function (e) { alert(e.message); });
    };
    function refresh() {
      api("/api/overview").then(function (d) {
        setStatus(d.status);
        $("kPackets").textContent = fmtNum(d.total);
        $("kPps").textContent = d.pps;
        $("kAlerts").textContent = fmtNum(d.alert_total);
        var payload = d.tls + d.plain;
        $("kEnc").textContent = payload ? Math.round(d.tls / payload * 100) + "%" : "n/a";
        var maxPk = Math.max.apply(null, [1].concat(Object.keys(d.layer_pkts).map(function (k) { return d.layer_pkts[k]; })));
        for (var i = 1; i <= 7; i++) {
          var a = d.layer_alerts[i] || 0;
          $("al" + i).textContent = a;
          $("al" + i).className = "a" + (a ? " hot" : "");
          $("bar" + i).style.width = (i === 1 ? 0 : Math.round((d.layer_pkts[i] || 0) / maxPk * 100)) + "%";
        }
        charts.rate.data.labels = d.rate.map(function (r) { return fmtTime(r.t); });
        charts.rate.data.datasets[0].data = d.rate.map(function (r) { return r.pps; });
        charts.rate.update();
        charts.sev.data.datasets[0].data = ["Critical", "High", "Medium", "Low"].map(function (k) { return d.severity[k] || 0; });
        charts.sev.update();
        var totalP = Math.max(1, d.total);
        $("protos").innerHTML = d.protocols.map(function (p) { return '<div class="hbar"><span>' + esc(p[0]) + '</span><div class="t"><i style="width:' + Math.round(p[1] / totalP * 100) + '%"></i></div><span class="mono">' + fmtNum(p[1]) + "</span></div>"; }).join("") || '<span class="sub">No traffic yet.</span>';
        var maxT = d.talkers.length ? d.talkers[0][1] : 1;
        $("talkers").innerHTML = d.talkers.map(function (p) { return '<div class="hbar"><span class="mono">' + esc(p[0]) + '</span><div class="t"><i style="width:' + Math.round(p[1] / maxT * 100) + '%"></i></div><span class="mono">' + fmtNum(p[1]) + "</span></div>"; }).join("") || '<span class="sub">No traffic yet.</span>';
        $("recent").innerHTML = d.recent_alerts.map(function (a) { return alertRow(a, false); }).join("") || '<tr><td colspan="5" class="sub">No alerts yet. Run a scenario below or start the attack simulator.</td></tr>';
      }).catch(function () {});
    }
    refresh();
    setInterval(refresh, 2000);
  }

  function initLayers() {
    function refresh() {
      api("/api/layers").then(function (d) {
        setStatus(d.status);
        $("layerCards").onclick = function (e) { var c = e.target.closest("[data-href]"); if (c) location.href = c.dataset.href; };
        $("layerCards").innerHTML = d.cards.map(function (c) {
          var last = c.last ? esc(c.last.threat) + " " + badge(c.last.severity) + " at " + fmtTime(c.last.ts) : "No alert on this layer yet";
          return '<div class="card lcard clickable" data-href="/layer/' + c.layer + '"><h3><span>L' + c.layer + " " + c.name + " &rarr;</span><span>" + (c.alerts ? '<span class="badge b-High">' + c.alerts + " alerts</span>" : '<span class="sub">clean</span>') + "</span></h3>" +
            (c.packets !== null ? '<div class="m"><span>Packets classified here</span><span>' + fmtNum(c.packets) + "</span></div>" : "") +
            c.metrics.map(function (m) { return '<div class="m"><span>' + esc(m.label) + "</span><span>" + fmtNum(m.value) + "</span></div>"; }).join("") +
            '<div class="last">' + last + "</div></div>";
        }).join("");
        $("ifaces").innerHTML = d.interfaces.map(function (i) {
          return "<tr><td>" + esc(i.name) + '</td><td><span class="dot ' + (i.up ? "live" : "error") + '" style="display:inline-block"></span> ' + (i.up ? "up" : "down") + '</td><td class="mono">' + esc(i.ip || "-") + "</td><td>" + (i.speed ? i.speed + " Mbps" : "-") + '</td><td class="mono">' + fmtBytes(i.rx_bps) + '/s</td><td class="mono">' + fmtBytes(i.tx_bps) + '/s</td><td>' + i.errors + "</td><td>" + i.drops + "</td></tr>";
        }).join("") || '<tr><td colspan="8" class="sub">No interface data yet.</td></tr>';
      }).catch(function () {});
    }
    refresh();
    setInterval(refresh, 2000);
  }

  function initAlerts() {
    var rows = {};
    function refresh() {
      var qs = "layer=" + encodeURIComponent($("fLayer").value) + "&severity=" + encodeURIComponent($("fSev").value) + "&q=" + encodeURIComponent($("fQ").value);
      api("/api/alerts?" + qs).then(function (d) {
        rows = {};
        d.alerts.forEach(function (a) { rows[a.id] = a; });
        $("alertRows").innerHTML = d.alerts.map(function (a) { return alertRow(a, true); }).join("") || '<tr><td colspan="6" class="sub">No alerts match these filters.</td></tr>';
      }).catch(function () {});
    }
    ["fLayer", "fSev"].forEach(function (id) { $(id).onchange = refresh; });
    $("fQ").oninput = refresh;
    $("clearAlerts").onclick = function () { if (confirm("Delete all alerts?")) api("/api/alerts/clear", {}).then(refresh); };
    $("alertRows").addEventListener("click", function (e) {
      var tr = e.target.closest("tr[data-id]"); if (!tr) return;
      var nxt = tr.nextElementSibling;
      if (nxt && nxt.classList.contains("detail")) { nxt.remove(); return; }
      var a = rows[tr.dataset.id]; if (!a) return;
      var d = document.createElement("tr");
      d.className = "detail";
      d.innerHTML = '<td colspan="6">' + esc(fmtDate(a.ts)) + " | Layer " + a.layer + " " + LAYERS[a.layer] + " | " + esc(a.detail) + "</td>";
      tr.parentNode.insertBefore(d, tr.nextSibling);
    });
    refresh();
    setInterval(function () { if (!document.querySelector(".detail")) refresh(); }, 2500);
  }

  function initPackets() {
    var paused = false;
    function refresh() {
      if (paused) return;
      api("/api/packets?layer=" + encodeURIComponent($("pLayer").value) + "&q=" + encodeURIComponent($("pQ").value)).then(function (d) {
        $("pktRows").innerHTML = d.packets.map(function (p) {
          return '<tr><td class="mono">' + fmtTime(p.ts) + "</td><td>" + lay(p.layer) + '</td><td class="mono">' + esc(p.src) + '</td><td class="mono">' + esc(p.dst) + "</td><td>" + esc(p.proto) + '</td><td class="mono">' + p.length + '</td><td class="mono' + (p.sim ? " tag-sim" : "") + '">' + esc(p.info) + "</td></tr>";
        }).join("") || '<tr><td colspan="7" class="sub">No packets match.</td></tr>';
      }).catch(function () {});
    }
    $("pPause").onclick = function () { paused = !paused; this.textContent = paused ? "Resume" : "Pause"; };
    $("pLayer").onchange = refresh;
    $("pQ").oninput = refresh;
    refresh();
    setInterval(refresh, 1500);
  }

  function initCrypto() {
    function show(id, text, state) {
      var el = $(id); el.hidden = false; el.textContent = text;
      el.className = "result" + (state === true ? " ok" : state === false ? " bad" : "");
    }
    function call(op, body, onOk, outId) {
      api("/api/crypto/" + op, body).then(onOk).catch(function (e) { show(outId, e.message, false); });
    }
    $("hGo").onclick = function () {
      call("sha256", {text: $("hText").value, compare: $("hCmp").value}, function (d) {
        var t = "SHA-256: " + d.digest;
        if (d.compare_digest) t += "\nSecond:  " + d.compare_digest + "\nBits that differ: " + d.bits_changed + " of 256 (" + d.percent_changed + "%)";
        show("hOut", t);
      }, "hOut");
    };
    $("aEnc").onclick = function () {
      call("aes_encrypt", {text: $("aText").value, password: $("aPass").value}, function (d) {
        $("aPkg").value = d.package; show("aOut", d.algorithm + "\nciphertext: " + d.ciphertext, true);
      }, "aOut");
    };
    $("aDec").onclick = function () {
      call("aes_decrypt", {package: $("aPkg").value, password: $("aPass").value}, function (d) {
        show("aOut", d.ok ? d.message + "\n" + d.plaintext : d.message, d.ok);
      }, "aOut");
    };
    $("rGenKey").onclick = function () {
      show("rOut", "Generating 2048-bit key pair...");
      call("rsa_generate", {}, function (d) {
        $("rPub").value = d.public_pem; $("rPriv").value = d.private_pem; show("rOut", "Key pair generated (" + d.bits + " bits).", true);
      }, "rOut");
    };
    $("rEnc").onclick = function () {
      call("rsa_encrypt", {text: $("rText").value, public_pem: $("rPub").value}, function (d) { $("rCt").value = d.ciphertext; show("rOut", "Encrypted (" + d.padding + ").", true); }, "rOut");
    };
    $("rDec").onclick = function () {
      call("rsa_decrypt", {ciphertext: $("rCt").value, private_pem: $("rPriv").value}, function (d) { show("rOut", d.ok ? d.message + "\n" + d.plaintext : d.message, d.ok); }, "rOut");
    };
    $("sSign").onclick = function () {
      call("sign", {text: $("sText").value, private_pem: $("rPriv").value}, function (d) { $("sSig").value = d.signature; show("sOut", "Signed (" + d.scheme + ").", true); }, "sOut");
    };
    $("sVer").onclick = function () {
      call("verify", {text: $("sText").value, signature: $("sSig").value, public_pem: $("rPub").value}, function (d) { show("sOut", d.message, d.ok); }, "sOut");
    };
  }

  function initReports() {
    function refresh() {
      api("/api/reports").then(function (d) {
        $("rList").innerHTML = d.reports.map(function (r) {
          return '<tr><td class="mono">' + esc(r.name) + "</td><td>" + fmtDate(r.mtime) + "</td><td>" + fmtBytes(r.size) + '</td><td><a class="btn sm" target="_blank" href="/reports/files/' + encodeURIComponent(r.name) + '">Open</a> <a class="btn ghost sm" href="/reports/files/' + encodeURIComponent(r.name) + '?download=1">Download</a></td></tr>';
        }).join("") || '<tr><td colspan="4" class="sub">No reports yet. Generate the first one above.</td></tr>';
      });
    }
    $("rGen").onclick = function () {
      $("rMsg").innerHTML = '<p class="sub">Generating...</p>';
      api("/api/reports/generate", {range: $("rRange").value}).then(function (d) {
        $("rMsg").innerHTML = '<p>Report ready: <a target="_blank" href="/reports/files/' + encodeURIComponent(d.name) + '">' + esc(d.name) + "</a></p>";
        refresh();
      }).catch(function (e) { $("rMsg").innerHTML = '<div class="result bad">' + esc(e.message) + "</div>"; });
    };
    refresh();
  }

  if (page !== "account") {
    api("/api/layers").then(function (d) { setStatus(d.status); }).catch(function () {});
  }
  window.Sentinel = {api: api, esc: esc, fmtTime: fmtTime, fmtDate: fmtDate, fmtNum: fmtNum, fmtBytes: fmtBytes, badge: badge, lay: lay, setStatus: setStatus, $: $, LAYERS: LAYERS, alertRow: alertRow,
    pages: {overview: initOverview, layers: initLayers, alerts: initAlerts, packets: initPackets, crypto: initCrypto, reports: initReports}};
  document.addEventListener("DOMContentLoaded", function () { var f = window.Sentinel.pages[page]; if (f) f(); });
})();
