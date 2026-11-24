(function () {
  "use strict";
  var S = window.Sentinel, $ = S.$, api = S.api, esc = S.esc, fmtTime = S.fmtTime, fmtNum = S.fmtNum, fmtBytes = S.fmtBytes, badge = S.badge, lay = S.lay;
  var LAYER_INFO = {
    1: ["Bits", "The physical layer moves raw bits over cable or radio. Software cannot see signals, so this page shows the state and counters of each network adapter and how a captured frame looks as a stream of bits."],
    2: ["Frame", "The data link layer delivers frames between devices on the same network using MAC addresses. Each row below is a captured Ethernet frame. Click a row to see the MAC addresses and break the frame apart."],
    3: ["Packet", "The network layer routes packets between networks using IP addresses. Each row is a frame that carries an IP or ICMP packet, with its TTL, flags and length."],
    4: ["Segment", "The transport layer provides end-to-end delivery with ports. TCP adds sequence numbers, flags and windows. UDP is connectionless. Each row is one TCP segment or UDP datagram."],
    5: ["Session", "The session layer manages the dialogue between two programs. On the Internet this is visible as TCP sessions: opening (SYN), running, and closing (FIN or RST). Below are the live sessions and the frames that control them."],
    6: ["Data", "The presentation layer handles encryption, encoding and data formats. Here you see TLS handshakes with the server name and cipher suites, plus traffic that travels without any encryption."],
    7: ["Data", "The application layer is what programs actually speak: HTTP requests, DNS lookups, DHCP, NetBIOS and more. Each row shows the readable content of the message."]
  };
  var HEXCLS = {2: "hb2", 3: "hb3", 4: "hb4", 5: "hb5", 6: "hb6", 7: "hb7"};
  var state = {res: null, tab: "decode", sel: null};

  function fmtDur(s) { s = Math.max(0, Math.round(s)); return s < 60 ? s + " s" : Math.floor(s / 60) + " min " + (s % 60) + " s"; }
  function copy(text) { if (navigator.clipboard) navigator.clipboard.writeText(text); }
  function debounce(fn, ms) { var t; return function () { clearTimeout(t); var a = arguments; t = setTimeout(function () { fn.apply(null, a); }, ms); }; }

  function hexdump(res, sel) {
    var hex = res.hex, n = Math.min(hex.length / 2, 1600), owner = [];
    res.layers.forEach(function (L) { for (var i = L.o; i < L.o + L.l && i < n; i++) owner[i] = L.osi; });
    var out = "";
    for (var r = 0; r < n; r += 16) {
      var line = '<span class="off">' + ("0000" + r.toString(16)).slice(-4) + "</span>  ", asc = "";
      for (var i = r; i < r + 16; i++) {
        if (i < n) {
          var b = parseInt(hex.substr(i * 2, 2), 16), cls = (owner[i] ? HEXCLS[owner[i]] : "") + (sel && i >= sel.o && i < sel.o + sel.l ? " hl" : "");
          line += '<span class="' + cls + '">' + hex.substr(i * 2, 2) + "</span> ";
          asc += b >= 32 && b < 127 ? esc(String.fromCharCode(b)) : ".";
        } else { line += "   "; }
        if (i % 8 === 7) line += " ";
      }
      out += line + ' <span class="asc">' + asc + "</span>\n";
    }
    return '<div class="hex" id="hexBox">' + out + "</div>";
  }

  function renderDecode(res) {
    var h = "";
    res.layers.forEach(function (L) {
      h += '<details class="ly" open><summary>' + lay(L.osi) + " <b>" + esc(L.name) + '</b> <span class="sub" style="margin:0">' + esc(L.s) + "</span></summary><table><tbody>" +
        L.f.map(function (f) { return '<tr class="fld" data-o="' + f.o + '" data-l="' + f.l + '"><td>' + esc(f.n) + '</td><td class="mono">' + esc(f.v) + '</td><td class="sub">' + esc(f.d) + "</td></tr>"; }).join("") + "</tbody></table></details>";
    });
    return h + '<h2 style="margin:16px 0 8px">Raw bytes <span class="copy" id="cpHex">copy hex</span></h2><p class="sub" style="margin:0 0 8px">Colours match the layers above. Click a field to highlight its bytes.</p>' + hexdump(res, state.sel);
  }

  function renderDecap(res) {
    var h = '<p class="sub">A frame is a set of nested boxes. Each layer adds its own header around the data of the layer above. A receiver reverses this: every layer removes its header and passes the payload up.</p>';
    h += '<div class="decap"><div class="t"><b>Captured frame</b><span class="hd">' + res.length + " bytes in total</span></div>";
    res.breakdown.forEach(function (b) {
      h += '<div class="decap l' + b.osi + '"><div class="t">' + lay(b.osi) + "<b>" + esc(b.name) + '</b><span class="hd">header ' + b.hdr[1] + ' B</span><span class="hd">carries ' + b.payload[1] + ' B</span></div><div class="sub" style="margin:4px 0 0">' + esc(b.s) + "</div>";
    });
    res.breakdown.forEach(function () { h += "</div>"; });
    h += "</div><h2 style=\"margin:16px 0 8px\">Receiving side, step by step</h2><ol style=\"padding-left:20px;line-height:1.8\">";
    res.breakdown.forEach(function (b) {
      h += "<li><b>Layer " + b.osi + " (" + esc(b.name) + "):</b> reads the " + b.hdr[1] + "-byte header" + (b.s ? " (" + esc(b.s) + ")" : "") + ", removes it and hands " + b.payload[1] + " bytes to the next layer.</li>";
    });
    return h + "</ol>";
  }

  function renderExtract(res) {
    var h = '<p class="sub">Addresses and values pulled out of the frame headers.</p><table><tbody>';
    Object.keys(res.extract).forEach(function (k) {
      var v = String(res.extract[k]), isMac = /^[0-9a-f]{2}(:[0-9a-f]{2}){5}$/.test(v);
      h += "<tr><td>" + esc(k) + '</td><td class="mono">' + esc(v) + '<span class="copy" data-c="' + esc(v) + '">copy</span></td><td class="sub" ' + (isMac ? 'data-mac="' + esc(v) + '"' : "") + "></td></tr>";
    });
    h += "</tbody></table><h2 style=\"margin:16px 0 8px\">Integrity checks</h2><table><tbody>";
    res.layers.forEach(function (L) { L.f.forEach(function (f) { if (/checksum/i.test(f.n)) h += "<tr><td>" + esc(L.name) + " " + esc(f.n) + '</td><td class="mono">' + esc(f.v) + '</td><td class="sub">' + esc(f.d) + "</td></tr>"; }); });
    return h + "</tbody></table><p class=\"sub\">An invalid checksum on a frame sent by this computer is usually harmless: network cards often compute checksums after the capture point (checksum offload).</p>";
  }

  function renderDrawer() {
    var res = state.res; if (!res) return;
    $("dTitle").textContent = res.proto + ": " + (res.info || "");
    $("dSub").textContent = res.length + " bytes | link type: " + res.link + (res.sim ? " | simulated" : "");
    [].forEach.call($("dTabs").children, function (b) { b.className = b.dataset.t === state.tab ? "on" : ""; });
    $("dBody").innerHTML = state.tab === "decode" ? renderDecode(res) : state.tab === "decap" ? renderDecap(res) : renderExtract(res);
    if (state.tab === "extract") {
      [].forEach.call($("dBody").querySelectorAll("[data-mac]"), function (td) {
        api("/api/tools/mac?v=" + encodeURIComponent(td.dataset.mac)).then(function (m) { td.textContent = m.vendor + " | " + m.kind; }).catch(function () {});
      });
    }
  }

  function showRes(res) { state.res = res; state.sel = null; state.tab = "decode"; $("drawer").hidden = false; renderDrawer(); }
  function openFrame(id) { api("/api/frame/" + id).then(showRes).catch(function (e) { alert(e.message); }); }
  function openRaw(b64, link) { api("/api/decode", {text: b64, link: link || null}).then(showRes).catch(function (e) { alert(e.message); }); }
  S.openFrame = openFrame;
  S.openRaw = openRaw;

  $("dClose").onclick = function () { $("drawer").hidden = true; };
  document.addEventListener("keydown", function (e) { if (e.key === "Escape") $("drawer").hidden = true; });
  $("dTabs").onclick = function (e) { var b = e.target.closest("button"); if (b) { state.tab = b.dataset.t; renderDrawer(); } };
  $("dBody").onclick = function (e) {
    var tr = e.target.closest(".fld");
    if (tr) {
      [].forEach.call($("dBody").querySelectorAll(".fld.sel"), function (x) { x.classList.remove("sel"); });
      tr.classList.add("sel");
      state.sel = {o: +tr.dataset.o, l: +tr.dataset.l};
      $("hexBox").outerHTML = hexdump(state.res, state.sel);
      return;
    }
    var c = e.target.closest(".copy");
    if (c) copy(c.id === "cpHex" ? state.res.hex : c.dataset.c);
  };

  function tools(n) {
    var list = {
      2: [["MAC address lookup", "aa:bb:cc:dd:ee:ff", "mac"]],
      3: [["IP address information", "192.168.1.10", "ip"], ["Subnet calculator", "192.168.1.10/24", "subnet"], ["TTL to operating system guess", "64", "ttl"]],
      4: [["Port to service lookup", "443 or http", "port"], ["TCP flags decoder", "SA or 0x12", "flags"]],
      5: [["TCP flags decoder", "SA or 0x12", "flags"]],
      6: [], 7: []
    }[n] || [];
    var h = "";
    list.forEach(function (t, i) {
      h += '<div class="card tool"><h2>' + t[0] + '</h2><div class="row"><input data-tool="' + t[2] + '" id="tin' + i + '" placeholder="' + t[1] + '"><button class="btn" data-run="' + i + '">Run</button></div><div class="out" id="tout' + i + '"></div></div>';
    });
    if (n === 7) {
      h += '<div class="card tool"><h2>URL and Base64 decoder</h2><div class="row"><input id="enc" placeholder="%27%20OR%201%3D1 or SGVsbG8="><button class="btn" id="encGo">Decode</button></div><div class="out" id="encOut"></div></div>';
    }
    if (n === 6) {
      h += '<div class="card tool"><h2>TLS versions</h2><table><tbody><tr><td>SSL 3.0</td><td class="warn">broken, must not be used</td></tr><tr><td>TLS 1.0 and 1.1</td><td class="warn">deprecated</td></tr><tr><td>TLS 1.2</td><td class="good">acceptable</td></tr><tr><td>TLS 1.3</td><td class="good">current</td></tr></tbody></table><p class="sub">See the <a href="/crypto">Crypto Lab</a> for hashing, AES, RSA and signatures.</p></div>';
    }
    h += '<div class="card tool"><h2>Decode a frame you paste</h2><p class="sub" style="margin:0 0 8px">Paste the hex bytes (or base64) of one Ethernet frame, for example copied from Wireshark.</p><textarea id="pasteHex" placeholder="ff ff ff ff ff ff 52 54 00 ..."></textarea><p><button class="btn" id="pasteGo">Break it apart</button></p></div>';
    return h;
  }

  function wireTools() {
    [].forEach.call(document.querySelectorAll("[data-run]"), function (b) {
      b.onclick = function () {
        var inp = $("tin" + b.dataset.run), out = $("tout" + b.dataset.run);
        api("/api/tools/" + inp.dataset.tool + "?v=" + encodeURIComponent(inp.value)).then(function (d) {
          out.textContent = d.matches ? d.matches.map(function (m) { return m.port + "  " + m.service; }).join("\n") || "No match" : Object.keys(d).map(function (k) { return k + ": " + d[k]; }).join("\n");
        }).catch(function (e) { out.textContent = e.message; });
      };
    });
    if ($("encGo")) $("encGo").onclick = function () {
      var v = $("enc").value, out = [];
      try { out.push("URL decoded: " + decodeURIComponent(v.replace(/\+/g, " "))); } catch (e) { out.push("URL decoded: not valid"); }
      try { out.push("Base64 decoded: " + atob(v)); } catch (e) { out.push("Base64 decoded: not valid"); }
      $("encOut").textContent = out.join("\n");
    };
    if ($("pasteGo")) $("pasteGo").onclick = function () { openRaw($("pasteHex").value, null); };
  }

  var CHIPS = {
    2: ["arp", "eth.src == 52:54:00:aa:00:01", "not arp"],
    3: ["icmp", "ip.src == 192.168.56.66", "ip.ttl < 64", "ip.frag == 1"],
    4: ["tcp.flags == S", "tcp.port == 80", "udp", "len > 100"],
    5: ["tcp.flags == S", "tcp.flags == R", "tcp.flags == FA"],
    6: ["tls.sni contains google", "tls.version == TLS 1.0", "app.cleartext"],
    7: ["http", "dns", "http.request.uri contains passwd", "frame contains \"select\""]
  };

  function initLayerPage() {
    var n = window.LAYER_N, info = LAYER_INFO[n];
    $("lDesc").innerHTML = "<b>Unit of data: " + info[0] + ".</b> " + esc(info[1]);
    var tabs = [["cap", n === 1 ? "Interfaces and bits" : "Captured " + info[0].toLowerCase() + "s"]];
    if (n === 5) tabs.unshift(["sess", "Live sessions"]);
    tabs.push(["tools", "Tools"]);
    var cur = tabs[0][0];
    $("lBody").innerHTML = '<div class="tabsl" id="lTabs">' + tabs.map(function (t) { return '<button data-t="' + t[0] + '">' + t[1] + "</button>"; }).join("") + '</div><div id="lPane"></div>';
    var paused = false, filterText = "", timers = [];

    function kpis() {
      api("/api/overview").then(function (d) {
        S.setStatus(d.status);
        $("lKpis").innerHTML = '<div class="card kpi"><div class="v">' + (n === 1 ? "-" : fmtNum(d.layer_pkts[n] || 0)) + '</div><div class="l">Frames classified at this layer</div></div><div class="card kpi"><div class="v">' + fmtNum(d.layer_alerts[n] || 0) + '</div><div class="l">Alerts on this layer</div></div><div class="card kpi"><div class="v">' + fmtNum(d.total) + '</div><div class="l">Frames captured in total</div></div><div class="card kpi"><div class="v">' + d.pps + '</div><div class="l">Frames per second</div></div>';
      }).catch(function () {});
    }

    function show(t) {
      cur = t; timers.forEach(clearInterval); timers = [];
      [].forEach.call($("lTabs").children, function (b) { b.className = b.dataset.t === t ? "on" : ""; });
      if (t === "tools") { $("lPane").innerHTML = tools(n); wireTools(); return; }
      if (t === "sess") return sessions();
      if (n === 1) return physical();
      captured();
    }

    function captured() {
      (document.getElementById("capHost") || $("lPane")).innerHTML = '<div class="card"><div class="toolbar"><div style="flex:3"><label for="lf">Filter</label><input id="lf" placeholder="ip == 10.0.0.5 and tcp.port == 80" spellcheck="false"></div><div><label for="ls">Show</label><select id="ls"><option value="contains">Every frame that has a layer ' + n + ' part</option><option value="top">Only frames whose top layer is ' + n + '</option></select></div><button class="btn ghost sm" id="lp">Pause</button><a class="btn ghost sm" id="lx" href="#">Export PCAP</a></div><div class="chips" id="lc" style="margin-bottom:10px"></div><div id="lerr"></div><div class="scroll" style="max-height:600px"><table><thead id="lh"></thead><tbody id="lr"></tbody></table></div></div>';
      $("lc").innerHTML = (CHIPS[n] || []).map(function (c) { return '<button class="btn ghost sm" data-f="' + esc(c) + '">' + esc(c) + "</button>"; }).join("");
      $("lc").onclick = function (e) { var b = e.target.closest("button"); if (b) { $("lf").value = b.dataset.f; filterText = b.dataset.f; load(); } };
      $("lf").oninput = debounce(function () { filterText = $("lf").value; load(); }, 400);
      $("ls").onchange = load;
      $("lp").onclick = function () { paused = !paused; this.textContent = paused ? "Resume" : "Pause"; };
      $("lx").onclick = function () { this.href = "/api/pcap?layer=" + n + "&filter=" + encodeURIComponent($("lf").value); };
      $("lr").onclick = function (e) { var tr = e.target.closest("tr[data-id]"); if (tr) openFrame(tr.dataset.id); };
      load();
      timers.push(setInterval(function () { if (!paused) load(); }, 1800));
    }

    function load() {
      api("/api/layer/" + n + "/frames?scope=" + $("ls").value + "&filter=" + encodeURIComponent(filterText)).then(function (d) {
        $("lerr").innerHTML = "";
        $("lh").innerHTML = "<tr>" + d.columns.map(function (c) { return "<th>" + esc(c.t) + "</th>"; }).join("") + "</tr>";
        $("lr").innerHTML = d.rows.map(function (r) {
          return '<tr class="clk" data-id="' + r.id + '">' + d.columns.map(function (c) {
            var v = r[c.k]; if (c.k === "time") v = fmtTime(v);
            return '<td class="' + (c.k === "info" ? "mono" : "mono") + (r.sim && c.k === "info" ? " tag-sim" : "") + '">' + esc(v) + "</td>";
          }).join("") + "</tr>";
        }).join("") || '<tr><td colspan="' + d.columns.length + '" class="sub">No frames match yet.</td></tr>';
      }).catch(function (e) { $("lerr").innerHTML = '<div class="banner err">' + esc(e.message) + "</div>"; });
    }

    function sessions() {
      $("lPane").innerHTML = '<div id="sessTop"></div><div id="capHost"></div>';
      $("sessTop").innerHTML = '<div class="card" style="margin-bottom:14px"><h2>TCP sessions</h2><div class="scroll" style="max-height:340px"><table><thead><tr><th>Client</th><th>Server</th><th>State</th><th>Packets</th><th>Bytes</th><th>Age</th></tr></thead><tbody id="sr"></tbody></table></div></div><h2 style="margin:0 0 8px">Session control frames (SYN, FIN, RST)</h2>';
      function go() {
        api("/api/sessions").then(function (d) {
          $("sr").innerHTML = d.sessions.map(function (s) {
            return '<tr class="clk" data-id="' + s.id + '"><td class="mono">' + esc(s.a + ":" + s.ap) + '</td><td class="mono">' + esc(s.b + ":" + s.bp) + '</td><td><span class="badge b-' + (s.state === "ESTABLISHED" ? "Low" : s.state === "RESET" ? "High" : "Medium") + '">' + esc(s.state || "-") + "</span></td><td>" + s.packets + "</td><td>" + fmtBytes(s.bytes) + "</td><td>" + fmtDur(s.last - s.start) + "</td></tr>";
          }).join("") || '<tr><td colspan="6" class="sub">No TCP sessions yet.</td></tr>';
        }).catch(function () {});
      }
      $("sr").onclick = function (e) { var tr = e.target.closest("tr[data-id]"); if (tr) location.href = "/flows#" + tr.dataset.id; };
      go(); timers.push(setInterval(go, 2000));
      captured();
    }

    function physical() {
      $("lPane").innerHTML = '<div class="card" style="margin-bottom:14px"><h2>Network adapters</h2><div class="scroll" style="max-height:320px"><table><thead><tr><th>Interface</th><th>State</th><th>Address</th><th>Speed</th><th>Receive</th><th>Send</th><th>Errors</th><th>Drops</th></tr></thead><tbody id="ifr"></tbody></table></div></div><div class="card"><h2>A frame as the physical layer sees it</h2><div class="row"><div><label for="bsel">Pick a recent frame</label><select id="bsel"></select></div></div><div id="bits" class="bits" style="margin-top:12px"></div></div>';
      function go() {
        api("/api/layers").then(function (d) {
          $("ifr").innerHTML = d.interfaces.map(function (i) {
            return "<tr><td>" + esc(i.name) + '</td><td><span class="st ' + (i.up ? "on" : "off") + '"><i></i>' + (i.up ? "up" : "down") + '</span></td><td class="mono">' + esc(i.ip || "-") + "</td><td>" + (i.speed ? i.speed + " Mbps" : "-") + '</td><td class="mono">' + fmtBytes(i.rx_bps) + '/s</td><td class="mono">' + fmtBytes(i.tx_bps) + "/s</td><td>" + i.errors + "</td><td>" + i.drops + "</td></tr>";
          }).join("");
        }).catch(function () {});
      }
      go(); timers.push(setInterval(go, 2000));
      api("/api/layer/2/frames").then(function (d) {
        $("bsel").innerHTML = d.rows.slice(0, 30).map(function (r) { return '<option value="' + r.id + '">' + fmtTime(r.ts) + " | " + esc(r.info || r.smac).slice(0, 60) + "</option>"; }).join("");
        $("bsel").onchange = showBits; showBits();
      });
      function showBits() {
        if (!$("bsel").value) return;
        api("/api/frame/" + $("bsel").value).then(function (res) {
          var bytes = res.hex.substr(0, 48).match(/../g) || [];
          var bits = bytes.map(function (b) { return ("00000000" + parseInt(b, 16).toString(2)).slice(-8); });
          $("bits").innerHTML = '<div class="pre">Preamble and start delimiter (added and removed by the network card, never captured):<br>10101010 10101010 10101010 10101010 10101010 10101010 10101010 10101011</div><br>First ' + bytes.length + " bytes of this frame as bits:<br>" + bits.join(" ") + '<br><span class="pre">(' + bytes.join(" ") + ") Total frame: " + res.length + " bytes = " + res.length * 8 + " bits on the wire, plus 4 bytes of frame check sequence added by the card.</span>";
        });
      }
    }

    $("lTabs").onclick = function (e) { var b = e.target.closest("button"); if (b) show(b.dataset.t); };
    kpis(); setInterval(kpis, 2500);
    show(cur);
  }

  function initPackets() {
    var paused = false, q = "";
    var chips = ["ip == 192.168.56.10 and tcp.port == 80", "tcp.flags == S", "dns or http", "len > 200", "not arp", "frame contains \"select\""];
    $("pChips").innerHTML = chips.map(function (c) { return '<button class="btn ghost sm" data-f="' + esc(c) + '">' + esc(c) + "</button>"; }).join("");
    $("pChips").onclick = function (e) { var b = e.target.closest("button"); if (b) { $("pQ").value = b.dataset.f; q = b.dataset.f; refresh(); } };
    function refresh() {
      if (paused) return;
      api("/api/packets?layer=" + encodeURIComponent($("pLayer").value) + "&q=" + encodeURIComponent(q)).then(function (d) {
        $("pErr").innerHTML = "";
        $("pktRows").innerHTML = d.packets.map(function (p) {
          return '<tr class="clk" data-id="' + p.id + '"><td class="mono">' + fmtTime(p.ts) + "</td><td>" + lay(p.layer) + '</td><td class="mono">' + esc(p.src) + '</td><td class="mono">' + esc(p.dst) + "</td><td>" + esc(p.proto) + '</td><td class="mono">' + p.length + '</td><td class="mono' + (p.sim ? " tag-sim" : "") + '">' + esc(p.info) + "</td></tr>";
        }).join("") || '<tr><td colspan="7" class="sub">No packets match.</td></tr>';
      }).catch(function (e) { $("pErr").innerHTML = '<div class="banner err">' + esc(e.message) + "</div>"; });
    }
    $("pktRows").onclick = function (e) { var tr = e.target.closest("tr[data-id]"); if (tr) openFrame(tr.dataset.id); };
    $("pPause").onclick = function () { paused = !paused; this.textContent = paused ? "Resume" : "Pause"; };
    $("pLayer").onchange = refresh;
    $("pQ").oninput = debounce(function () { q = $("pQ").value; refresh(); }, 400);
    $("pPcap").onclick = function () { this.href = "/api/pcap?layer=" + encodeURIComponent($("pLayer").value) + "&filter=" + encodeURIComponent($("pQ").value); };
    refresh(); setInterval(refresh, 1500);
  }

  function initAlerts() {
    var rows = {};
    function row(a) {
      return '<tr class="clk" data-id="' + a.id + '"><td class="mono">' + fmtTime(a.ts) + "</td><td>" + lay(a.layer) + "</td><td>" + esc(a.threat) + (a.has_ev ? ' <span class="pbadge">evidence</span>' : "") + "</td><td>" + badge(a.severity) + '</td><td class="mono">' + esc(a.src) + '</td><td class="mono">' + esc(a.dst) + "</td></tr>";
    }
    function refresh() {
      var qs = "layer=" + encodeURIComponent($("fLayer").value) + "&severity=" + encodeURIComponent($("fSev").value) + "&q=" + encodeURIComponent($("fQ").value);
      api("/api/alerts?" + qs).then(function (d) {
        rows = {}; d.alerts.forEach(function (a) { rows[a.id] = a; });
        $("alertRows").innerHTML = d.alerts.map(row).join("") || '<tr><td colspan="6" class="sub">No alerts match these filters.</td></tr>';
      }).catch(function () {});
    }
    function evidence(id) {
      api("/api/alerts/" + id + "/evidence").then(function (d) {
        var m = document.createElement("div"); m.className = "modal";
        m.innerHTML = '<div class="box"><div class="row" style="justify-content:space-between;align-items:center;margin-bottom:10px"><h2 style="margin:0">Evidence: ' + esc(rows[id] ? rows[id].threat : "") + '</h2><span style="flex:0 0 auto"><a class="btn ghost sm" href="/api/alerts/' + id + '/pcap">Export PCAP</a> <button class="btn sm" id="mx">Close</button></span></div><p class="sub">The frames that triggered this alert (up to 12). Click one to break it apart.</p><table><thead><tr><th>Time</th><th>Layer</th><th>Protocol</th><th>Source</th><th>Destination</th><th>Info</th></tr></thead><tbody>' +
          d.items.map(function (it, i) { return '<tr class="clk" data-i="' + i + '"><td class="mono">' + fmtTime(it.ts) + "</td><td>" + lay(it.layer) + "</td><td>" + esc(it.proto) + '</td><td class="mono">' + esc(it.src) + '</td><td class="mono">' + esc(it.dst) + '</td><td class="mono">' + esc(it.info) + "</td></tr>"; }).join("") + "</tbody></table></div>";
        document.body.appendChild(m);
        m.onclick = function (e) {
          if (e.target === m || e.target.id === "mx") { m.remove(); return; }
          var tr = e.target.closest("tr[data-i]"); if (tr) openRaw(d.items[tr.dataset.i].raw, d.items[tr.dataset.i].link);
        };
      });
    }
    ["fLayer", "fSev"].forEach(function (id) { $(id).onchange = refresh; });
    $("fQ").oninput = refresh;
    $("clearAlerts").onclick = function () { if (confirm("Delete all alerts?")) api("/api/alerts/clear", {}).then(refresh); };
    $("alertRows").addEventListener("click", function (e) {
      var btn = e.target.closest("[data-ev]"); if (btn) { evidence(btn.dataset.ev); return; }
      var tr = e.target.closest("tr[data-id]"); if (!tr) return;
      var nxt = tr.nextElementSibling;
      if (nxt && nxt.classList.contains("detail")) { nxt.remove(); return; }
      var a = rows[tr.dataset.id]; if (!a) return;
      var d = document.createElement("tr"); d.className = "detail";
      d.innerHTML = '<td colspan="6">' + esc(S.fmtDate(a.ts)) + " | Layer " + a.layer + " " + S.LAYERS[a.layer] + " | " + esc(a.detail) + (a.has_ev ? ' <button class="btn sm" data-ev="' + a.id + '" style="margin-left:10px">View evidence packets</button>' : "") + "</td>";
      tr.parentNode.insertBefore(d, tr.nextSibling);
    });
    refresh();
    setInterval(function () { if (!document.querySelector(".detail") && !document.querySelector(".modal")) refresh(); }, 2500);
  }

  function spark(h) {
    if (!h || h.length < 2) return "";
    var mx = Math.max.apply(null, h.concat([1])), pts = h.map(function (v, i) { return Math.round(i * 90 / (h.length - 1)) + "," + Math.round(22 - v / mx * 20); }).join(" ");
    return '<svg class="spark" viewBox="0 0 90 22"><polyline fill="none" stroke="#46c2cb" stroke-width="1.5" points="' + pts + '"/></svg>';
  }

  function deviceModal(d, reload) {
    var m = document.createElement("div"); m.className = "modal";
    function body() {
      return '<div class="box"><div class="row" style="justify-content:space-between;align-items:center"><h2 style="margin:0">' + esc(d.name || d.mac) + '</h2><button class="btn sm" id="mx" style="flex:0 0 auto">Close</button></div><table style="margin-top:10px"><tbody>' +
        [["IP address", d.ip], ["MAC address", d.mac + (d.random_mac ? "  (private or random MAC)" : "")], ["Vendor", d.vendor || "unknown"], ["Device type (guess)", d.type], ["Operating system (guess)", d.os || "unknown"], ["Hostnames seen", (d.names || []).join(", ") || "none"],
          ["Learned from", (d.sources || []).join(", ")], ["Reply time", d.latency != null ? d.latency + " ms" : "-"], ["First seen", S.fmtDate(d.first_seen)], ["Last seen", S.fmtDate(d.last_seen)], ["Trusted", d.known ? "yes" : "no (new device)"], ["DHCP vendor class", d.dhcp_vendor || "-"], ["UPnP/SSDP server", d.ssdp || "-"],
          ["Traffic seen by this computer", "sent " + fmtBytes(d.bw.tx) + ", received " + fmtBytes(d.bw.rx)]].map(function (r) { return "<tr><td>" + r[0] + '</td><td class="mono">' + esc(r[1]) + "</td></tr>"; }).join("") +
        '</tbody></table><h2 style="margin:16px 0 8px">Open ports</h2><div id="pl">' + ((d.ports || []).map(function (p) { return '<span class="pbadge">' + p.port + " " + esc(p.service) + "</span>"; }).join("") || '<span class="sub">Not scanned yet.</span>') + '</div><p><button class="btn" id="ps">Scan common ports</button> <span class="sub">Only devices inside your own network are scanned (34 common ports).</span></p></div>';
    }
    m.innerHTML = body(); document.body.appendChild(m);
    m.onclick = function (e) {
      if (e.target === m || e.target.id === "mx") { m.remove(); return; }
      if (e.target.id === "ps") {
        e.target.disabled = true; e.target.textContent = "Scanning...";
        api("/api/devices/" + d.mac + "/ports", {}).then(function (r) { d.ports = r.ports; m.innerHTML = body(); }).catch(function (er) { alert(er.message); e.target.disabled = false; e.target.textContent = "Scan common ports"; });
      }
    };
  }

  function initDevices() {
    var devs = [], view = [];
    $("dvOnline").checked = localStorage.getItem("dvOnline") !== "0";
    $("dvOnline").onchange = function () { localStorage.setItem("dvOnline", this.checked ? "1" : "0"); refresh(); };
    $("dvReset").onclick = function () { if (confirm("Forget all stored devices and scan the network again?")) api("/api/devices/reset", {}).then(function () { setTimeout(refresh, 900); }); };
    api("/api/devices/networks").then(function (d) {
      $("dvNet").innerHTML = d.networks.map(function (n) { return '<option value="' + n.cidr + '"' + (n.cidr === d.current ? " selected" : "") + ">" + esc(n.iface) + " | " + n.cidr + (n.gateway ? " | gateway " + n.gateway : "") + "</option>"; }).join("") || "<option>No private network found</option>";
    });
    $("dvScan").onclick = function () { api("/api/devices/scan", {cidr: $("dvNet").value}).then(refresh); };
    $("dvAuto").onchange = function () { api("/api/devices/auto", {enabled: this.checked}); };
    function refresh() {
      api("/api/devices").then(function (d) {
        devs = d.devices;
        view = devs.filter(function (x) { return !$("dvOnline").checked || x.online; });
        $("dvNote").innerHTML = '<div class="banner">' + esc(d.note) + "</div>";
        $("dvAuto").checked = d.auto;
        var online = devs.filter(function (x) { return x.online; }).length, fresh = devs.filter(function (x) { return !x.known; }).length;
        $("dvKpis").innerHTML = [["Devices found", devs.length], ["Online now", online], ["New or untrusted", fresh], ["With traffic seen here", d.traffic_seen]].map(function (k) { return '<div class="card kpi"><div class="v">' + k[1] + '</div><div class="l">' + k[0] + "</div></div>"; }).join("");
        var s = d.scan;
        $("dvState").textContent = s.running ? "Scanning... " + (s.mode || "") : s.message ? s.message : s.finished ? "Last scan: " + devs.length + " devices, " + S.fmtDate(s.finished) + " (" + s.mode + ")" : "No scan yet.";
        $("dvScan").disabled = s.running;
        $("dvRows").innerHTML = view.map(function (x, i) {
          var tags = (x.is_self ? '<span class="pbadge">this computer</span>' : "") + (x.is_gateway ? '<span class="pbadge">gateway</span>' : "") + (!x.known ? '<span class="pbadge warn">new</span>' : "") + (x.ip_conflict ? '<span class="pbadge warn">IP conflict</span>' : "") + (x.random_mac ? '<span class="pbadge">private MAC</span>' : "");
          return "<tr><td><span class=\"st " + (x.online ? "on" : "off") + '"><i></i>' + (x.online ? "online" : "offline") + "</span></td><td><b>" + esc(x.name || "-") + "</b> " + tags + '</td><td class="mono">' + esc(x.ip) + '</td><td class="mono">' + esc(x.mac) + "</td><td>" + esc(x.vendor || "unknown") + "</td><td>" + esc(x.type) + '</td><td class="mono">&darr;' + fmtBytes(x.bw.rx_rate) + "/s &uarr;" + fmtBytes(x.bw.tx_rate) + "/s " + spark(x.bw.hist) + '</td><td class="mono">' + fmtBytes(x.bw.tx + x.bw.rx) + '</td><td style="white-space:nowrap"><button class="btn ghost sm" data-d="' + i + '">Details</button> <button class="btn ghost sm" data-r="' + i + '">Rename</button>' + (!x.known ? ' <button class="btn sm" data-t="' + i + '">Trust</button>' : "") + "</td></tr>";
        }).join("") || '<tr><td colspan="9" class="sub">No devices yet. Press "Scan now".</td></tr>';
      }).catch(function () {});
    }
    $("dvRows").onclick = function (e) {
      var b = e.target.closest("button"); if (!b) return;
      if (b.dataset.d !== undefined) deviceModal(view[b.dataset.d]);
      if (b.dataset.r !== undefined) { var x = view[b.dataset.r], n = prompt("Name for " + x.mac, x.name || ""); if (n !== null) api("/api/devices/" + x.mac + "/rename", {name: n}).then(refresh); }
      if (b.dataset.t !== undefined) api("/api/devices/" + view[b.dataset.t].mac + "/trust", {known: true}).then(refresh);
    };
    refresh(); setInterval(refresh, 2500);
  }

  function initTopology() {
    var devs = [];
    function color(d) { return d.ip_conflict ? "#e5484d" : !d.known ? "#ef8a3c" : d.online ? "#3fb68b" : "#5b6a7d"; }
    function draw(d, flows) {
      var svg = $("topo"), W = 760, H = 560, cx = W / 2, cy = H / 2 + 10, gw = d.devices.filter(function (x) { return x.is_gateway; })[0] || null;
      var others = d.devices.filter(function (x) { return x !== gw; }), pos = {}, out = "";
      out += '<circle cx="' + cx + '" cy="42" r="26" fill="#152130" stroke="#46c2cb" stroke-width="2"/><text x="' + cx + '" y="47" text-anchor="middle" fill="#dde6f0" font-size="12">Internet</text>';
      out += '<line x1="' + cx + '" y1="68" x2="' + cx + '" y2="' + (cy - 34) + '" stroke="#46c2cb" stroke-width="2"/>';
      others.forEach(function (x, i) {
        var a = ((i + 0.5) / Math.max(others.length, 1)) * 2 * Math.PI - Math.PI / 2;
        pos[x.mac] = [cx + Math.cos(a) * 270, cy + Math.sin(a) * 175];
      });
      var maxB = Math.max.apply(null, [1].concat(d.devices.map(function (x) { return x.bw.tx + x.bw.rx; })));
      var byIp = {}; d.devices.forEach(function (x) { byIp[x.ip] = x; });
      flows.slice(0, 40).forEach(function (f) {
        var a = byIp[f.a], b = byIp[f.b];
        if (a && b && a !== gw && b !== gw && pos[a.mac] && pos[b.mac]) out += '<line x1="' + pos[a.mac][0] + '" y1="' + pos[a.mac][1] + '" x2="' + pos[b.mac][0] + '" y2="' + pos[b.mac][1] + '" stroke="#46c2cb" stroke-opacity=".35" stroke-dasharray="4 4"/>';
      });
      others.forEach(function (x) {
        var w = 1 + Math.round(7 * Math.log(1 + x.bw.tx + x.bw.rx) / Math.log(1 + maxB));
        out += '<line x1="' + cx + '" y1="' + cy + '" x2="' + pos[x.mac][0] + '" y2="' + pos[x.mac][1] + '" stroke="' + (x.online ? "#46c2cb" : "#3a4a5c") + '" stroke-width="' + w + '" stroke-opacity=".6"/>';
      });
      out += '<circle cx="' + cx + '" cy="' + cy + '" r="34" fill="#152130" stroke="' + (gw ? color(gw) : "#5b6a7d") + '" stroke-width="3" data-m="' + (gw ? gw.mac : "") + '" style="cursor:pointer"/><text x="' + cx + '" y="' + (cy + 4) + '" text-anchor="middle" fill="#dde6f0" font-size="12">Router</text>';
      if (gw) out += '<text x="' + cx + '" y="' + (cy + 52) + '" text-anchor="middle" fill="#8397ad" font-size="11">' + esc(gw.ip) + "</text>";
      others.forEach(function (x) {
        var p = pos[x.mac], label = x.name || x.vendor || x.mac.slice(-8);
        out += '<circle cx="' + p[0] + '" cy="' + p[1] + '" r="26" fill="#152130" stroke="' + color(x) + '" stroke-width="3" data-m="' + x.mac + '" style="cursor:pointer"/><text x="' + p[0] + '" y="' + (p[1] + 4) + '" text-anchor="middle" fill="#dde6f0" font-size="11" pointer-events="none">' + esc(x.ip.split(".").slice(-1)[0] ? "." + x.ip.split(".").slice(-1)[0] : "?") + '</text><text x="' + p[0] + '" y="' + (p[1] + 42) + '" text-anchor="middle" fill="#8397ad" font-size="11" pointer-events="none">' + esc(String(label).slice(0, 18)) + "</text>";
      });
      svg.innerHTML = out + '<g font-size="11" fill="#8397ad"><circle cx="20" cy="20" r="5" fill="#3fb68b"/><text x="30" y="24">online</text><circle cx="20" cy="40" r="5" fill="#ef8a3c"/><text x="30" y="44">new / untrusted</text><circle cx="20" cy="60" r="5" fill="#5b6a7d"/><text x="30" y="64">offline</text><circle cx="20" cy="80" r="5" fill="#e5484d"/><text x="30" y="84">IP conflict</text></g>';
    }
    function info(mac) {
      var x = devs.filter(function (d) { return d.mac === mac; })[0]; if (!x) return;
      $("topoInfo").innerHTML = "<h2>" + esc(x.name || x.mac) + '</h2><table><tbody>' + [["IP", x.ip], ["MAC", x.mac], ["Vendor", x.vendor || "unknown"], ["Type", x.type], ["OS", x.os || "unknown"], ["Status", x.online ? "online" : "offline"], ["Traffic", "&darr;" + fmtBytes(x.bw.rx_rate) + "/s &uarr;" + fmtBytes(x.bw.tx_rate) + "/s"], ["Total", fmtBytes(x.bw.tx + x.bw.rx)]].map(function (r) { return "<tr><td>" + r[0] + '</td><td class="mono">' + (r[0] === "Traffic" ? r[1] : esc(r[1])) + "</td></tr>"; }).join("") + '</tbody></table><p><a class="btn ghost sm" href="/devices">Open Devices page</a></p>';
    }
    $("topo").onclick = function (e) { var c = e.target.closest("[data-m]"); if (c && c.dataset.m) info(c.dataset.m); };
    $("topoOnline").checked = localStorage.getItem("dvOnline") !== "0";
    $("topoOnline").onchange = function () { localStorage.setItem("dvOnline", this.checked ? "1" : "0"); go(); };
    $("topoReset").onclick = function () { if (confirm("Forget all stored devices and scan the network again?")) api("/api/devices/reset", {}).then(function () { setTimeout(go, 1500); }); };
    function go() {
      Promise.all([api("/api/devices"), api("/api/flows")]).then(function (r) {
        var list = r[0].devices.filter(function (x) { return !$("topoOnline").checked || x.online || x.is_gateway; });
        devs = list; draw({devices: list}, r[1].flows);
      }).catch(function () {});
    }
    go(); setInterval(go, 3000);
  }

  function initFlows() {
    var openId = null;
    function list() {
      api("/api/flows?q=" + encodeURIComponent($("fq").value) + "&state=" + encodeURIComponent($("fstate").value)).then(function (d) {
        $("flRows").innerHTML = d.flows.map(function (f) {
          return '<tr class="clk" data-id="' + f.id + '"><td>' + f.proto + '</td><td class="mono">' + esc(f.a + (f.ap ? ":" + f.ap : "")) + '</td><td class="mono">' + esc(f.b + (f.bp ? ":" + f.bp : "")) + "</td><td>" + esc(f.app || f.service || "-") + "</td><td>" + (f.state ? '<span class="badge b-' + (f.state === "ESTABLISHED" ? "Low" : f.state === "RESET" ? "High" : "Medium") + '">' + f.state + "</span>" : "-") + "</td><td>" + f.packets + "</td><td>" + fmtBytes(f.bytes) + "</td><td>" + fmtBytes(f.a2b) + "</td><td>" + fmtBytes(f.b2a) + "</td><td>" + fmtDur(f.last - f.start) + "</td></tr>";
        }).join("") || '<tr><td colspan="10" class="sub">No conversations yet.</td></tr>';
      }).catch(function () {});
    }
    function detail(id) {
      openId = id;
      api("/api/flows/" + id).then(function (d) {
        var f = d.flow, box = $("flDetail"); box.hidden = false;
        box.innerHTML = '<div class="row" style="justify-content:space-between;align-items:center"><h2 style="margin:0">' + f.proto + " " + esc(f.a + ":" + f.ap) + " &harr; " + esc(f.b + ":" + f.bp) + '</h2><span style="flex:0 0 auto"><a class="btn ghost sm" href="/api/flows/' + id + '/pcap">Export PCAP</a> <button class="btn sm" id="flClose">Close</button></span></div><p class="sub">' + f.packets + " packets, " + fmtBytes(f.bytes) + ", state " + (f.state || "-") + '. <span style="color:#8fd3ff">Blue</span> = data sent by ' + esc(f.a) + ', <span style="color:#ff9d8a">red</span> = data sent by ' + esc(f.b) + '.</p><h2 style="margin:12px 0 6px">Followed stream</h2><div style="max-height:320px;overflow:auto">' +
          (d.chunks.map(function (c) { return '<div class="chunk d' + c.dir + '">' + esc(c.text) + "</div>"; }).join("") || '<p class="sub">No payload bytes captured in this conversation (handshake only, encrypted data would appear as dots).</p>') + '</div><h2 style="margin:12px 0 6px">Frames</h2><div class="scroll" style="max-height:260px"><table><thead><tr><th>Time</th><th>From</th><th>To</th><th>Length</th><th>Info</th></tr></thead><tbody>' +
          d.frames.map(function (r) { return '<tr class="clk" data-f="' + r.id + '"><td class="mono">' + fmtTime(r.ts) + '</td><td class="mono">' + esc(r.src) + '</td><td class="mono">' + esc(r.dst) + '</td><td>' + r.length + '</td><td class="mono">' + esc(r.info) + "</td></tr>"; }).join("") + "</tbody></table></div>";
        box.scrollIntoView({behavior: "smooth"});
      }).catch(function (e) { alert(e.message); });
    }
    $("flRows").onclick = function (e) { var tr = e.target.closest("tr[data-id]"); if (tr) detail(+tr.dataset.id); };
    $("flDetail").onclick = function (e) {
      if (e.target.id === "flClose") { $("flDetail").hidden = true; return; }
      var tr = e.target.closest("tr[data-f]"); if (tr) openFrame(tr.dataset.f);
    };
    $("fq").oninput = debounce(list, 300); $("fstate").onchange = list;
    list(); setInterval(list, 2500);
    if (location.hash.length > 1) detail(+location.hash.slice(1));
  }

  function initRules() {
    function load() {
      api("/api/rules").then(function (d) {
        $("ruRows").innerHTML = d.rules.map(function (r) {
          return '<tr><td><input type="checkbox" style="width:auto" data-rule="' + esc(r.id) + '"' + (r.enabled ? " checked" : "") + "></td><td>" + lay(r.layer) + "</td><td><b>" + esc(r.id) + '</b><div class="sub" style="margin:0">' + esc(r.desc) + "</div></td><td>" + badge(r.severity) + "</td></tr>";
        }).join("");
        $("ruLimits").innerHTML = Object.keys(d.limits).map(function (k) {
          var l = d.limits[k];
          return '<label for="th_' + k + '">' + esc(l.label) + ' <span class="sub">(default ' + l.default + ", allowed " + l.min + " to " + l.max + ')</span></label><input type="number" id="th_' + k + '" data-k="' + k + '" value="' + l.value + '" min="' + l.min + '" max="' + l.max + '">';
        }).join("");
      });
    }
    $("ruSave").onclick = function () {
      var th = {}, dis = [];
      [].forEach.call(document.querySelectorAll("[data-k]"), function (i) { th[i.dataset.k] = i.value; });
      [].forEach.call(document.querySelectorAll("[data-rule]"), function (i) { if (!i.checked) dis.push(i.dataset.rule); });
      api("/api/rules", {thresholds: th, disabled: dis}).then(function () { $("ruMsg").innerHTML = '<div class="result ok">Saved. The new values are active now.</div>'; }).catch(function (e) { $("ruMsg").innerHTML = '<div class="result bad">' + esc(e.message) + "</div>"; });
    };
    $("ruReset").onclick = function () { if (confirm("Restore all default thresholds and enable every rule?")) api("/api/rules/reset", {}).then(function () { load(); $("ruMsg").innerHTML = '<div class="result ok">Defaults restored.</div>'; }); };
    load();
  }

  S.pages.packets = initPackets;
  S.pages.alerts = initAlerts;
  S.pages.devices = initDevices;
  S.pages.topology = initTopology;
  S.pages.flows = initFlows;
  S.pages.rules = initRules;
  if (window.LAYER_N) {
    S.pages.layers = function () {};
    document.addEventListener("DOMContentLoaded", initLayerPage);
  }
})();
