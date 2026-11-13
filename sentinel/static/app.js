"use strict";
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SVGNS = "http://www.w3.org/2000/svg";

const S = {
  machines: {}, order: [], events: [], alerts: [], byKind: {}, byIp: {}, total: 0, attacks: 0, latSum: 0, latN: 0,
  selected: null, trace: null, mid: "sqli_tautology", step: 0, timer: null, protected: false, paused: false,
  filter: "all", text: "", lastIp: null, lastIpState: null, banSeconds: 20, demo: false,
};
let graphView = null, uid = 0;

/* ------------------------------------------------------------------ graph drawing */
function makeGraph(el, g, patterns, opts = {}) {
  const id = "g" + (++uid), R = 15;
  const pat = patterns && patterns.length ? patterns : null;
  const GX = opts.gx || (pat ? 54 : 84), GY = 56;
  const adj = {};
  g.edges.forEach(e => (adj[e.from] = adj[e.from] || []).push(e.to));
  const depth = {};
  if (pat) {
    g.nodes.forEach(n => (depth[n.id] = n.label.length));
  } else {
    depth[g.start] = 0;
    const q = [g.start];
    while (q.length) { const a = q.shift(); (adj[a] || []).forEach(b => { if (!(b in depth)) { depth[b] = depth[a] + 1; q.push(b); } }); }
    const md = Math.max(0, ...Object.values(depth));
    g.nodes.forEach(n => { if (!(n.id in depth)) depth[n.id] = md + 1; });
  }
  const rowOf = {}, counts = {};
  g.nodes.forEach(n => {
    if (pat) rowOf[n.id] = n.label === "" ? (pat.length - 1) / 2 : Math.max(0, pat.findIndex(p => p.startsWith(n.label)));
    else { counts[depth[n.id]] = (counts[depth[n.id]] || 0); rowOf[n.id] = counts[depth[n.id]]++; }
  });
  const pos = {};
  let maxX = 0, maxY = 0;
  g.nodes.forEach(n => {
    const x = 48 + depth[n.id] * GX, y = 56 + rowOf[n.id] * GY;
    pos[n.id] = { x, y, d: depth[n.id] };
    maxX = Math.max(maxX, x); maxY = Math.max(maxY, y);
  });
  const W = maxX + 60, H = maxY + 90;
  let defs = `<defs><marker id="${id}a" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="#94a3b8"/></marker>
    <marker id="${id}h" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="#2563eb"/></marker></defs>`;
  let body = "";
  const st = pos[g.start];
  if (st) body += `<path d="M${st.x - R - 22} ${st.y}L${st.x - R - 2} ${st.y}" stroke="#64748b" stroke-width="1.5" marker-end="url(#${id}a)"/>`;
  let k = 0;
  g.edges.forEach(e => {
    const a = pos[e.from], b = pos[e.to];
    if (!a || !b) return;
    let d, lx, ly;
    if (e.from === e.to) {
      d = `M${a.x - 9} ${a.y - R + 2}C${a.x - 26} ${a.y - R - 30} ${a.x + 26} ${a.y - R - 30} ${a.x + 9} ${a.y - R + 2}`;
      lx = a.x; ly = a.y - R - 22;
    } else if (b.d === a.d + 1 && Math.abs(b.y - a.y) < GY * 3) {
      const dx = b.x - a.x, dy = b.y - a.y, L = Math.hypot(dx, dy), ux = dx / L, uy = dy / L;
      d = `M${a.x + ux * R} ${a.y + uy * R}L${b.x - ux * (R + 2)} ${b.y - uy * (R + 2)}`;
      lx = (a.x + b.x) / 2; ly = (a.y + b.y) / 2 - 7;
    } else {
      const dx = b.x - a.x, dy = b.y - a.y, back = dx <= 0;
      const off = (back ? 1 : -1) * (30 + Math.min(Math.abs(dx), 280) * 0.2 + (k++ % 3) * 11);
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      const c = Math.abs(dx) >= Math.abs(dy) ? { x: mx, y: my + off * 1.6 } : { x: mx + off * 1.6, y: my };
      const sh = (p, q, r) => { const L = Math.hypot(q.x - p.x, q.y - p.y) || 1; return { x: p.x + (q.x - p.x) / L * r, y: p.y + (q.y - p.y) / L * r }; };
      const p0 = sh(a, c, R), p1 = sh(b, c, R + 2);
      d = `M${p0.x} ${p0.y}Q${c.x} ${c.y} ${p1.x} ${p1.y}`;
      lx = 0.25 * a.x + 0.5 * c.x + 0.25 * b.x; ly = 0.25 * a.y + 0.5 * c.y + 0.25 * b.y + 3;
    }
    body += `<g class="edge" data-f="${e.from}" data-t="${e.to}"><path d="${d}" marker-end="url(#${id}a)"/><text x="${lx}" y="${ly}">${esc(e.label)}</text></g>`;
  });
  g.nodes.forEach(n => {
    const p = pos[n.id];
    body += `<g class="node" data-id="${n.id}" transform="translate(${p.x},${p.y})"><circle r="${R}"/>${n.accepting ? `<circle class="acc" r="${R - 4}"/>` : ""}
      <text>${esc(pat ? n.id : (n.label.length > 6 ? n.id : n.label))}</text><title>${esc(n.label)}</title></g>`;
  });
  el.innerHTML = `<svg width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">${defs}${body}</svg>`;
  const nodes = {}, edges = [];
  $$(".node", el).forEach(n => (nodes[n.dataset.id] = n));
  $$(".edge", el).forEach(e => edges.push(e));
  const markers = { a: id + "a", h: id + "h" };
  return {
    pos,
    paint(cur, visited, fired, prev) {
      Object.entries(nodes).forEach(([nid, n]) => {
        n.classList.toggle("active", String(nid) === String(cur));
        n.classList.toggle("visited", visited ? visited.has(Number(nid)) : false);
        n.classList.toggle("fired", !!fired && String(nid) === String(cur));
      });
      edges.forEach(e => {
        const hot = prev !== undefined && prev !== null && String(e.dataset.f) === String(prev) && String(e.dataset.t) === String(cur);
        e.classList.toggle("hot", hot);
        $("path", e).setAttribute("marker-end", `url(#${hot ? markers.h : markers.a})`);
      });
      const p = pos[cur];
      if (p && el.scrollWidth > el.clientWidth) {
        const left = p.x - el.clientWidth / 2;
        el.scrollTo({ left: Math.max(0, left), behavior: "smooth" });
      }
    },
  };
}

function tableHtml(t, cur) {
  if (!t) return "";
  return `<table class="t"><tr><th>state</th>${t.symbols.map(s => `<th>${esc(s)}</th>`).join("")}</tr>` +
    t.rows.map(r => `<tr><th>${r.start ? "→" : ""}${r.accepting ? "*" : ""}${esc(r.label)}</th>${r.cells.map((c, i) => {
      const label = t.rows[c] ? t.rows[c].label : c;
      return `<td class="${r.state === cur ? "cur" : ""}">${esc(label)}</td>`;
    }).join("")}</tr>`).join("") + `</table>`;
}

/* ------------------------------------------------------------------ websocket */
function connect() {
  const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "/ws");
  ws.onopen = () => setConn(true);
  ws.onclose = () => { setConn(false); setTimeout(connect, 1500); };
  ws.onmessage = m => handle(JSON.parse(m.data));
}
function setConn(on) {
  $("#conn").classList.toggle("on", on);
  $("#conn span").textContent = on ? "live" : "reconnecting…";
}
function handle(m) {
  if (m.type === "init") init(m);
  else if (m.type === "event") addEvent(m, true);
  else if (m.type === "mode") setMode(m.protected);
  else if (m.type === "bans") renderBans(m.bans);
}
function init(m) {
  S.machines = {}; S.order = [];
  m.machines.forEach(d => { S.machines[d.id] = d; S.order.push(d.id); });
  S.events = []; S.alerts = []; S.byKind = {}; S.byIp = {}; S.total = S.attacks = S.latSum = S.latN = 0;
  $("#logs").innerHTML = "";
  S.demo = m.demo; S.banSeconds = m.banSeconds;
  $("#src").textContent = m.demo ? "synthetic demo traffic" : "tailing " + m.log.split(/[\\/]/).slice(-2).join("/");
  $("#simnote").textContent = m.demo ? "demo mode: simulator needs the victim shop" : "fires real HTTP requests at the shop";
  $$("#sim button").forEach(b => (b.disabled = m.demo));
  setMode(m.protected);
  m.history.forEach(e => addEvent(e, false));
  renderChips(); renderMachine(); renderStats();
}

/* ------------------------------------------------------------------ events / stats */
function addEvent(ev, live) {
  S.events.push(ev);
  if (S.events.length > 3000) S.events.shift();
  S.total++;
  S.lastIp = ev.ip; S.lastIpState = ev.ip_state;
  if (ev.latency_ms !== null) { S.latSum += ev.latency_ms; S.latN++; }
  const ip = (S.byIp[ev.ip] = S.byIp[ev.ip] || { req: 0, atk: 0 });
  ip.req++;
  if (ev.attack) {
    S.attacks++; ip.atk++;
    const kinds = [...new Set(ev.alerts.map(a => a.kind))];
    kinds.forEach(k => (S.byKind[k] = (S.byKind[k] || 0) + 1));
    ev.alerts.forEach(a => S.alerts.unshift({ ev, a }));
    if (S.alerts.length > 200) S.alerts.length = 200;
  }
  if (!S.paused || !live) appendRow(ev);
  if (live && ev.attack) {
    toast(ev);
    if ($("#follow").checked) select(ev.id, true);
  } else if (live && !S.selected) {
    renderMachine();
  } else if (live && S.lastIp && S.machines[S.mid] && S.machines[S.mid].perIP && !S.trace) renderMachine();
  renderAlerts();
}
function rowVisible(ev) {
  if (S.filter === "atk" && !ev.attack) return false;
  if (S.text && !(ev.raw.toLowerCase().includes(S.text))) return false;
  return true;
}
function appendRow(ev) {
  const box = $("#logs");
  const atBottom = box.scrollTop + box.clientHeight >= box.scrollHeight - 30;
  const r = document.createElement("div");
  r.className = "row" + (ev.attack ? " atk" : "");
  r.dataset.id = ev.id;
  const st = ev.status >= 500 || ev.status === 403 || ev.status === 401 ? "e" : ev.status >= 400 ? "w" : "";
  const med = ev.alerts.length && ev.alerts.every(a => a.severity !== "high");
  const tags = (ev.blocked ? '<span class="tag blk">BLOCKED</span>' : "") +
    [...new Set(ev.alerts.map(a => a.kind))].map(k => `<span class="tag ${med ? "med" : ""}">${esc(k)}</span>`).join("") +
    (ev.banned ? `<span class="tag blk">IP BANNED ${ev.banned}s</span>` : "");
  r.innerHTML = `<span class="t mono">${esc(ev.iso.slice(11, 19))}</span><span class="mono">${esc(ev.ip)}</span><span class="mono">${esc(ev.method)}</span>
    <span class="u mono" title="${esc(ev.raw)}">${esc(decodeSafe(ev.target))}${tags}</span><span class="st mono ${st}">${ev.status}</span>`;
  r.onclick = () => select(ev.id, false);
  r.style.display = rowVisible(ev) ? "" : "none";
  if (ev.id === S.selected) r.classList.add("sel");
  box.appendChild(r);
  while (box.children.length > 400) box.removeChild(box.firstChild);
  if (atBottom) box.scrollTop = box.scrollHeight;
}
function decodeSafe(s) { try { return decodeURIComponent(s.replace(/\+/g, " ")); } catch (e) { return s; } }
function refilter() {
  const byId = new Map(S.events.map(e => [String(e.id), e]));
  $$("#logs .row").forEach(r => { const e = byId.get(r.dataset.id); r.style.display = e && rowVisible(e) ? "" : "none"; });
}
function toast(ev) {
  const a = ev.alerts[0];
  const t = document.createElement("div");
  t.className = "toast";
  t.innerHTML = `<b>ALERT · ${esc(a.kind)}</b><br>${esc(ev.ip)} · ${esc(a.detail)}`;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3800);
}
function renderStats() {
  $("#s-req").textContent = S.total;
  $("#s-atk").textContent = S.attacks;
  $("#s-ips").textContent = Object.keys(S.byIp).length;
  $("#s-lat").textContent = S.latN ? Math.round(S.latSum / S.latN) + " ms" : "–";
  const max = Math.max(1, ...Object.values(S.byKind));
  $("#bytype").innerHTML = Object.entries(S.byKind).sort((a, b) => b[1] - a[1]).map(([k, v]) =>
    `<div class="bar"><span>${esc(k)}</span><div class="b"><div class="f" style="width:${v / max * 100}%"></div></div><b>${v}</b></div>`).join("") || '<span style="color:var(--mute)">no attacks yet</span>';
  $("#topips").innerHTML = Object.entries(S.byIp).filter(([, v]) => v.atk).sort((a, b) => b[1].atk - a[1].atk).slice(0, 5).map(([ip, v]) =>
    `<div class="bar"><span class="mono">${esc(ip)}</span><div class="b"><div class="f" style="width:${v.atk / v.req * 100}%"></div></div><b>${v.atk}</b></div>`).join("") || '<span style="color:var(--mute)">none</span>';
  renderTimeline();
}
function renderTimeline() {
  const svg = $("#timeline"), W = svg.clientWidth || 300, H = 110, N = 24, BIN = 5, now = Date.now() / 1000;
  const tot = new Array(N).fill(0), atk = new Array(N).fill(0);
  S.events.forEach(e => {
    const i = N - 1 - Math.floor((now - e.ts) / BIN);
    if (i >= 0 && i < N) { tot[i]++; if (e.attack) atk[i]++; }
  });
  const max = Math.max(3, ...tot), bw = W / N;
  svg.innerHTML = tot.map((t, i) => {
    const h = t / max * (H - 18), ha = atk[i] / max * (H - 18);
    return `<rect x="${i * bw + 1}" y="${H - 14 - h}" width="${bw - 2}" height="${h}" fill="#bfdbfe" rx="2"/><rect x="${i * bw + 1}" y="${H - 14 - ha}" width="${bw - 2}" height="${ha}" fill="#dc2626" rx="2"/>`;
  }).join("") + `<text x="0" y="${H - 2}" font-size="10" fill="#64748b">−2 min</text><text x="${W}" y="${H - 2}" font-size="10" fill="#64748b" text-anchor="end">now</text>`;
}
function renderAlerts() {
  $("#alert-n").textContent = S.attacks + " flagged";
  $("#alerts").innerHTML = S.alerts.slice(0, 40).map(({ ev, a }) =>
    `<div class="alert ${a.severity === "high" ? "" : "med"}" data-id="${ev.id}"><b>${esc(a.kind)}</b> · ${esc(ev.ip)} · <span class="mono">${esc(a.machine)}</span>
     <small>${esc(ev.iso.slice(11, 19))} · ${esc(a.detail)}</small></div>`).join("") || '<span style="color:var(--mute)">No alerts yet. Browse the shop or press a simulator button.</span>';
  $$("#alerts .alert").forEach(el => (el.onclick = () => select(Number(el.dataset.id), false)));
  renderStats();
}
function renderBans(b) {
  const entries = Object.entries(b);
  $("#bans").innerHTML = entries.length ? entries.map(([ip, s]) => `<div class="ban"><span class="mono">${esc(ip)}</span><span>${s}s left</span></div>`).join("")
    : '<span style="color:var(--mute)">none</span>';
}

/* ------------------------------------------------------------------ machine panel */
async function select(id, play) {
  S.selected = id;
  $$("#logs .row").forEach(r => r.classList.toggle("sel", Number(r.dataset.id) === id));
  const ev = S.events.find(e => e.id === id);
  try {
    const r = await fetch("/api/trace/" + id);
    S.trace = r.ok ? await r.json() : null;
  } catch (e) { S.trace = null; }
  if (ev && S.trace) {
    const firstHit = ev.alerts.map(a => a.machine).find(m => S.trace[m]);
    if (firstHit) S.mid = firstHit;
    else if (!S.trace[S.mid] || !S.machines[S.mid]) S.mid = "sqli_tautology";
  }
  S.step = 0;
  renderChips(); renderMachine();
  if (play) startPlay();
}
function renderChips() {
  $("#chips").innerHTML = S.order.map(id => {
    const d = S.machines[id], hit = S.trace && S.trace[id] && S.trace[id].fired;
    return `<span class="chip ${id === S.mid ? "on" : ""} ${hit ? "hit" : ""}" data-m="${id}">${esc(d.title.replace(/^(DFA|PDA|CFG): /, d.kind.toUpperCase() + " · "))}</span>`;
  }).join("");
  $$("#chips .chip").forEach(c => (c.onclick = () => { stopPlay(); S.mid = c.dataset.m; S.step = 0; renderChips(); renderMachine(); }));
}
function curTrace() { return S.trace && S.trace[S.mid]; }

function renderMachine() {
  const d = S.machines[S.mid];
  if (!d) return;
  const tr = curTrace();
  $("#m-class").textContent = d.cls;
  $("#m-class").className = "badge" + (d.cls === "Context-free" ? " cf" : "");
  $("#m-desc").textContent = d.desc;
  const flag = $("#m-flag"), strip = $("#strip"), body = $("#m-body");
  if (!S.selected) flag.innerHTML = '<div class="flag no">Click a log line, or trigger an attack, to watch this machine process it.</div>';
  else if (tr && tr.fired) flag.innerHTML = `<div class="flag yes">🚩 Flagged: ${esc(tr.detail)}</div>`;
  else flag.innerHTML = `<div class="flag no">✓ This machine did not flag the selected request.</div>`;
  strip.style.display = "none";
  graphView = null;

  if (d.kind === "dfa") {
    body.innerHTML = '<div class="gwrap" id="gw"></div><div id="tbl"></div>';
    graphView = makeGraph($("#gw"), d.graph, d.patterns);
    $("#tbl").innerHTML = "";
    if (d.elided_note !== false && d.graph.elided) $("#tbl").innerHTML = '<div class="readout">Only the matching (forward) edges are drawn. Any other character falls back to a shallower state, usually q0, so no pattern can be missed.</div>';
  } else if (d.kind === "pda") {
    body.innerHTML = `<div class="pdawrap"><div><div style="font-size:12px;color:var(--mute);margin-bottom:4px">stack (top ↑)</div><div class="stack" id="stack"></div></div>
      <div style="flex:1"><div id="pstates"></div><div id="ptoks" style="margin-top:8px"></div></div></div>
      <ul class="rules">${d.rules.map(r => `<li class="mono">${esc(r)}</li>`).join("")}</ul>`;
  } else {
    body.innerHTML = `<div class="mono" style="font-size:12.5px;line-height:1.7">${d.grammar.map(esc).join("<br>")}</div><div id="cfgres" style="margin-top:10px"></div>`;
  }
  setupControls();
  paint();
}

function stepsOf(tr) { return tr ? tr.steps : null; }
function setupControls() {
  const tr = curTrace(), d = S.machines[S.mid];
  const steps = stepsOf(tr);
  let n = steps ? steps.length - 1 : 0;
  if (!tr && d.perIP && S.lastIpState) n = 0;
  $("#scrub").max = n;
  $("#ctl").style.visibility = n > 0 ? "visible" : "hidden";
}
function paint() {
  const d = S.machines[S.mid], tr = curTrace(), steps = stepsOf(tr);
  const idx = steps ? Math.min(S.step, steps.length - 1) : 0;
  $("#scrub").value = idx;
  const readout = $("#readout"), strip = $("#strip");
  if (d.kind === "dfa") {
    let cur = d.graph.start, prev = null, visited = new Set([d.graph.start]), fired = false;
    if (steps) {
      for (let i = 0; i <= idx; i++) visited.add(steps[i].state);
      cur = steps[idx].state; prev = idx > 0 ? steps[idx - 1].state : null;
      fired = !!tr.fired && idx >= tr.fired;
    } else if (d.perIP && S.lastIpState) {
      cur = S.lastIpState[d.id];
      visited = new Set([cur]);
    }
    graphView && graphView.paint(cur, visited, fired, prev);
    const node = d.graph.nodes.find(n => n.id === cur);
    if (d.table && !steps) $("#tbl").innerHTML = tableHtml(d.table, cur);
    else if (d.table) $("#tbl").innerHTML = tableHtml(d.table, cur);
    if (steps && tr.input) {
      strip.style.display = "";
      strip.innerHTML = [...tr.input].map((c, i) => `<span class="${i + 1 === tr.fired && idx >= tr.fired ? "hit" : i + 1 === idx ? "cur" : i < idx ? "done" : ""}">${esc(c === " " ? "␣" : c)}</span>`).join("") || "(empty)";
      const s = steps[idx];
      readout.innerHTML = idx === 0 ? `Start in <b>q${esc(d.graph.start)}</b>. Press play or step through.` :
        `Read <b>'${esc(s.sym)}'</b> → state <b>${esc(node ? (node.label.length <= 6 ? node.label : "q" + node.id) : cur)}</b>${node && node.label.length > 0 && d.patterns.length ? ` · text matched so far: <b>"${esc(node.label)}"</b>` : ""}${s.state === d.graph.start && d.graph.elided && idx > 0 ? " (reset to q0)" : ""}`;
    } else if (d.perIP) {
      readout.innerHTML = S.lastIp ? `Live state for the most recent source <b class="mono">${esc(S.lastIp)}</b>: <b>q${cur}</b>${tr ? " (selected request: no step for this machine)" : ""}` : "Waiting for traffic…";
    } else readout.textContent = "";
  } else if (d.kind === "pda") {
    const stack = $("#stack"), states = $("#pstates"), toks = $("#ptoks");
    if (!steps) { stack.innerHTML = '<div class="z">Z</div>'; states.innerHTML = ""; toks.innerHTML = ""; readout.textContent = ""; return; }
    const s = steps[idx];
    stack.innerHTML = s.stack.map((x, i) => `<div class="${i === 0 ? "z" : ""}">${esc(x)}</div>`).join("");
    states.innerHTML = d.states.map(q => `<span class="tok ${q === s.state ? "cur" : ""}">${esc(q)}</span>`).join("");
    toks.innerHTML = tr.tokens.length ? tr.tokens.map((t, i) => `<span class="tok ${i + 1 === idx ? "cur" : i < idx ? "done" : ""}">${esc(t)}</span>`).join("")
      : '<span style="color:var(--mute)">No brackets or tags in this request: the stack stays [Z] and the PDA never leaves q0.</span>';
    readout.innerHTML = idx === 0 ? "Start: state q0, stack [Z]." : `Token <b>${esc(s.tok)}</b> · ${esc(s.note)} · state <b>${esc(s.state)}</b>`;
  } else {
    const box = $("#cfgres");
    if (!tr) { box.innerHTML = ""; readout.textContent = ""; return; }
    const r = tr.result;
    box.innerHTML = `<div style="margin-bottom:6px">${r.tokens.map(t => `<span class="tok">${esc(t.name)}<small style="color:var(--mute)"> ${esc(t.text)}</small></span>`).join("")}</div>` +
      (r.accepted ? `<div class="tree">${treeHtml(r.tree)}</div>` : `<div class="flag no">Not derivable from Inj: ${esc(r.reason)}</div>`);
    readout.textContent = "";
  }
}
function treeNode(n) {
  if (!n.children.length) return `<li><i>${esc(n.name)}</i> <span class="mono">${esc(n.text)}</span></li>`;
  return `<li><b>${esc(n.name)}</b><ul>${n.children.map(treeNode).join("")}</ul></li>`;
}
function treeHtml(n) { return `<ul>${treeNode(n)}</ul>`; }

/* player */
function maxStep() { const tr = curTrace(); return tr ? tr.steps.length - 1 : 0; }
function goto_(i) { S.step = Math.max(0, Math.min(maxStep(), i)); paint(); }
function stopPlay() { clearInterval(S.timer); S.timer = null; $("#b-play").textContent = "▶ Play"; }
function startPlay() {
  stopPlay();
  const d = S.machines[S.mid], n = maxStep();
  if (n < 1) return;
  if (S.step >= n) S.step = 0;
  const base = d.kind === "pda" || d.perIP ? 520 : n > 80 ? 22 : 70;
  const delay = base / Number($("#speed").value);
  $("#b-play").textContent = "⏸ Pause";
  S.timer = setInterval(() => { if (S.step >= maxStep()) return stopPlay(); goto_(S.step + 1); }, delay);
}
$("#b-play").onclick = () => (S.timer ? stopPlay() : startPlay());
$("#b-first").onclick = () => { stopPlay(); goto_(0); };
$("#b-last").onclick = () => { stopPlay(); goto_(maxStep()); };
$("#b-prev").onclick = () => { stopPlay(); goto_(S.step - 1); };
$("#b-next").onclick = () => { stopPlay(); goto_(S.step + 1); };
$("#scrub").oninput = e => { stopPlay(); goto_(Number(e.target.value)); };
$("#speed").onchange = () => { if (S.timer) startPlay(); };

/* ------------------------------------------------------------------ controls */
function setMode(p) {
  S.protected = p;
  $("#m-vuln").classList.toggle("on", !p); $("#m-prot").classList.toggle("on", p);
}
async function postMode(p) {
  await fetch("/api/mode", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ protected: p }) });
}
$("#m-vuln").onclick = () => postMode(false);
$("#m-prot").onclick = () => postMode(true);
$("#unblock").onclick = () => fetch("/api/unblock", { method: "POST" });
$("#pause").onclick = e => {
  S.paused = !S.paused; e.target.textContent = S.paused ? "Resume" : "Pause";
  if (!S.paused) { $("#logs").innerHTML = ""; S.events.slice(-300).forEach(appendRow); }
};
$$(".filters .chip[data-f]").forEach(c => (c.onclick = () => {
  S.filter = c.dataset.f; $$(".filters .chip[data-f]").forEach(x => x.classList.toggle("on", x === c)); refilter();
}));
$("#q").oninput = e => { S.text = e.target.value.toLowerCase(); refilter(); };

const SIMS = [["normal", "Normal browsing", ""], ["brute", "Brute-force login", "DFA"], ["sqli_login", "SQLi login bypass", "DFA + CFG"],
  ["sqli_union", "SQLi UNION dump", "DFA"], ["xss", "XSS <script>", "DFA"], ["xss_nested", "XSS nested tags", "PDA"],
  ["nested_sql", "Nested sub-query", "PDA + CFG"], ["traversal", "Path traversal", "DFA"], ["scan", "URL scan", "DFA"], ["all", "Run everything", ""]];
$("#sim").innerHTML = SIMS.map(([k, label, m]) => `<button class="btn ${k === "all" ? "primary" : ""}" data-k="${k}" title="${m ? "caught by: " + m : ""}">${esc(label)}${m ? ` <small style="color:var(--mute)">${m}</small>` : ""}</button>`).join("");
$$("#sim button").forEach(b => (b.onclick = () => fetch("/api/simulate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ kind: b.dataset.k }) })));

$$("nav.tabs button").forEach(b => (b.onclick = () => {
  $$("nav.tabs button").forEach(x => x.classList.toggle("on", x === b));
  $$(".tab").forEach(t => t.classList.toggle("on", t.id === "tab-" + b.dataset.tab));
}));

/* ------------------------------------------------------------------ regex lab */
let reViews = {}, reRun = null, reTimer = null;
async function buildRegex() {
  $("#re-err").textContent = "";
  const r = await fetch("/api/regex", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ pattern: $("#re-pat").value, sample: $("#re-sample").value }) });
  const j = await r.json();
  if (!r.ok) { $("#re-err").textContent = "Pattern error: " + j.error; return; }
  reViews.nfa = makeGraph($("#g-nfa"), j.nfa, null, { gx: 70 });
  reViews.dfa = makeGraph($("#g-dfa"), j.dfa, null, { gx: 78 });
  reViews.min = makeGraph($("#g-min"), j.min, null, { gx: 78 });
  $("#c-nfa").textContent = j.counts.nfa + " states"; $("#c-dfa").textContent = j.counts.dfa + " states"; $("#c-min").textContent = j.counts.min + " states";
  $("#re-table").innerHTML = tableHtml(j.table, -1) + (j.min.dead ? '<div class="readout">The dead (trap) state is hidden; missing edges lead to it.</div>' : "");
  Object.values(reViews).forEach(v => v.paint(0, new Set([0]), false, null));
  reRun = j.run; $("#re-ctl").hidden = !reRun; $("#re-result").textContent = "";
}
$("#re-go").onclick = buildRegex;
$("#re-play").onclick = () => {
  if (!reRun) return;
  clearInterval(reTimer);
  let i = 0; const vis = new Set([0]);
  reViews.min.paint(0, vis, false, null);
  $("#re-result").textContent = "";
  reTimer = setInterval(() => {
    i++;
    if (i >= reRun.steps.length) { clearInterval(reTimer); $("#re-result").innerHTML = reRun.accepted ? '<b class="yes">accepted ✓</b>' : '<b style="color:var(--red)">rejected ✗</b>'; return; }
    const s = reRun.steps[i], prev = reRun.steps[i - 1].state; vis.add(s.state);
    reViews.min.paint(s.state, vis, false, prev);
    $("#re-result").textContent = `read '${s.sym}' → q${s.state}`;
  }, 550);
};

/* ------------------------------------------------------------------ compare machines */
const PRESETS = [["Tautology login", "admin' or 1=1 --"], ["UNION dump", "x' union select username,password from users --"],
  ["Nested sub-query", "x' and (select (select 1))=1 and 'a'='a"], ["Nested tags", "<div><b>hi</b></div>"], ["Script tag", "<script>alert(1)</script>"],
  ["Quote + comment", "admin'--"], ["Unclosed bracket", "x' and (select (1=1 --"], ["Benign", "blue running shoes (size 10)"]];
$("#presets").innerHTML = PRESETS.map(([l, p], i) => `<button class="btn" data-i="${i}">${esc(l)}</button>`).join("");
$$("#presets button").forEach(b => (b.onclick = () => { $("#cmp-in").value = PRESETS[b.dataset.i][1]; compare(); }));
async function compare() {
  const r = await fetch("/api/inspect", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ payload: $("#cmp-in").value }) });
  const j = await r.json();
  const hit = {}; j.findings.forEach(f => (hit[f.machine] = f));
  const rows = S.order.filter(id => !S.machines[id].perIP).map(id => {
    const d = S.machines[id], f = hit[id];
    return `<tr><td>${esc(d.title)}</td><td>${esc(d.cls)}</td><td>${f ? `<span class="yes">flagged</span> · ${esc(f.detail)}` : '<span class="no">—</span>'}</td></tr>`;
  }).join("");
  const dfa = j.findings.some(f => S.machines[f.machine].kind === "dfa"), cf = j.findings.some(f => S.machines[f.machine].kind !== "dfa");
  const v = !j.findings.length ? ["none", "No machine flags this payload."] : !dfa && cf ? ["win", "Missed by every DFA, caught by a context-free machine. A regular language cannot describe this."] :
    dfa && cf ? ["ok", "Caught by both the DFAs and the context-free machines."] : ["ok", "Caught by the DFAs."];
  $("#cmp-out").innerHTML = `<table class="cmp" style="margin-top:12px"><tr><th>Machine</th><th>Class</th><th>Verdict</th></tr>${rows}</table><div class="verdict ${v[0]}">${v[1]}</div>`;
}
$("#cmp-go").onclick = compare;

/* ------------------------------------------------------------------ boot */
setInterval(renderTimeline, 1000);
connect();
