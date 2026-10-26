// The Cairn admin UI. Plain JavaScript, no build step: it's embedded in the
// binary as is. Everything shown that comes from the server is put on the page
// as text (never as HTML), since keys and names can be anything.
"use strict";

// ─── Helpers ────────────────────────────────────────────────────────────────

/** Builds an element: h("a", {href: "#"}, "text", child, ...). */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "style") Object.assign(el.style, v);
    else if (v === true) el.setAttribute(k, "");
    else el.setAttribute(k, v);
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}

const SVG = "http://www.w3.org/2000/svg";
function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v !== null && v !== undefined) el.setAttribute(k, v);
  }
  append(el, children);
  return el;
}

function bytes(n) {
  if (n === null || n === undefined) return "–";
  const units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
  let i = 0;
  let v = Number(n);
  while (Math.abs(v) >= 1024 && i < units.length - 1) { v /= 1024; i++; }
  return (i === 0 ? v.toFixed(0) : v.toFixed(v < 10 ? 2 : v < 100 ? 1 : 0)) + " " + units[i];
}

function num(n) {
  if (n === null || n === undefined) return "–";
  return Number(n).toLocaleString("en-US");
}

function rate(n) {
  if (!isFinite(n)) return "–";
  if (n === 0) return "0";
  if (n < 0.1) return n.toFixed(3);
  if (n < 10) return n.toFixed(2);
  if (n < 1000) return n.toFixed(1);
  return num(Math.round(n));
}

function pct(part, whole) {
  if (!whole) return "–";
  const p = (100 * part) / whole;
  return (p > 0 && p < 0.1 ? "<0.1" : p.toFixed(p < 10 ? 1 : 0)) + "%";
}

function duration(secs) {
  if (secs === null || secs === undefined || !isFinite(secs)) return "–";
  secs = Math.max(0, secs);
  if (secs < 1) return Math.round(secs * 1000) + " ms";
  if (secs < 60) return secs.toFixed(secs < 10 ? 1 : 0) + " s";
  if (secs < 3600) return Math.floor(secs / 60) + "m " + Math.floor(secs % 60) + "s";
  if (secs < 86400) return Math.floor(secs / 3600) + "h " + Math.floor((secs % 3600) / 60) + "m";
  return Math.floor(secs / 86400) + "d " + Math.floor((secs % 86400) / 3600) + "h";
}

function ago(t) {
  if (!t) return "never";
  return duration(Date.now() / 1000 - t) + " ago";
}

function date(t) {
  if (!t) return "–";
  const d = new Date(t * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
    `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function clock(t) {
  const d = new Date(t * 1000);
  return String(d.getHours()).padStart(2, "0") + ":" + String(d.getMinutes()).padStart(2, "0");
}

function badge(text, kind) {
  return h("span", { class: "badge " + (kind || "") }, text);
}

function card(label, value, note, kind) {
  return h("div", { class: "card " + (kind || "") },
    h("div", { class: "label" }, label),
    h("div", { class: "value", title: String(value) }, value),
    note ? h("div", { class: "note" }, note) : null);
}

function panel(title, ...children) {
  return h("section", { class: "panel" }, title ? h("h2", {}, title) : null, ...children);
}

function table(headers, rows, emptyText) {
  const head = h("tr", {}, headers.map((c) => {
    const [label, cls] = Array.isArray(c) ? c : [c, ""];
    return h("th", { class: cls }, label);
  }));
  const body = rows.length
    ? rows
    : [h("tr", {}, h("td", { class: "empty", colspan: headers.length }, emptyText || "Nothing here."))];
  return h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, head), h("tbody", {}, body)));
}

function bar(used, total, warnAt = 0.8, badAt = 0.92) {
  const f = total ? Math.min(1, used / total) : 0;
  const kind = f >= badAt ? "bad" : f >= warnAt ? "warn" : "";
  const fill = h("span");
  fill.style.width = (f * 100).toFixed(1) + "%";
  return h("div", { class: "bar " + kind }, fill);
}

function toast(message, error) {
  const t = h("div", { class: "toast" + (error ? " error" : "") }, message);
  document.getElementById("toasts").append(t);
  setTimeout(() => t.remove(), error ? 7000 : 3500);
}

// ─── API ────────────────────────────────────────────────────────────────────

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

async function api(method, path, body) {
  const opts = { method, headers: { "x-cairn-ui": "1" }, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["content-type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch("/api/" + path, opts);
  let data = {};
  try { data = await res.json(); } catch (_) { /* not JSON */ }
  if (res.status === 401 && path !== "login") {
    showLogin();
    throw new ApiError(401, "not logged in");
  }
  if (!res.ok) throw new ApiError(res.status, data.error || `request failed (${res.status})`);
  return data;
}

/** Runs an action, telling the user how it went. Resolves to its result, or
 * undefined if it failed. */
async function act(fn, success) {
  try {
    const result = await fn();
    if (success) toast(success);
    return result;
  } catch (e) {
    if (e.status !== 401) toast(e.message, true);
  }
}

function enc(s) { return encodeURIComponent(s); }

// ─── Merged metrics ─────────────────────────────────────────────────────────

/** Adds up the request history of `nodes` (their `stats`), slot by slot. */
function mergeHistory(nodes) {
  const slots = new Map();
  let slotSecs = 10;
  for (const n of nodes) {
    const r = n.stats && n.stats.requests;
    if (!r) continue;
    slotSecs = r.slot_secs;
    for (const e of r.history) {
      const acc = slots.get(e.t) || { t: e.t, requests: 0, client_errors: 0, server_errors: 0, bytes_in: 0, bytes_out: 0, latency_us: 0 };
      for (const k of ["requests", "client_errors", "server_errors", "bytes_in", "bytes_out", "latency_us"]) acc[k] += e[k];
      slots.set(e.t, acc);
    }
  }
  return { slotSecs, slots };
}

/** Per-second rates over the last `window` seconds of complete slots. */
function recentRates(merged, window = 60) {
  const now = Date.now() / 1000;
  const totals = { requests: 0, client_errors: 0, server_errors: 0, bytes_in: 0, bytes_out: 0, latency_us: 0 };
  for (const e of merged.slots.values()) {
    if (e.t + merged.slotSecs <= now && e.t + merged.slotSecs > now - window) {
      for (const k in totals) totals[k] += e[k];
    }
  }
  return {
    requests: totals.requests / window,
    client_errors: totals.client_errors / window,
    server_errors: totals.server_errors / window,
    bytes_in: totals.bytes_in / window,
    bytes_out: totals.bytes_out / window,
    latency: totals.requests ? totals.latency_us / totals.requests / 1e6 : null,
  };
}

/** The series for a chart over the last `span` seconds, one point per
 * complete slot, with slots without requests as zeroes. */
function seriesOf(merged, span, value) {
  const now = Date.now() / 1000;
  const step = merged.slotSecs;
  const last = Math.floor(now / step) * step - step;
  const points = [];
  for (let t = last - span + step; t <= last; t += step) {
    const e = merged.slots.get(t);
    points.push([t, e ? value(e) : 0]);
  }
  return points;
}

function opsTotals(nodes) {
  const ops = new Map();
  for (const n of nodes) {
    const r = n.stats && n.stats.requests;
    if (!r) continue;
    for (const o of r.ops) {
      const acc = ops.get(o.op) || { op: o.op, requests: 0, client_errors: 0, server_errors: 0, bytes_in: 0, bytes_out: 0, latency_us: 0 };
      for (const k of ["requests", "client_errors", "server_errors", "bytes_in", "bytes_out", "latency_us"]) acc[k] += o[k];
      ops.set(o.op, acc);
    }
  }
  return [...ops.values()];
}

// ─── Charts ─────────────────────────────────────────────────────────────────

/** A line chart of `series` ([{name, color, points: [[t, v]]}]) with values
 * shown by `fmt`. Drawn at the size it's laid out at, so that its text isn't
 * stretched, and again whenever that changes. */
function lineChart(series, fmt) {
  const all = series.flatMap((s) => s.points);
  if (!all.length) return h("div", { class: "empty" }, "No data yet.");
  const H = 190, L = 56, R = 8, T = 8, B = 22;
  const pts = series[0].points;
  const t0 = pts[0][0], t1 = pts[pts.length - 1][0];
  const max = niceMax(Math.max(...all.map((p) => p[1]), 0));
  const svg = s("svg", {});
  const tip = h("div", { class: "tooltip" });
  tip.hidden = true;
  const wrap = h("div", { class: "chart" }, svg, tip,
    h("div", { class: "legend" }, series.map((se) => {
      const i = h("i");
      i.style.background = se.color;
      return h("span", {}, i, se.name);
    })));
  let W = 0;
  const x = (t) => L + ((t - t0) / Math.max(1, t1 - t0)) * (W - L - R);
  const y = (v) => T + (1 - v / max) * (H - T - B);
  let cursor;
  const draw = () => {
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.replaceChildren();
    for (let i = 0; i <= 4; i++) {
      const v = (max * i) / 4;
      svg.append(s("line", { class: "grid-line", x1: L, x2: W - R, y1: y(v), y2: y(v) }));
      svg.append(s("text", { class: "axis-label", x: L - 6, y: y(v) + 4, "text-anchor": "end" }, fmt(v)));
    }
    const ticks = Math.max(2, Math.min(6, Math.floor((W - L) / 70)));
    for (let i = 0; i <= ticks; i++) {
      const t = t0 + ((t1 - t0) * i) / ticks;
      svg.append(s("text", { class: "axis-label", x: x(t), y: H - 6, "text-anchor": i === 0 ? "start" : i === ticks ? "end" : "middle" }, clock(t)));
    }
    for (const se of series) {
      const d = se.points.map((p, i) => (i ? "L" : "M") + x(p[0]).toFixed(1) + "," + y(p[1]).toFixed(1)).join("");
      if (se.fill) svg.append(s("path", { class: "area", fill: se.color, d: d + `L${x(t1)},${y(0)}L${x(t0)},${y(0)}Z` }));
      svg.append(s("path", { class: "line", stroke: se.color, d }));
    }
    cursor = s("line", { class: "cursor", y1: T, y2: H - B, visibility: "hidden" });
    svg.append(cursor);
  };
  const resized = new ResizeObserver(() => {
    if (!wrap.isConnected) { resized.disconnect(); return; }
    const width = Math.round(svg.getBoundingClientRect().width);
    if (width && width !== W) { W = width; draw(); }
  });
  resized.observe(wrap);
  svg.addEventListener("mousemove", (ev) => {
    if (!W) return;
    const px = ev.clientX - svg.getBoundingClientRect().left;
    let idx = Math.round(((px - L) / (W - L - R)) * (pts.length - 1));
    idx = Math.max(0, Math.min(pts.length - 1, idx));
    const t = pts[idx][0];
    cursor.setAttribute("x1", x(t));
    cursor.setAttribute("x2", x(t));
    cursor.setAttribute("visibility", "visible");
    tip.replaceChildren(h("div", { class: "t" }, clock(t) + ":" + String(new Date(t * 1000).getSeconds()).padStart(2, "0")),
      series.map((se) => h("div", {}, se.name + ": " + fmt(se.points[idx][1]))));
    tip.hidden = false;
    tip.style.left = Math.max(0, Math.min(x(t) + 12, W - tip.offsetWidth)) + "px";
    tip.style.top = "4px";
  });
  svg.addEventListener("mouseleave", () => { if (cursor) cursor.setAttribute("visibility", "hidden"); tip.hidden = true; });
  return wrap;
}

function niceMax(v) {
  if (v <= 0) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * exp) return m * exp;
  return 10 * exp;
}

const color = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

// ─── Pages ──────────────────────────────────────────────────────────────────

const state = { role: null, timer: null, span: 900, route: null, cluster: null, storage: null };

const pages = {
  overview: { title: "Overview", poll: 5000, render: renderOverview },
  storage: { title: "Storage", poll: 30000, render: renderStorage },
  jobs: { title: "Jobs", poll: 5000, render: renderJobs },
  buckets: { title: "Buckets", render: renderBuckets },
  bucket: { title: "Bucket", nav: "buckets", render: renderBucket },
  object: { title: "Object", nav: "buckets", render: renderObject },
  roles: { title: "Roles", render: renderRoles },
};

function parseRoute() {
  const hash = location.hash.replace(/^#\/?/, "");
  const [path, query] = hash.split("?");
  const parts = path.split("/").map(decodeURIComponent);
  return { page: pages[parts[0]] ? parts[0] : "overview", args: parts.slice(1), params: new URLSearchParams(query || "") };
}

async function navigate() {
  clearTimeout(state.timer);
  if (!state.role) return;
  const route = parseRoute();
  state.route = route;
  const page = pages[route.page];
  document.title = page.title + " · Cairn";
  for (const a of document.querySelectorAll("#nav a")) {
    a.classList.toggle("active", a.dataset.page === (page.nav || route.page));
  }
  const main = document.getElementById("main");
  main.replaceChildren(h("div", { class: "subtle" }, "Loading…"));
  await refresh(route, true);
}

/** Renders the page of `route`, and schedules its next refresh. */
async function refresh(route, first) {
  if (state.route !== route) return;
  const page = pages[route.page];
  const main = document.getElementById("main");
  try {
    const content = await page.render(route, first);
    if (state.route !== route) return;
    if (content) {
      // Keep the scroll position across refreshes.
      const y = window.scrollY;
      main.replaceChildren(content);
      if (!first) window.scrollTo(0, y);
    }
  } catch (e) {
    if (e.status === 401) return;
    if (state.route !== route) return;
    if (first) main.replaceChildren(panel("Something went wrong", h("p", {}, e.message)));
    else toast(e.message, true);
  }
  if (page.poll && state.route === route) {
    state.timer = setTimeout(function again() {
      if (document.hidden) state.timer = setTimeout(again, 1000);
      else refresh(route, false);
    }, page.poll);
  }
}

// ── Overview ──

async function renderOverview() {
  const cluster = (state.cluster = await api("GET", "cluster"));
  const nodes = cluster.nodes;
  const live = nodes.filter((n) => n.live);
  const merged = mergeHistory(nodes);
  const r = recentRates(merged);
  const rfs = new Set(live.filter((n) => n.stats && n.stats.replication_factor).map((n) => n.stats.replication_factor));
  let diskTotal = 0, diskAvail = 0;
  for (const n of live) {
    const d = n.stats && n.stats.disk;
    if (d && d.total) { diskTotal += d.total; diskAvail += d.available; }
  }
  const rf = cluster.replication_factor;
  const inFlight = live.reduce((a, n) => a + ((n.stats && n.stats.in_flight) || 0), 0);
  const errRate = r.requests ? r.server_errors / r.requests : 0;

  const cards = h("div", { class: "cards" },
    card("Nodes live", `${live.length} / ${nodes.length}`,
      live.length < rf ? `fewer than the replication factor (${rf}): uploads fail` : live.length < nodes.length ? "some nodes are down" : "all nodes are up",
      live.length < rf ? "bad" : live.length < nodes.length ? "warn" : "ok"),
    card("Replication factor", rfs.size > 1 ? [...rfs].join(" / ") : String(rf),
      rfs.size > 1 ? "nodes disagree: check --replication-factor" : "copies of every blob", rfs.size > 1 ? "bad" : ""),
    card("Requests", rate(r.requests) + "/s", `${num(inFlight)} in flight · last minute`),
    card("Errors", rate(r.server_errors + r.client_errors) + "/s",
      `${rate(r.server_errors)}/s server · ${rate(r.client_errors)}/s client`, errRate > 0.01 ? "bad" : r.server_errors ? "warn" : ""),
    card("Throughput", bytes(r.bytes_in + r.bytes_out) + "/s", `${bytes(r.bytes_in)}/s in · ${bytes(r.bytes_out)}/s out`),
    card("Latency", r.latency === null ? "–" : duration(r.latency), "average, to response headers"),
    card("Disk", diskTotal ? pct(diskTotal - diskAvail, diskTotal) + " used" : "–",
      diskTotal ? `${bytes(diskAvail)} free of ${bytes(diskTotal)}, over live nodes` : "", diskTotal && diskAvail / diskTotal < 0.08 ? "bad" : diskTotal && diskAvail / diskTotal < 0.2 ? "warn" : ""),
  );

  const span = state.span;
  const spanPicker = h("select", { onchange: (e) => { state.span = Number(e.target.value); refresh(state.route, false); } },
    [[300, "5 min"], [900, "15 min"], [1800, "30 min"], [3600, "1 hour"]].map(([v, l]) => h("option", { value: v, selected: v === span }, l)));
  const perSec = (k) => (e) => e[k] / merged.slotSecs;
  const charts = h("div", { class: "grid cols-3" },
    panel(h("span", {}, "Requests ", h("span", { class: "subtle" }, "per second")),
      lineChart([
        { name: "all", color: color("--series-1"), fill: true, points: seriesOf(merged, span, perSec("requests")) },
        { name: "4xx", color: color("--series-2"), points: seriesOf(merged, span, perSec("client_errors")) },
        { name: "5xx", color: color("--series-3"), points: seriesOf(merged, span, perSec("server_errors")) },
      ], rate)),
    panel(h("span", {}, "Throughput ", h("span", { class: "subtle" }, "per second")),
      lineChart([
        { name: "in", color: color("--series-1"), fill: true, points: seriesOf(merged, span, perSec("bytes_in")) },
        { name: "out", color: color("--series-4"), fill: true, points: seriesOf(merged, span, perSec("bytes_out")) },
      ], bytes)),
    panel(h("span", {}, "Latency ", h("span", { class: "subtle" }, "average, to response headers")),
      lineChart([
        { name: "latency", color: color("--series-2"), points: seriesOf(merged, span, (e) => (e.requests ? e.latency_us / e.requests / 1e6 : 0)) },
      ], duration)),
  );

  const nodeRows = nodes.map((n) => {
    const st = n.stats && !n.stats.error ? n.stats : null;
    const disk = st && st.disk && st.disk.total ? st.disk : null;
    const nodeRates = st ? recentRates(mergeHistory([n])) : null;
    const m = st && st.maintenance;
    return h("tr", {},
      h("td", {}, h("span", { class: "live-dot" + (n.live ? "" : " down") }), "#" + n.id,
        n.id === cluster.this_node ? h("span", {}, " ", badge("this node", "accent")) : null),
      h("td", { class: "mono" }, n.peer_url, h("div", { class: "subtle small" }, n.node_id)),
      h("td", {}, n.live ? (st ? badge("live", "ok") : badge("not answering", "warn")) : badge("down", "bad"),
        h("div", { class: "subtle small" }, n.live ? (st ? "up " + duration(st.now - st.started_at) : n.stats && n.stats.error) : "last seen " + ago(n.last_seen))),
      h("td", {}, st ? st.version : "–", st && st.replication_factor !== rf ? h("div", {}, badge("RF " + st.replication_factor, "bad")) : null),
      h("td", { style: { minWidth: "180px" } }, disk
        ? [bar(disk.total - disk.available, disk.total), h("div", { class: "bar-label" }, h("span", {}, pct(disk.total - disk.available, disk.total) + " used"), h("span", {}, bytes(disk.available) + " free of " + bytes(disk.total)))]
        : h("span", { class: "subtle" }, bytes(n.free_space) + " free")),
      h("td", { class: "num" }, nodeRates ? rate(nodeRates.requests) + "/s" : "–"),
      h("td", { class: "num" }, st ? num(st.in_flight) : "–"),
      h("td", {}, m ? (m.running_since ? badge("running", "accent") : m.last_started ? ago(m.last_started) : "not yet") : "–"),
    );
  });

  const ops = opsTotals(live).filter((o) => o.requests).sort((a, b) => b.requests - a.requests);
  const opRows = ops.map((o) => h("tr", {},
    h("td", {}, o.op),
    h("td", { class: "num" }, num(o.requests)),
    h("td", { class: "num" }, num(o.client_errors)),
    h("td", { class: "num" }, o.server_errors ? h("span", { class: "badge bad" }, num(o.server_errors)) : "0"),
    h("td", { class: "num" }, duration(o.latency_us / o.requests / 1e6)),
    h("td", { class: "num" }, bytes(o.bytes_in)),
    h("td", { class: "num" }, bytes(o.bytes_out)),
  ));

  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Overview"), h("div", { class: "form-row" }, h("span", { class: "subtle" }, "Charts show"), spanPicker)),
    cards,
    charts,
    h("div", { class: "stack" },
      panel(h("span", {}, "Nodes ", h("span", { class: "subtle" }, "a node is live if it was seen in the last 10 s")),
        table(["Node", "Peer URL", "Status", "Version", "Disk", ["Requests", "num"], ["In flight", "num"], "Last maintenance"], nodeRows)),
      panel(h("span", {}, "Requests by operation ", h("span", { class: "subtle" }, "since each node started")),
        table(["Operation", ["Requests", "num"], ["4xx", "num"], ["5xx", "num"], ["Avg latency", "num"], ["In", "num"], ["Out", "num"]], opRows, "No requests yet."))),
  );
}

// ── Storage ──

async function renderStorage() {
  const [storage, cluster] = await Promise.all([api("GET", "storage"), api("GET", "cluster")]);
  state.storage = storage;
  const rf = storage.replication_factor;
  let healthy = 0, healthyBytes = 0, under = 0, underBytes = 0, lost = 0, lostBytes = 0;
  for (const g of storage.replicas) {
    if (g.live === 0) { lost += g.blobs; lostBytes += g.bytes; }
    else if (g.live < rf) { under += g.blobs; underBytes += g.bytes; }
    else { healthy += g.blobs; healthyBytes += g.bytes; }
  }
  const o = storage.objects, b = storage.blobs;
  const cards = h("div", { class: "cards" },
    card("Objects", num(o.current), bytes(o.current_bytes) + ` in ${num(o.buckets)} buckets`),
    card("Older versions", num(o.noncurrent), bytes(o.noncurrent_bytes) + ` · ${num(o.delete_markers)} delete markers`),
    card("Blobs", num(b.committed), bytes(b.bytes) + " before replication"),
    card("Garbage", bytes(b.garbage_bytes), pct(b.garbage_bytes, b.bytes) + " of blob bytes, freed by compaction", b.garbage_bytes / Math.max(1, b.bytes) > 0.3 ? "warn" : ""),
    card("Fully replicated", pct(healthyBytes, healthyBytes + underBytes + lostBytes), `${num(healthy)} blobs with ≥ ${rf} live copies`, under + lost ? "warn" : "ok"),
    card("Under-replicated", num(under), bytes(underBytes) + " with fewer live copies than " + rf, under ? "warn" : "ok"),
    card("Unavailable", num(lost), bytes(lostBytes) + " with no live copy", lost ? "bad" : "ok"),
  );

  const replicaRows = storage.replicas.map((g) => {
    const kind = g.live === 0 ? "bad" : g.live < rf ? "warn" : "ok";
    const label = g.live === 0 ? "unavailable" : g.live < rf ? "under-replicated" : g.live > rf ? "over-replicated" : "healthy";
    return h("tr", {},
      h("td", { class: "num" }, num(g.live)),
      h("td", { class: "num" }, num(g.copies)),
      h("td", {}, badge(label, kind), g.copies > g.live ? h("span", { class: "subtle small" }, ` ${g.copies - g.live} on down nodes`) : null),
      h("td", { class: "num" }, num(g.blobs)),
      h("td", { class: "num" }, bytes(g.bytes)),
      h("td", { style: { minWidth: "140px" } }, bar(g.bytes, b.bytes, 2, 2)),
    );
  });

  const byNode = new Map(storage.nodes.map((n) => [n.node, n]));
  const nodeRows = cluster.nodes.map((n) => {
    const held = byNode.get(n.id) || { blobs: 0, bytes: 0 };
    const disk = n.stats && n.stats.disk && n.stats.disk.total ? n.stats.disk : null;
    return h("tr", {},
      h("td", {}, h("span", { class: "live-dot" + (n.live ? "" : " down") }), "#" + n.id),
      h("td", { class: "mono" }, n.peer_url),
      h("td", { class: "num" }, num(held.blobs)),
      h("td", { class: "num" }, bytes(held.bytes)),
      h("td", { class: "num" }, pct(held.bytes, b.bytes * rf)),
      h("td", { style: { minWidth: "200px" } }, disk
        ? [bar(disk.total - disk.available, disk.total), h("div", { class: "bar-label" },
            h("span", {}, pct(disk.total - disk.available, disk.total) + " used"),
            h("span", {}, bytes(disk.available) + " free"))]
        : h("span", { class: "subtle small" }, bytes(n.free_space) + " free (as of last heartbeat)")),
    );
  });

  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Storage"), h("span", { class: "subtle small" }, "Counted from the catalog; refreshes every 30 s")),
    cards,
    h("div", { class: "grid cols-2" },
      panel(h("span", {}, "Replicas ", h("span", { class: "subtle" }, `committed blobs by copies on live nodes · replication factor ${rf}`)),
        table([["Live copies", "num"], ["Copies", "num"], "", ["Blobs", "num"], ["Bytes", "num"], ""], replicaRows, "No blobs yet.")),
      panel(h("span", {}, "Data per node ", h("span", { class: "subtle" }, "committed blobs each node holds a copy of")),
        table(["Node", "Peer URL", ["Blobs", "num"], ["Bytes", "num"], ["Share", "num"], "Disk"], nodeRows))),
  );
}

// ── Jobs ──

async function renderJobs(route, first) {
  // The catalog's backlog takes a scan, so it's fetched less often.
  const fetchStorage = first || !state.storage || Date.now() - (state.storageAt || 0) > 30000;
  const [cluster, storage] = await Promise.all([api("GET", "cluster"), fetchStorage ? api("GET", "storage") : state.storage]);
  if (fetchStorage) { state.storage = storage; state.storageAt = Date.now(); }
  const bl = storage.backlog, b = storage.blobs, pk = storage.packer;
  const now = Date.now() / 1000;
  const cards = h("div", { class: "cards" },
    card("Packing now", num(bl.packing), bytes(bl.packing_bytes) + " in blobs leased by packing jobs", bl.packing ? "ok" : ""),
    card("To consolidate", num(bl.consolidate), `${bytes(bl.consolidate_bytes)} in blobs ≤ ${bytes(pk.small_size)}; packed once ${bytes(pk.target_size)} or ${num(pk.max_sources)} blobs wait`),
    card("To compact", num(bl.compact), `${bytes(bl.compact_garbage_bytes)} of garbage in blobs ≥ ${pct(pk.compact_threshold, 1)} garbage`),
    card("Garbage log", num(bl.garbage_log), "deleted parts, folded on the next packer pass"),
    card("Pending blobs", num(b.pending), b.oldest_pending ? "oldest " + duration(now - b.oldest_pending) + "; dropped after a day" : "uploads and packing jobs in progress",
      b.oldest_pending && now - b.oldest_pending > 3600 ? "warn" : ""),
    card("Multipart uploads", num(bl.uploads), bl.oldest_upload ? `${bytes(bl.upload_bytes)} · oldest ${duration(now - bl.oldest_upload)}; given up after a day` : "none in progress",
      bl.oldest_upload && now - bl.oldest_upload > 3600 ? "warn" : ""),
  );

  const rows = [];
  const events = [];
  for (const n of cluster.nodes) {
    const m = n.stats && n.stats.maintenance;
    for (const e of (m && m.events) || []) events.push({ ...e, node: n.id });
    if (!n.live) {
      rows.push(h("tr", {}, h("td", {}, h("span", { class: "live-dot down" }), "#" + n.id), h("td", { colspan: 7, class: "subtle" }, "down")));
      continue;
    }
    if (!m) {
      rows.push(h("tr", {}, h("td", {}, h("span", { class: "live-dot" }), "#" + n.id), h("td", { colspan: 7, class: "subtle" }, (n.stats && n.stats.error) || "no data")));
      continue;
    }
    const next = m.last_started ? m.last_started + m.interval_secs : n.stats.started_at + m.interval_secs;
    rows.push(h("tr", {},
      h("td", {}, h("span", { class: "live-dot" }), "#" + n.id),
      h("td", {}, m.running_since ? [badge("running", "accent"), " for " + duration(n.stats.now - m.running_since)]
        : m.last_started ? [ago(m.last_started), h("div", { class: "subtle small" }, "took " + duration(m.last_duration) + " · next in " + duration(next - n.stats.now))]
        : ["not yet", h("div", { class: "subtle small" }, "first in " + duration(next - n.stats.now))]),
      h("td", { class: "num" }, num(m.passes)),
      h("td", { class: "mono small" }, m.last_started ? ["0x" + m.sweep_shard.toString(16).padStart(4, "0"), h("span", { class: "subtle" }, " of 0x" + m.shards.toString(16))] : "–"),
      h("td", { class: "num" }, `${num(m.gc.pending)} / ${num(m.gc.files)} / ${num(m.gc.dirs)}`, m.gc.errors ? h("div", {}, badge(num(m.gc.errors) + " errors", "bad")) : null),
      h("td", { class: "num" }, num(m.packer.jobs), m.packer.failed ? h("div", {}, badge(num(m.packer.failed) + " failed", "bad")) : null),
      h("td", { class: "num" }, num(m.packer.blobs) + " → " + num(m.packer.parts) + " parts"),
      h("td", { class: "num" }, bytes(m.packer.bytes)),
    ));
  }
  events.sort((a, b) => b.time - a.time);
  const eventRows = events.slice(0, 200).map((e) => h("tr", { class: e.error ? "error" : "" },
    h("td", { class: "subtle", title: date(e.time) }, ago(e.time)),
    h("td", {}, "#" + e.node),
    h("td", {}, badge(e.source, e.error ? "bad" : "")),
    h("td", { class: "msg" }, e.message)));

  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Background jobs"),
      h("span", { class: "subtle small" }, "Every node runs garbage collection, then packing, once a minute")),
    cards,
    panel(h("span", {}, "Maintenance per node ", h("span", { class: "subtle" }, "totals since each node started")),
      table(["Node", "Last pass", ["Passes", "num"], "File sweep at", ["GC: pending / files / dirs", "num"], ["Packing jobs", "num"], ["Blobs packed", "num"], ["Bytes moved", "num"]], rows)),
    panel(h("span", {}, "Recent events ", h("span", { class: "subtle" }, "what passes did, and what failed; the last 100 per node")),
      h("div", { class: "events" }, table(["When", "Node", "Source", "Message"], eventRows, "Nothing happened yet: passes that do nothing aren't listed."))),
  );
}

// ── Buckets ──

async function renderBuckets() {
  const { buckets } = await api("GET", "buckets");
  const name = h("input", { type: "text", placeholder: "new-bucket-name", "aria-label": "Bucket name" });
  const form = h("form", { class: "form-row", onsubmit: async (e) => {
    e.preventDefault();
    if (await act(() => api("POST", "buckets", { name: name.value.trim() }), `Created bucket ${name.value.trim()}`)) navigate();
  } }, name, h("button", { class: "primary", type: "submit" }, "Create bucket"));
  const rows = buckets.map((bk) => h("tr", {},
    h("td", { class: "key" }, h("a", { href: "#/bucket/" + enc(bk.name) }, bk.name)),
    h("td", {}, bk.versioning === "enabled" ? badge("versioned", "accent") : bk.versioning === "suspended" ? badge("suspended", "warn") : badge("unversioned")),
    h("td", { class: "num" }, num(bk.objects)),
    h("td", { class: "num" }, bytes(bk.bytes)),
    h("td", { class: "num" }, bk.versions > bk.objects ? `${num(bk.versions - bk.objects)} · ${bytes(bk.version_bytes - bk.bytes)}` : "–"),
    h("td", { class: "num" }, num(bk.uploads)),
    h("td", { class: "num" }, num(bk.roles)),
    h("td", {}, date(bk.created_at)),
    h("td", { class: "actions" },
      h("button", { class: "small danger", onclick: async () => {
        if (!confirm(`Delete bucket "${bk.name}"? It must be empty.`)) return;
        if (await act(() => api("DELETE", "buckets/" + enc(bk.name)), `Deleted bucket ${bk.name}`)) navigate();
      } }, "Delete")),
  ));
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Buckets"), form),
    panel(null, table(["Name", "Versioning", ["Objects", "num"], ["Size", "num"], ["Older versions", "num"], ["Uploads", "num"], ["Roles", "num"], "Created", ""], rows, "No buckets yet.")),
  );
}

function crumbs(bucket, prefix) {
  const out = [h("a", { href: "#/buckets" }, "Buckets"), h("span", { class: "sep" }, "/"), h("a", { href: "#/bucket/" + enc(bucket) }, bucket)];
  let acc = "";
  for (const seg of prefix.split("/").slice(0, -1)) {
    acc += seg + "/";
    out.push(h("span", { class: "sep" }, "/"), h("a", { href: `#/bucket/${enc(bucket)}?prefix=${enc(acc)}` }, seg || "(empty)"));
  }
  return h("div", { class: "crumbs" }, out);
}

function downloadUrl(bucket, key, version) {
  return `/api/buckets/${enc(bucket)}/download?key=${enc(key)}` + (version ? "&version=" + enc(version) : "");
}

async function renderBucket(route) {
  const bucket = route.args[0] || "";
  const prefix = route.params.get("prefix") || "";
  const deleted = route.params.get("deleted") === "1";
  const tbody = h("tbody");
  const more = h("button", { hidden: true }, "Load more");
  let next = null;
  const load = async () => {
    const q = `prefix=${enc(prefix)}&after=${enc(next || "")}` + (deleted ? "&deleted=1" : "");
    const page = await api("GET", `buckets/${enc(bucket)}/objects?${q}`);
    for (const e of page.entries) {
      if (e.prefix !== undefined) {
        tbody.append(h("tr", {},
          h("td", { class: "key" }, h("a", { href: `#/bucket/${enc(bucket)}?prefix=${enc(e.prefix)}` + (deleted ? "&deleted=1" : "") }, "📁 " + e.prefix.slice(prefix.length))),
          h("td", { class: "num" }, bytes(e.bytes)),
          h("td", { class: "num subtle" }, num(e.objects) + " objects"),
          h("td", {}, date(e.last_modified)),
          h("td", {})));
      } else {
        const link = `#/object/${enc(bucket)}?key=${enc(e.key)}`;
        tbody.append(h("tr", {},
          h("td", { class: "key" }, h("a", { href: link }, e.key.slice(prefix.length)), e.delete_marker ? h("span", {}, " ", badge("deleted", "warn")) : null),
          h("td", { class: "num" }, e.delete_marker ? "–" : bytes(e.size)),
          h("td", { class: "num mono subtle small" }, e.etag || ""),
          h("td", {}, date(e.last_modified)),
          h("td", { class: "actions" },
            h("a", { class: "button small", href: link }, "Details"),
            e.delete_marker ? null : h("a", { class: "button small", href: downloadUrl(bucket, e.key) }, "Download"))));
      }
    }
    if (!tbody.children.length) tbody.append(h("tr", {}, h("td", { class: "empty", colspan: 5 }, prefix ? "Nothing under this prefix." : "This bucket is empty.")));
    next = page.next;
    more.hidden = !next;
  };
  more.addEventListener("click", () => act(load));
  await load();

  const open = h("input", { type: "search", placeholder: "Go to key…", "aria-label": "Key" });
  const goto = h("form", { class: "form-row", onsubmit: (e) => {
    e.preventDefault();
    if (open.value) location.hash = `#/object/${enc(bucket)}?key=${enc(open.value)}`;
  } }, open, h("button", { type: "submit" }, "Open"));
  const toggle = h("label", { class: "check" },
    h("input", { type: "checkbox", checked: deleted, onchange: (e) => {
      location.hash = `#/bucket/${enc(bucket)}?prefix=${enc(prefix)}` + (e.target.checked ? "&deleted=1" : "");
    } }), "Show deleted keys");
  return h("div", {},
    h("h1", {}, "Bucket ", h("span", { class: "mono" }, bucket)),
    crumbs(bucket, prefix),
    h("div", { class: "toolbar" }, toggle, h("span", { class: "spacer" }), goto),
    panel(null,
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Name"), h("th", { class: "num" }, "Size"), h("th", { class: "num" }, "ETag"), h("th", {}, "Last modified"), h("th", {}))),
        tbody)),
      h("div", { class: "toolbar" }, more)),
  );
}

async function renderObject(route) {
  const bucket = route.args[0] || "";
  const key = route.params.get("key") || "";
  const [obj, cluster] = await Promise.all([
    api("GET", `buckets/${enc(bucket)}/object?key=${enc(key)}`),
    state.cluster ? Promise.resolve(state.cluster) : api("GET", "cluster"),
  ]);
  state.cluster = cluster;
  const nodes = new Map(cluster.nodes.map((n) => [n.id, n]));
  const lastSlash = key.lastIndexOf("/");
  const prefix = lastSlash >= 0 ? key.slice(0, lastSlash + 1) : "";
  const versions = obj.versions.map((v) => {
    const head = h("div", { class: "version-head" },
      v.latest ? badge("current", "accent") : badge("older"),
      v.delete_marker ? badge("delete marker", "warn") : null,
      h("span", { class: "mono" }, "version " + v.version_id),
      h("span", { class: "subtle" }, date(v.last_modified)),
      h("span", { class: "spacer" }),
      v.delete_marker ? null : h("a", { class: "button small", href: downloadUrl(bucket, key, v.version_id) }, "Download"));
    if (v.delete_marker) return h("div", { class: "version" + (v.latest ? " latest" : "") }, head);
    const partRows = v.parts.map((p) => h("tr", {},
      h("td", { class: "num" }, p.number),
      h("td", { class: "num" }, bytes(p.size)),
      h("td", { class: "mono small" }, p.blob_id, h("div", { class: "subtle" }, `at ${num(p.blob_offset)} of ${bytes(p.blob_size)}` + (p.blob_size > p.size ? " (packed)" : ""))),
      h("td", {}, p.nodes.length ? p.nodes.map((id) => {
        const n = nodes.get(id);
        return h("span", { class: "chip", title: n ? n.peer_url : "" }, h("span", { class: "live-dot" + (n && n.live ? "" : " down") }), "#" + id + " ");
      }) : badge("no copies", "bad"),
      p.nodes.filter((id) => nodes.get(id) && nodes.get(id).live).length < cluster.replication_factor ? h("span", {}, " ", badge("under-replicated", "warn")) : null),
      h("td", { class: "mono small" }, p.crc64nvme || "–"),
    ));
    return h("div", { class: "version" + (v.latest ? " latest" : "") }, head,
      h("dl", { class: "kv" },
        h("dt", {}, "Size"), h("dd", {}, bytes(v.size) + ` (${num(v.size)} bytes)`),
        h("dt", {}, "ETag"), h("dd", { class: "mono" }, v.etag),
        h("dt", {}, "Content type"), h("dd", {}, v.content_type)),
      h("div", { style: { marginTop: "10px" } }, table([["Part", "num"], ["Size", "num"], "Blob", "Replicas", "CRC64/NVME"], partRows, "No parts.")));
  });
  return h("div", {},
    h("h1", {}, "Object"),
    crumbs(bucket, prefix),
    panel(null, h("dl", { class: "kv" },
      h("dt", {}, "Bucket"), h("dd", {}, bucket),
      h("dt", {}, "Key"), h("dd", { class: "mono" }, key),
      h("dt", {}, "Versions"), h("dd", {}, num(obj.versions.length) + (obj.versions.length >= 200 ? " (showing the newest 200)" : "")))),
    obj.versions.length ? versions : panel(null, h("p", { class: "empty" }, "No such key.")),
  );
}

// ── Roles ──

function showSecret(name, secret) {
  const input = h("input", { type: "text", readonly: true, value: secret });
  const dialog = h("dialog", {},
    h("h2", {}, "Secret for ", h("span", { class: "mono" }, name)),
    h("p", { class: "subtle" }, "Store it now: it isn't shown again. Clients use the role's name as access key ID and this as secret access key."),
    h("div", { class: "secret" }, input,
      h("button", { onclick: async () => {
        try { await navigator.clipboard.writeText(secret); toast("Copied"); } catch (_) { input.select(); }
      } }, "Copy")),
    h("div", { class: "buttons" }, h("button", { class: "primary", onclick: () => dialog.close() }, "Done")));
  dialog.addEventListener("close", () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
  input.select();
}

async function renderRoles() {
  const [{ roles }, { buckets }] = await Promise.all([api("GET", "roles"), api("GET", "buckets")]);
  const name = h("input", { type: "text", placeholder: "role-name", "aria-label": "Role name", autocomplete: "off" });
  const secret = h("input", { type: "password", placeholder: "secret (generated if empty)", "aria-label": "Secret", autocomplete: "new-password" });
  const admin = h("input", { type: "checkbox" });
  const create = h("form", { class: "form-row", onsubmit: async (e) => {
    e.preventDefault();
    const res = await act(() => api("POST", "roles", { name: name.value.trim(), secret: secret.value, admin: admin.checked }), `Created role ${name.value.trim()}`);
    if (!res) return;
    if (!secret.value) showSecret(res.name, res.secret);
    navigate();
  } }, name, secret, h("label", { class: "check" }, admin, "Admin"), h("button", { class: "primary", type: "submit" }, "Create role"));

  const rows = roles.map((r) => {
    const self = r.name === state.role;
    const grants = r.grants.map((g) => h("span", { class: "chip" }, `${g.bucket}: ${g.permission}`,
      h("button", { title: "Revoke", "aria-label": `Revoke ${g.permission} on ${g.bucket}`, onclick: async () => {
        if (await act(() => api("DELETE", `roles/${enc(r.name)}/grants?bucket=${enc(g.bucket)}&permission=${enc(g.permission)}`), `Revoked ${g.permission} on ${g.bucket}`)) navigate();
      } }, "×")));
    const bucketSel = h("select", { "aria-label": "Bucket" }, buckets.map((b) => h("option", { value: b.name }, b.name)));
    const perms = ["read", "write", "delete-version"].map((p) => h("input", { type: "checkbox", value: p, checked: p === "read" }));
    const grantForm = h("form", { class: "form-row", hidden: true, onsubmit: async (e) => {
      e.preventDefault();
      const permissions = perms.filter((c) => c.checked).map((c) => c.value);
      if (await act(() => api("POST", `roles/${enc(r.name)}/grants`, { bucket: bucketSel.value, permissions }), `Granted ${permissions.join(", ")} on ${bucketSel.value}`)) navigate();
    } }, bucketSel, perms.map((c) => h("label", { class: "check" }, c, c.value)), h("button", { class: "small primary", type: "submit" }, "Grant"));
    return h("tr", {},
      h("td", { class: "mono" }, r.name, self ? h("span", {}, " ", badge("you", "accent")) : null),
      h("td", {}, r.admin ? badge("admin", "accent") : h("span", { class: "subtle" }, "–")),
      h("td", {}, grants.length ? grants : h("span", { class: "subtle" }, "no grants"), grantForm),
      h("td", {}, date(r.created_at)),
      h("td", { class: "actions" },
        h("button", { class: "small", disabled: !buckets.length, title: buckets.length ? "" : "Create a bucket first", onclick: () => { grantForm.hidden = !grantForm.hidden; } }, "Grant…"),
        h("button", { class: "small", disabled: self && r.admin, title: self ? "You can't demote yourself" : "", onclick: async () => {
          if (r.admin && !confirm(`Revoke admin from "${r.name}"?`)) return;
          if (await act(() => api("POST", `roles/${enc(r.name)}/admin`, { admin: !r.admin }), r.admin ? `${r.name} is no longer an admin` : `${r.name} is now an admin`)) navigate();
        } }, r.admin ? "Revoke admin" : "Make admin"),
        h("button", { class: "small", onclick: async () => {
          const warn = self ? " You're logged in as this role, so you'll have to log in again." : "";
          if (!confirm(`Replace the secret of "${r.name}"? Clients using the old one stop working.${warn}`)) return;
          const res = await act(() => api("POST", `roles/${enc(r.name)}/secret`, {}));
          if (res) showSecret(res.name, res.secret);
          if (res && !self) navigate();
        } }, "Rotate secret"),
        h("button", { class: "small danger", disabled: self, title: self ? "You can't delete yourself" : "", onclick: async () => {
          if (!confirm(`Delete role "${r.name}" and all its grants? Clients using it stop working.`)) return;
          if (await act(() => api("DELETE", "roles/" + enc(r.name)), `Deleted role ${r.name}`)) navigate();
        } }, "Delete")),
    );
  });
  return h("div", {},
    h("div", { class: "page-head" }, h("h1", {}, "Roles")),
    panel("New role", create,
      h("p", { class: "subtle small" }, "A role's name is its access key ID. Admins manage buckets (and, here, roles); object access always takes a grant.")),
    panel(null, table(["Name", "Admin", "Grants", "Created", ""], rows, "No roles.")),
  );
}

// ─── Login ──────────────────────────────────────────────────────────────────

function showLogin() {
  state.role = null;
  clearTimeout(state.timer);
  state.route = null;
  document.body.classList.add("logged-out");
  document.getElementById("session").replaceChildren();
  const name = h("input", { type: "text", autocomplete: "username", required: true, id: "login-name" });
  const secret = h("input", { type: "password", autocomplete: "current-password", required: true, id: "login-secret" });
  const err = h("div", { class: "error" });
  const button = h("button", { class: "primary", type: "submit" }, "Log in");
  const form = h("form", { class: "login", onsubmit: async (e) => {
    e.preventDefault();
    button.disabled = true;
    err.textContent = "";
    try {
      const res = await api("POST", "login", { name: name.value, secret: secret.value });
      loggedIn(res.role);
    } catch (e) {
      err.textContent = e.message;
      button.disabled = false;
    }
  } },
    h("h1", {}, "Cairn admin"),
    h("p", { class: "subtle" }, "Log in with the name and secret of an admin role."),
    h("label", { for: "login-name" }, "Role name"), name,
    h("label", { for: "login-secret" }, "Secret"), secret,
    button, err);
  document.getElementById("main").replaceChildren(h("div", { class: "login-wrap" }, form));
  document.title = "Log in · Cairn";
  name.focus();
}

function loggedIn(role) {
  state.role = role;
  document.body.classList.remove("logged-out");
  document.getElementById("session").replaceChildren(
    h("span", { class: "who" }, "Logged in as ", h("strong", {}, role)),
    h("button", { class: "small", onclick: async () => {
      await act(() => api("POST", "logout"));
      showLogin();
    } }, "Log out"));
  navigate();
}

window.addEventListener("hashchange", navigate);
window.addEventListener("DOMContentLoaded", async () => {
  document.body.classList.add("logged-out");
  try {
    const session = await api("GET", "session");
    loggedIn(session.role);
  } catch (e) {
    if (e.status !== 401) {
      document.getElementById("main").replaceChildren(panel("Can't reach the node", h("p", {}, e.message)));
    }
  }
});
