#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
aa_exec_report.py — Executive + Technical HTML Report for Imperva Attack Analytics

Features:
- Robust fetching: chunking windows (--chunk-days), retries/backoff, parallel stats/sample fetch
- Filters: severity/host/violation/country/min-events
- Aggregation: severity, IPs, countries, agents, tools, tool types, URLs, hosts, class-C, rules, violations, CVEs
- Block rate: from time-series if present, else from incident-level approx
- Per-host breakdown
- Insights (recommended actions)
- Rule-name mapping (--rules-map JSON/CSV + --rule-label name|name_id)
- Export JSON + MoM delta vs previous export
- HTML UI: Dark Mode, Privacy mode (blur sensitive), Export CSV, TOC, sortable tables
- Charts: daily incidents, severity, top lists, Stacked Blocked vs Alerted, Heatmap Day×Hour
- Featured section: search box + severity toggle + copy-to-clipboard for IP/Host
- Optional PDF export (--pdf-out) using Chrome headless or wkhtmltopdf
- Optional Slack notify (--slack-webhook)
- Optional config preload (--config YAML)

Requirements:
  pip install requests python-dateutil pyyaml
"""

import argparse, json, sys, time, os, shutil, subprocess
from argparse import RawTextHelpFormatter
from datetime import datetime
from collections import Counter, defaultdict, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dateutil import tz, parser as dtparser

BKK_TZ = tz.gettz("Asia/Bangkok")

# ---------------- helpers (robust parsing) ----------------

def _as_int(x, default=0):
    try:
        if isinstance(x, bool): return int(x)
        if isinstance(x, (int, float)): return int(x)
        if isinstance(x, str):
            x = x.strip()
            if x == "": return default
            return int(float(x))
    except Exception:
        return default
    return default

def kv_count(kv, default=0):
    for k in ("value", "count", "events", "eventsCount", "num"):
        if k in kv: return _as_int(kv.get(k), default)
    return default

def kv_key_str(kv, ip=False):
    key = kv.get("key")
    if isinstance(key, str): return key
    if isinstance(key, dict):
        if ip: return key.get("ip") or key.get("value") or ""
        return key.get("value") or key.get("name") or key.get("country") or key.get("label") or ""
    return ""

def to_ms(dt_obj): return int(dt_obj.timestamp() * 1000)
def ms_to_dt(ms): return datetime.fromtimestamp(ms/1000, tz=BKK_TZ)
def ms_to_local_str(ms): return "-" if not isinstance(ms, int) else ms_to_dt(ms).strftime("%Y-%m-%d %H:%M:%S %Z")

def parse_date_to_ms(date_str):
    d = dtparser.parse(date_str)
    if d.tzinfo is None:
        d = datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=BKK_TZ)
    else:
        d = d.astimezone(BKK_TZ).replace(hour=0, minute=0, second=0, microsecond=0)
    return to_ms(d)

def end_of_day_ms(date_str):
    d = dtparser.parse(date_str)
    if d.tzinfo is None:
        d = datetime(d.year, d.month, d.day, 23, 59, 59, 999000, tzinfo=BKK_TZ)
    else:
        d = d.astimezone(BKK_TZ).replace(hour=23, minute=59, second=59, microsecond=999000)
    return to_ms(d)

def create_session(timeout, retries):
    s = requests.Session()
    retry = Retry(
        total=retries, connect=retries, read=retries, backoff_factor=0.8,
        status_forcelist=[429, 500, 502, 503, 504], allowed_methods=["GET"]
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=30, pool_maxsize=30)
    s.mount("https://", adapter); s.mount("http://", adapter)
    s.request_timeout = timeout
    return s

def http_get(session, base_url, path, headers, params=None, debug=False):
    import copy
    url = f"{base_url}{path}"
    if debug:
        red = copy.deepcopy(headers)
        for k in list(red.keys()):
            if k.lower() == "x-api-key": red[k] = "***"
        print(f"→ GET {url}\n  headers={red}\n  params={params}")
    r = session.get(url, headers=headers, params=params, timeout=session.request_timeout)
    if r.status_code == 401 and base_url.endswith("/analytics"):
        # auto-fallback to /attack-analytics if some tenants use that path
        alt = base_url.replace("/analytics", "/attack-analytics")
        if debug:
            print("  401 received. Retrying with base:", alt)
        r = session.get(f"{alt}{path}", headers=headers, params=params, timeout=session.request_timeout)
    if r.status_code in (401, 403):
        raise RuntimeError(
            f"{r.status_code} from {url} – ตรวจ API ID/Key และ CAID (ตอนนี้ใช้ CAID={params.get('caid') if params else 'N/A'}). "
            "ถ้าเทนแนนท์อยู่ region อื่น ลอง --base-url ให้ตรง"
        )
    r.raise_for_status()
    try: return r.json()
    except Exception: return r.text

# -------- rules mapping helpers --------

def load_rules_map(path):
    """Load rule-id -> rule-name mapping from JSON or CSV (columns: id,name)."""
    import csv
    if not path: return {}
    if not os.path.exists(path):
        print(f"[WARN] rules-map not found: {path}")
        return {}
    try:
        if path.lower().endswith(".json"):
            with open(path, "r", encoding="utf-8") as f:
                m = json.load(f)
            return {str(k): str(v) for k, v in m.items()}
        # CSV
        with open(path, "r", encoding="utf-8") as f:
            rdr = csv.DictReader(f)
            m = {}
            for row in rdr:
                rid = str(row.get("id") or row.get("ID") or "").strip()
                name = str(row.get("name") or row.get("NAME") or "").strip()
                if rid and name: m[rid] = name
            return m
    except Exception as e:
        print(f"[WARN] failed to load rules-map: {e}")
        return {}

def remap_rules_counter(counter, mapping, style="name_id"):
    """Return new Counter with keys remapped by mapping; style: name | name_id."""
    if not mapping: return counter
    out = Counter()
    for k, v in counter.items():
        k_str = str(k)
        name = mapping.get(k_str)
        label = (name if style == "name" else f"{name} ({k_str})") if name else k_str
        out[label] += v
    return out

# ---------------- fetching ----------------

def fetch_incidents(session, base_url, headers, caid, from_ms, to_ms, debug=False):
    return http_get(session, base_url, "/v1/incidents", headers,
                    {"caid": caid, "from_timestamp": from_ms, "to_timestamp": to_ms}, debug=debug) or []

def fetch_incidents_chunked(session, base_url, headers, caid, from_ms, to_ms, step_days=2, debug=False):
    out = []
    ms_day = 24*60*60*1000
    step = max(1, step_days) * ms_day
    total_windows = ((to_ms - from_ms) // step) + 1
    cur = from_ms
    idx = 1
    while cur <= to_ms:
        end = min(cur + step - 1, to_ms)
        print(f"  → window {idx}/{total_windows}: {ms_to_local_str(cur)} .. {ms_to_local_str(end)}")
        part = fetch_incidents(session, base_url, headers, caid, cur, end, debug=debug)
        if isinstance(part, list): out.extend(part)
        cur = end + 1
        idx += 1
    return out

# ---------------- aggregation ----------------

def aggregate_global(incidents, stats_list):
    by_severity = Counter()
    incident_by_day = Counter()

    approx_blocked = 0
    approx_total   = 0
    ts_blocked = 0
    ts_alerted = 0

    # time-series per day for stacked
    blocked_by_day = Counter()
    alerted_by_day = Counter()

    c_ips = Counter(); c_geos = Counter(); c_agents = Counter()
    c_tools = Counter(); c_tool_types = Counter()
    c_urls = Counter(); c_hosts = Counter(); c_classc = Counter(); c_rules = Counter()
    c_vio_blocked = Counter(); c_vio_alerted = Counter()
    c_waf_alerts = Counter(); c_waf_blocks = Counter(); c_waf_entities = Counter()
    c_cves = Counter()

    for inc in incidents:
        sev = (inc.get("severity") or "UNKNOWN").upper()
        by_severity[sev] += 1
        ts = inc.get("first_event_time")
        if isinstance(ts, int):
            incident_by_day[ms_to_dt(ts).strftime("%Y-%m-%d")] += 1
        events = inc.get("events_count") or 0
        pct_block = inc.get("events_blocked_percent") or 0
        approx_blocked += int(round(events * (pct_block/100.0)))
        approx_total   += int(events)

    def _ts_from_kv(kv):
        ts = kv.get("timestamp") or kv.get("time") or kv.get("key")
        try:
            return int(ts)
        except Exception:
            return None

    for st in stats_list:
        for kv in st.get("blocked_events_timeseries", []):
            c = kv_count(kv); ts = _ts_from_kv(kv)
            ts_blocked += c
            if ts:
                blocked_by_day[ms_to_dt(ts).strftime("%Y-%m-%d")] += c
        for kv in st.get("alerted_events_timeseries", []):
            c = kv_count(kv); ts = _ts_from_kv(kv)
            ts_alerted += c
            if ts:
                alerted_by_day[ms_to_dt(ts).strftime("%Y-%m-%d")] += c

        for kv in st.get("attack_ips", []):
            ip = kv_key_str(kv, ip=True); c = kv_count(kv)
            if ip: c_ips[ip] += c
        for kv in st.get("attack_geolocations", []):
            geo = kv_key_str(kv); c = kv_count(kv)
            if geo: c_geos[geo] += c
        for kv in st.get("attack_agents", []):
            a = kv_key_str(kv); c = kv_count(kv)
            if a: c_agents[a] += c
        for kv in st.get("attack_tools", []):
            t = kv_key_str(kv); c = kv_count(kv)
            if t: c_tools[t] += c
        for kv in st.get("attack_tool_types", []):
            tt = kv_key_str(kv); c = kv_count(kv)
            if tt: c_tool_types[tt] += c
        for kv in st.get("attack_urls", []):
            u = kv_key_str(kv); c = kv_count(kv)
            if u: c_urls[u] += c
        for kv in st.get("attacked_hosts", []):
            h = kv_key_str(kv); c = kv_count(kv)
            if h: c_hosts[h] += c
        for kv in st.get("attack_class_c", []):
            cc = kv_key_str(kv); c = kv_count(kv)
            if cc: c_classc[cc] += c
        for kv in st.get("rules_list", []):
            r = kv_key_str(kv); c = kv_count(kv)
            if r: c_rules[r] += c
        for kv in st.get("violations_blocked", []):
            v = kv_key_str(kv); c = kv_count(kv)
            if v: c_vio_blocked[v] += c
        for kv in st.get("violations_alerted", []):
            v = kv_key_str(kv); c = kv_count(kv)
            if v: c_vio_alerted[v] += c
        for kv in st.get("waf_origins_of_alerts", []):
            site = kv.get("siteName") or kv.get("site_name") or "-"
            vio  = kv.get("violation") or "-"
            c_waf_alerts[f"{site} | {vio}"] += kv_count(kv)
        for kv in st.get("waf_origins_of_blocks", []):
            site = kv.get("siteName") or kv.get("site_name") or "-"
            vio  = kv.get("violation") or "-"
            c_waf_blocks[f"{site} | {vio}"] += kv_count(kv)
        for kv in st.get("waf_origins_entities", []):
            site = kv.get("siteName") or kv.get("site_name") or "-"
            c_waf_entities[site] += kv_count(kv)
        for cve in st.get("associated_cve", []):
            c_cves[cve] += 1

    if (ts_blocked + ts_alerted) > 0:
        overall_block_rate = round(100.0 * ts_blocked / (ts_blocked + ts_alerted), 2)
    else:
        overall_block_rate = round(100.0 * (approx_blocked / approx_total), 2) if approx_total > 0 else 0.0

    return {
        "by_severity": by_severity,
        "incident_by_day": incident_by_day,
        "overall_block_rate": overall_block_rate,
        "ips": c_ips, "geos": c_geos, "agents": c_agents,
        "tools": c_tools, "tool_types": c_tool_types,
        "urls": c_urls, "hosts": c_hosts, "classc": c_classc, "rules": c_rules,
        "vio_blocked": c_vio_blocked, "vio_alerted": c_vio_alerted,
        "waf_alerts": c_waf_alerts, "waf_blocks": c_waf_blocks, "waf_entities": c_waf_entities,
        "cves": c_cves,
        "blocked_by_day": blocked_by_day,
        "alerted_by_day": alerted_by_day,
    }

def aggregate_per_host(stats_list, top_n_hosts=5):
    host_detail = defaultdict(lambda: {"urls": Counter(), "violations": Counter(), "tools": Counter(), "ips": Counter()})
    for st in stats_list:
        hosts = [kv_key_str(kv) for kv in st.get("attacked_hosts", []) if kv_key_str(kv)]
        for kv in st.get("attack_urls", []):
            u = kv_key_str(kv); c = kv_count(kv)
            if u and hosts:
                for h in hosts: host_detail[h]["urls"][u] += c
        for kv in st.get("violations_blocked", []):
            v = kv_key_str(kv); c = kv_count(kv)
            if v and hosts:
                for h in hosts: host_detail[h]["violations"][v] += c
        for kv in st.get("violations_alerted", []):
            v = kv_key_str(kv); c = kv_count(kv)
            if v and hosts:
                for h in hosts: host_detail[h]["violations"][v] += c
        for kv in st.get("attack_tools", []):
            t = kv_key_str(kv); c = kv_count(kv)
            if t and hosts:
                for h in hosts: host_detail[h]["tools"][t] += c
        for kv in st.get("attack_ips", []):
            ip = kv_key_str(kv, ip=True); c = kv_count(kv)
            if ip and hosts:
                for h in hosts: host_detail[h]["ips"][ip] += c
    host_totals = Counter({h: sum(v["urls"].values()) + sum(v["violations"].values()) for h, v in host_detail.items()})
    top_hosts = [h for h, _ in host_totals.most_common(top_n_hosts)]
    return OrderedDict((h, host_detail[h]) for h in top_hosts)

# ---------------- HTML rendering ----------------

def html_escape(s): return (s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')

def render_html(params, agg, per_host, incidents, featured, samples_by_id, insights,
                mom=None, rules_map=None, rule_label_style="name_id"):
    report_range = f"{ms_to_local_str(params['from_ms'])} – {ms_to_local_str(params['to_ms'])}"
    generated_at = datetime.now(tz=BKK_TZ).strftime("%Y-%m-%d %H:%M:%S %Z")

    head = """<!doctype html><html lang="th"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Attack Analytics – Executive + Technical Report</title>
<link rel="preconnect" href="https://cdn.jsdelivr.net"/>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-chart-matrix@2.0.1/dist/chartjs-chart-matrix.min.js"></script>
<style>
:root{--bg:#fff;--fg:#0f172a;--muted:#64748b;--card:#fff;--bd:#e2e8f0}
@media (prefers-color-scheme: dark){
  :root{--bg:#0b1220;--fg:#e5e7eb;--muted:#94a3b8;--card:#0f172a;--bd:#1f2937}
}
.dark{--bg:#0b1220;--fg:#e5e7eb;--muted:#94a3b8;--card:#0f172a;--bd:#1f2937}
body{font-family:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans","Liberation Sans",sans-serif;margin:24px;color:var(--fg);background:var(--bg)}
h1,h2,h3{margin:0 0 12px}.muted{color:var(--muted);font-size:13px}
.toolbar{display:flex;gap:8px;align-items:center;margin:6px 0 12px;flex-wrap:wrap}
.btn{padding:6px 10px;border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:8px;cursor:pointer}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:16px;margin:16px 0 24px}
.card{border:1px solid var(--bd);border-radius:12px;padding:16px;box-shadow:0 1px 2px rgba(2,6,23,.05);background:var(--card)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
table{border-collapse:collapse;width:100%;font-size:14px}
th,td{border-bottom:1px solid var(--bd);padding:8px 6px;text-align:left}
th{background:rgba(148,163,184,.15);cursor:pointer}
td.right{text-align:right}
.chips>span{display:inline-block;background:rgba(99,102,241,.15);border:1px solid var(--bd);border-radius:999px;padding:4px 10px;margin:2px 6px 2px 0}
footer{margin-top:28px;color:var(--muted);font-size:12px}
canvas{max-height:340px}
.warn{background:rgba(251,146,60,.1);border:1px solid #fed7aa;padding:10px;border-radius:10px}
.code{font-family:ui-monospace, Menlo, Monaco, Consolas, "Liberation Mono","Courier New", monospace; font-size:12px; padding:2px 6px; background:rgba(148,163,184,.15); border-radius:6px}
.toc a{margin-right:10px;font-size:13px}
.mask .revealable{filter: blur(6px)}
@media print {.toolbar{display:none}}
</style></head><body>"""

    header = (
        "<h1>Attack Analytics – Executive + Technical Report</h1>"
        f"<div class='muted'>CAID: <b>{params['caid']}</b> | ช่วงเวลา: <b>{report_range}</b> | สร้างเมื่อ: <b>{generated_at}</b></div>"
        + (f"<div class='muted'>Filters: severity={html_escape(params['severity_filter'])}</div>" if params.get("severity_filter") else "")
    )

    toolbar = """
<div class="toolbar">
  <button class="btn" onclick="document.body.classList.toggle('dark')">🌓 Dark</button>
  <button class="btn" onclick="window.print()">🖨️ Print/PDF</button>
  <button class="btn" onclick="document.body.classList.toggle('mask')">🫣 Privacy</button>
  <button class="btn" onclick="exportAllTables()">⬇️ Export CSV</button>
</div>
<div class="toc muted">
  ไปที่:
  <a href="#kpis">KPIs</a>
  <a href="#tops">Top Lists</a>
  <a href="#waf">WAF Origins</a>
  <a href="#featured">Featured</a>
  <a href="#perhost">Per-Host</a>
  <a href="#insights">Insights</a>
</div>
"""

    sev_items = "".join([f"<span class='chips'>{html_escape(k)}: {v}</span>" for k, v in agg["by_severity"].items()])

    delta_html = ""
    if mom:
        def fmt_delta(x): return f"{'▲' if x>0 else ('▼' if x<0 else '—')} {x:+}"
        delta_html = (
            "<div class='muted'>MoM: "
            f"Incidents {fmt_delta(mom.get('incidents_delta',0))} | "
            f"Block Rate {fmt_delta(mom.get('block_rate_delta',0.0))} pp | "
            f"Hosts {fmt_delta(mom.get('hosts_delta',0))} | "
            f"Attacker IPs {fmt_delta(mom.get('ips_delta',0))}</div>"
        )

    kpis = (
        "<div id='kpis'></div>"
        "<div class='kpis'>"
        f"<div class='card'><div class='muted'>จำนวนเหตุการณ์ทั้งหมด</div><div style='font-size:28px;font-weight:700'>{len(incidents)}</div>{delta_html}</div>"
        f"<div class='card'><div class='muted'>อัตราการบล็อกโดย WAF (รวม)</div><div style='font-size:28px;font-weight:700'>{agg['overall_block_rate']}%</div></div>"
        f"<div class='card'><div class='muted'>Hosts (unique)</div><div style='font-size:28px;font-weight:700'>{len(agg['hosts'])}</div></div>"
        f"<div class='card'><div class='muted'>Attacker IPs (unique)</div><div style='font-size:28px;font-weight:700'>{len(agg['ips'])}</div></div>"
        "</div>"
        + "<div class='card'><h3>สรุปตาม Severity</h3><div class='chips'>" + sev_items + "</div></div>"
    )

    days_sorted = sorted(agg["incident_by_day"].keys())
    day_counts = [agg["incident_by_day"][d] for d in days_sorted]

    # Remap rules to names (if mapping provided)
    rules_display = remap_rules_counter(agg["rules"], rules_map or {}, style=rule_label_style)

    def section_top(title, counter, n=10, canvas_id=None, numeric=False, anchor_id=None):
        labels_vals = counter.most_common(n)
        anchor = f"<div id='{anchor_id}'></div>" if anchor_id else ""
        if not labels_vals:
            return f"{anchor}<div class='card'><h3>{title}</h3><div class='muted'>ไม่มีข้อมูล</div></div>"
        rows = "".join([f"<tr><td>{html_escape(k)}</td><td class='right'>{v}</td></tr>" for k, v in labels_vals])
        chart = f"<canvas id='{canvas_id}'></canvas>" if canvas_id else ""
        th_cls = " class='num'" if numeric else ""
        return f"{anchor}<div class='card'><h3>{title}</h3>{chart}<div style='overflow:auto'><table class='sortable'><thead><tr><th>ค่า</th><th{th_cls}>จำนวน</th></tr></thead><tbody>{rows}</tbody></table></div></div>"

    # Heatmap prep: Day x Hour using first_event_time (proxy)
    import collections
    dow_map = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]  # align with Python weekday()
    heat = collections.Counter()
    for inc in incidents:
        ts = inc.get("first_event_time")
        if isinstance(ts, int):
            dt = ms_to_dt(ts)
            heat[(dow_map[dt.weekday()], dt.hour)] += 1
    heat_points = [{"x": h, "y": d, "v": heat[(d,h)]} for d in dow_map for h in range(24)]

    # Stacked per day (blocked vs alerted)
    days_all = sorted(set(list(agg["blocked_by_day"].keys()) + list(agg["alerted_by_day"].keys())))
    blocked_series = [agg["blocked_by_day"].get(d,0) for d in days_all]
    alerted_series = [agg["alerted_by_day"].get(d,0) for d in days_all]

    grid_top = (
        "<div id='tops'></div>"
        "<div class='grid'>"
        "<div class='card'><h3>แนวโน้ม Incident (รายวัน)</h3><canvas id='chartTimeline'></canvas></div>"
        "<div class='card'><h3>สัดส่วนตาม Severity</h3><canvas id='chartSeverity'></canvas></div>"
        + section_top("Top Countries", agg["geos"], 10, "chartCountries")
        + section_top("Top IPs", agg["ips"], 10, "chartIPs")
        + section_top("Top User-Agents", agg["agents"], 10, "chartAgents")
        + section_top("Top Tools", agg["tools"], 10, "chartTools")
        + section_top("Top Tool Types", agg["tool_types"], 10, "chartToolTypes")
        + section_top("Top Violations (Blocked)", agg["vio_blocked"], 10, "chartVioBlocked", numeric=True)
        + section_top("Top Violations (Alerted)", agg["vio_alerted"], 10, "chartVioAlerted", numeric=True)
        + section_top("Top URLs", agg["urls"], 10, "chartURLs")
        + section_top("Top Hosts", agg["hosts"], 10, "chartHosts")
        + section_top("Top Class-C", agg["classc"], 10, "chartClassC")
        + section_top("Top Rules", rules_display, 10, "chartRules")
        + section_top("Associated CVEs", agg["cves"], 20, "chartCVEs")
        + "<div class='card'><h3>Blocked vs Alerted (รายวัน)</h3><canvas id='chartStacked'></canvas></div>"
        + "<div class='card'><h3>Incident Heatmap (Day × Hour)</h3><canvas id='chartHeat'></canvas></div>"
        + "</div>"
    )

    def table_kv(title, counter, anchor_id=None):
        anchor = f"<div id='{anchor_id}'></div>" if anchor_id else ""
        if not counter: return f"{anchor}<div class='card'><h3>{title}</h3><div class='muted'>ไม่มีข้อมูล</div></div>"
        rows = "".join([f"<tr><td>{html_escape(k)}</td><td class='right'>{v}</td></tr>" for k, v in counter.most_common(50)])
        return f"{anchor}<div class='card'><h3>{title}</h3><div style='overflow:auto'><table class='sortable'><thead><tr><th>Site | Violation</th><th class='num'>Count</th></tr></thead><tbody>{rows}</tbody></table></div></div>"

    waf_sections = ("<div id='waf'></div>" +
                    table_kv("WAF Origins (Alerts)", agg["waf_alerts"]) +
                    table_kv("WAF Origins (Blocks)", agg["waf_blocks"]) +
                    table_kv("WAF Origins (Entities)", agg["waf_entities"]))

    # Featured
    feat_rows = []
    for inc in featured:
        host = html_escape((inc.get('dominant_attacked_host') or {}).get('value',''))
        ip   = html_escape((inc.get('dominant_attack_ip') or {}).get('ip',''))
        feat_rows.append(
            "<tr>"
            f"<td class='code'>{html_escape(inc.get('id',''))}</td>"
            f"<td>{html_escape((inc.get('severity') or '').upper())}</td>"
            f"<td class='revealable'>{host} <button class='btn' onclick=\"navigator.clipboard.writeText('{host}')\">📋</button></td>"
            f"<td>{html_escape(inc.get('dominant_attack_violation',''))}</td>"
            f"<td class='revealable'>{ip} <button class='btn' onclick=\"navigator.clipboard.writeText('{ip}')\">📋</button></td>"
            f"<td class='right'>{inc.get('events_count') or 0}</td>"
            f"<td class='right'>{inc.get('events_blocked_percent') or 0}%</td>"
            f"<td>{html_escape(inc.get('main_sentence',''))}</td>"
            f"<td>{ms_to_local_str(inc.get('first_event_time'))}</td>"
            f"<td>{ms_to_local_str(inc.get('last_event_time'))}</td>"
            "</tr>"
        )
    featured_html = (
        "<div id='featured'></div>"
        "<div class='card'><h2>เหตุการณ์เด่น</h2>"
        "<div class='toolbar'>"
        "  <input id='qFeat' placeholder='ค้นหา (host / rule / ip / summary)' "
        "         style='padding:6px 10px;border:1px solid var(--bd);border-radius:8px;background:var(--card);color:var(--fg);'/>"
        "  <label><input type='checkbox' id='sevCritical' checked> CRITICAL</label>"
        "  <label><input type='checkbox' id='sevMajor' checked> MAJOR</label>"
        "  <label><input type='checkbox' id='sevMinor' checked> MINOR</label>"
        "</div>"
        + ("<div class='muted'>ไม่มีเหตุการณ์เด่นตามเกณฑ์</div>" if not feat_rows else
           "<div class='warn' style='margin:8px 0'>แนะนำ: ทบทวน WAF action, ต้นทาง IP/ASNs, พฤติกรรมสแกน, และ correlation กับ SIEM</div>"
           "<div style='overflow:auto'><table class='sortable'>"
           "<thead><tr><th>ID</th><th>Severity</th><th>Host</th><th>Violation</th><th>Attacker IP</th><th class='num'>Events</th><th class='num'>Blocked%</th><th>Summary</th><th>First</th><th>Last</th></tr></thead>"
           "<tbody>" + "".join(feat_rows) + "</tbody></table></div>")
        + "</div>"
    )

    # Sample events
    sample_html = ""
    if samples_by_id:
        blocks = []
        for iid, events in samples_by_id.items():
            if not events: continue
            rows = []
            for ev in events[:20]:
                rows.append(
                    "<tr>"
                    f"<td class='code'>{html_escape(str(ev.get('event_id')))}</td>"
                    f"<td>{html_escape(ev.get('method',''))}</td>"
                    f"<td class='code'>{html_escape(ev.get('url_path',''))}</td>"
                    f"<td>{html_escape(ev.get('response_code',''))}</td>"
                    f"<td class='code'>{html_escape(ev.get('main_client_ip',''))}</td>"
                    f"<td>{html_escape(ev.get('client_application',''))}</td>"
                    f"<td class='code'>{html_escape(ev.get('referrer',''))}</td>"
                    "</tr>"
                )
            blocks.append(
                "<div class='card'>"
                f"<h3>Sample Events – <span class='code'>{html_escape(iid)}</span></h3>"
                "<div style='overflow:auto'><table class='sortable'><thead>"
                "<tr><th>EventID</th><th>Method</th><th>Path</th><th>Status</th><th>Client IP</th><th>Client App</th><th>Referrer</th></tr>"
                "</thead><tbody>" + "".join(rows) + "</tbody></table></div></div>"
            )
        sample_html = "".join(blocks)

    # Per-host breakdown
    host_blocks = []
    for h, detail in per_host.items():
        urls = detail["urls"].most_common(10)
        vios = detail["violations"].most_common(10)
        tools = detail["tools"].most_common(10)
        ips = detail["ips"].most_common(10)
        def tab(rows, head1, head2):
            if not rows: return "<div class='muted'>ไม่มีข้อมูล</div>"
            rs = "".join([f"<tr><td>{html_escape(k)}</td><td class='right'>{v}</td></tr>" for k,v in rows])
            return f"<table class='sortable'><thead><tr><th>{head1}</th><th class='num'>{head2}</th></tr></thead><tbody>{rs}</tbody></table>"
        host_blocks.append(
            "<div class='card'>"
            f"<h3>Host Breakdown – {html_escape(h)}</h3>"
            "<div class='grid'>"
            f"<div class='card'><h4>Top URLs</h4>{tab(urls,'URL','Count')}</div>"
            f"<div class='card'><h4>Top Violations</h4>{tab(vios,'Violation','Count')}</div>"
            f"<div class='card'><h4>Top Tools</h4>{tab(tools,'Tool','Count')}</div>"
            f"<div class='card'><h4>Top Attacker IPs</h4>{tab(ips,'IP','Count')}</div>"
            "</div></div>"
        )
    per_host_html = "<div id='perhost'></div>" + "".join(host_blocks)

    ins_html = ""
    if insights:
        rows = "".join([
            "<tr>"
            f"<td>{html_escape(x.get('mainSentence',''))}</td>"
            f"<td>{html_escape(x.get('secondarySentence',''))}</td>"
            f"<td>{html_escape(x.get('recommendation',''))}</td>"
            f"<td>{html_escape(x.get('moreInfo',''))}</td>"
            "</tr>" for x in insights
        ])
        ins_html = "<div id='insights'></div><div class='card'><h2>Insights (Recommended Actions)</h2><div style='overflow:auto'><table class='sortable'><thead><tr><th>Main</th><th>Details</th><th>Recommendation</th><th>More</th></tr></thead><tbody>"+rows+"</tbody></table></div></div>"

    footer = "<footer>แหล่งข้อมูล: Imperva Attack Analytics API (incidents, incident stats, insights, sample events)</footer>"

    # ---- JS (charts + sortable tables + CSV export + filters)
    import json as pyjson
    sev_labels = list(agg["by_severity"].keys())
    sev_values = [agg["by_severity"][k] for k in sev_labels]
    js = "<script>\n"
    js += "const days=" + pyjson.dumps(days_sorted, ensure_ascii=False) + ";\n"
    js += "const dayCounts=" + pyjson.dumps(day_counts) + ";\n"
    js += "const sevLabels=" + pyjson.dumps(sev_labels, ensure_ascii=False) + ";\n"
    js += "const sevValues=" + pyjson.dumps(sev_values) + ";\n"
    def top_for(id_prefix, counter, n=10):
        items = counter.most_common(n)
        labels = [k for k, _ in items]
        values = [v for _, v in items]
        return f"const {id_prefix}Labels="+pyjson.dumps(labels, ensure_ascii=False)+";\nconst "+f"{id_prefix}Values="+pyjson.dumps(values)+";\n"
    js += top_for("countries", agg["geos"])
    js += top_for("ips", agg["ips"])
    js += top_for("agents", agg["agents"])
    js += top_for("tools", agg["tools"])
    js += top_for("toolTypes", agg["tool_types"])
    js += top_for("vioBlocked", agg["vio_blocked"])
    js += top_for("vioAlerted", agg["vio_alerted"])
    js += top_for("urls", agg["urls"])
    js += top_for("hosts", agg["hosts"])
    js += top_for("classC", agg["classc"])
    js += top_for("rules", rules_display)
    js += top_for("cves", agg["cves"])
    js += "const stackedDays=" + pyjson.dumps(days_all, ensure_ascii=False) + ";\n"
    js += "const stackedBlocked=" + pyjson.dumps(blocked_series) + ";\n"
    js += "const stackedAlerted=" + pyjson.dumps(alerted_series) + ";\n"
    js += "const heatData=" + pyjson.dumps(heat_points) + ";\n"
    js += r"""
function makeBar(id, labels, data){
  const el = document.getElementById(id); if(!el) return;
  new Chart(el, {
    type: 'bar',
    data: { labels: labels, datasets: [{ label: 'Count', data: data }] },
    options: { responsive: true, plugins:{legend:{display:false}},
      scales:{ y:{ beginAtZero:true, ticks:{ precision:0 } }, x:{ ticks:{ autoSkip:false, maxRotation:60, minRotation:40 } } }
    }
  });
}
function makeLine(id, labels, data){
  const el = document.getElementById(id); if(!el) return;
  new Chart(el, {
    type: 'line',
    data: { labels: labels, datasets: [{ label: 'Incidents', data: data, tension: 0.3 }] },
    options: { responsive: true, plugins:{legend:{display:false}},
      scales:{ y:{ beginAtZero:true, ticks:{ precision:0 } } }
    }
  });
}
makeLine('chartTimeline', days, dayCounts);
makeBar('chartSeverity', sevLabels, sevValues);
makeBar('chartCountries', countriesLabels, countriesValues);
makeBar('chartIPs', ipsLabels, ipsValues);
makeBar('chartAgents', agentsLabels, agentsValues);
makeBar('chartTools', toolsLabels, toolsValues);
makeBar('chartToolTypes', toolTypesLabels, toolTypesValues);
makeBar('chartVioBlocked', vioBlockedLabels, vioBlockedValues);
makeBar('chartVioAlerted', vioAlertedLabels, vioAlertedValues);
makeBar('chartURLs', urlsLabels, urlsValues);
makeBar('chartHosts', hostsLabels, hostsValues);
makeBar('chartClassC', classCLabels, classCValues);
makeBar('chartRules', rulesLabels, rulesValues);
makeBar('chartCVEs', cvesLabels, cvesValues);

// Stacked bar
(function(){
  const el = document.getElementById('chartStacked'); if(!el) return;
  new Chart(el, {
    type: 'bar',
    data: {
      labels: stackedDays,
      datasets: [
        {label:'Blocked', data: stackedBlocked, stack:'stack1'},
        {label:'Alerted', data: stackedAlerted, stack:'stack1'}
      ]
    },
    options: {responsive:true, plugins:{legend:{display:true}},
      scales:{ y:{beginAtZero:true, ticks:{precision:0}}, x:{ticks:{autoSkip:false}}}
    }
  });
})();

// Heatmap Day × Hour
(function(){
  const el = document.getElementById('chartHeat'); if(!el) return;
  new Chart(el, {
    type: 'matrix',
    data: {
      datasets: [{
        label: 'Incidents',
        data: heatData.map(p => ({x: p.x, y: p.y, v: p.v})),
        width: ({chart}) => (chart.chartArea.width / 24) - 2,
        height: ({chart}) => (chart.chartArea.height / 7) - 2,
        backgroundColor: ctx => {
          const v = ctx.dataset.data[ctx.dataIndex].v || 0;
          const a = Math.min(0.9, 0.1 + v / (1 + v));
          return `rgba(99,102,241,${a})`;
        },
        borderColor: 'rgba(0,0,0,0.05)',
        borderWidth: 1,
        parsing: {xAxisKey: 'x', yAxisKey: 'y', vAxisKey: 'v'}
      }]
    },
    options: {
      responsive:true,
      plugins:{legend:{display:false}, tooltip:{callbacks:{label:(ctx)=>` ${ctx.raw.y} @ ${ctx.raw.x}: ${ctx.raw.v}`}}},
      scales:{
        x:{type:'category', labels:[...Array(24).keys()].map(h=>h.toString().padStart(2,'0'))},
        y:{type:'category', labels:['Mon','Tue','Wed','Thu','Fri','Sat','Sun']}
      }
    }
  });
})();

// simple sortable tables
function makeSortable(table){
  const ths = table.tHead ? table.tHead.rows[0].cells : [];
  for (let i=0;i<ths.length;i++){
    const th = ths[i];
    th.addEventListener('click', ()=>{
      const tbody = table.tBodies[0];
      const rows = Array.from(tbody.rows);
      const dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
      th.dataset.dir = dir;
      const numeric = th.classList.contains('num');
      rows.sort((a,b)=>{
        let A = a.cells[i].innerText.trim();
        let B = b.cells[i].innerText.trim();
        if(numeric){ A = parseFloat(A.replace(/[^0-9.-]/g,''))||0; B = parseFloat(B.replace(/[^0-9.-]/g,''))||0; }
        else { A = A.toLowerCase(); B = B.toLowerCase(); }
        return (A>B?1:(A<B?-1:0)) * (dir==='asc'?1:-1);
      });
      rows.forEach(r=>tbody.appendChild(r));
    });
  }
}
document.querySelectorAll('table.sortable').forEach(makeSortable);

// Export CSV (all tables)
function tableToCSV(table){
  const rows = Array.from(table.querySelectorAll('tr'));
  return rows.map(r => Array.from(r.cells).map(td => {
    let t = td.innerText.replaceAll('"','""');
    return `"${t}"`;
  }).join(',')).join('\n');
}
function downloadFile(name, content){
  const blob = new Blob([content], {type:'text/csv;charset=utf-8;'});
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; a.click();
}
function exportAllTables(){
  const tables = document.querySelectorAll('table');
  tables.forEach((t,i)=> downloadFile(`table_${i+1}.csv`, tableToCSV(t)));
}

// Featured filters (search + severity)
(function(){
  const q = document.getElementById('qFeat');
  const c = document.getElementById('sevCritical');
  const m = document.getElementById('sevMajor');
  const n = document.getElementById('sevMinor');
  const tbl = document.querySelector('#featured table tbody');
  if(!tbl || !q) return;
  function apply(){
    const kw = (q.value||'').toLowerCase();
    const show = {CRITICAL:c.checked, MAJOR:m.checked, MINOR:n.checked};
    Array.from(tbl.rows).forEach(r=>{
      const sev = (r.cells[1].innerText||'').trim().toUpperCase();
      const text = r.innerText.toLowerCase();
      const okSev = show[sev] ?? true;
      const okKw = !kw || text.includes(kw);
      r.style.display = (okSev && okKw) ? '' : 'none';
    });
  }
  [q,c,m,n].forEach(el=> el && el.addEventListener('input', apply));
})();
</script>
"""
    return head + header + toolbar + kpis + grid_top + waf_sections + featured_html + sample_html + per_host_html + ins_html + footer + js + "\n</body></html>"

# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser(
        description="Generate Imperva Attack Analytics Executive + Technical HTML Report (detailed)",
        formatter_class=RawTextHelpFormatter,
        epilog="""\
Examples:
  1) รายงาน 2 วันล่าสุด
     python3 aa_exec_report.py --api-id $API_ID --api-key $API_KEY --caid 12345678 \\
       --from "2025-08-22" --to "2025-08-23" --out report.html

  2) รายเดือน + กรอง Severity + บันทึก JSON + เทียบเดือนก่อน (MoM)
     python3 aa_exec_report.py --api-id $API_ID --api-key $API_KEY --caid 12345678 \\
       --from "2025-08-01" --to "2025-08-31" --severity-filter "CRITICAL,MAJOR" \\
       --export-json aa_export_2025-08.json --prev-export aa_export_2025-07.json \\
       --out attack_analytics_report.html

  3) ดึงเป็นช่วงย่อย (chunk) + ตัวอย่างอีเวนต์ + แสดงชื่อกฎจากไฟล์แม็พ
     python3 aa_exec_report.py --api-id $API_ID --api-key $API_KEY --caid 12345678 \\
       --from "2025-08-01" --to "2025-08-31" --chunk-days 2 --include-sample 5 \\
       --rules-map ./rules_map.json --rule-label name_id --out report.html

Notes:
  - base URL ปกติคือ https://api.imperva.com/analytics (ปรับได้ด้วย --base-url)
  - ใส่ --debug เพื่อดู URL/params (ซ่อน API Key ให้อัตโนมัติ)
"""
    )

    ap.add_argument("-v", "--version", action="version", version="aa_exec_report 1.1")

    # ====== อาร์กิวเมนต์หลัก ======
    ap.add_argument("--api-id", required=True, help="Imperva API ID")
    ap.add_argument("--api-key", required=True, help="Imperva API Key")
    ap.add_argument("--caid", type=int, required=True, help="Customer Account ID (CAID)")
    ap.add_argument("--from", dest="from_date", required=True, help="วันที่เริ่ม (เช่น 2025-08-01)")
    ap.add_argument("--to", dest="to_date", required=True, help="วันที่สิ้นสุด (เช่น 2025-08-31)")
    ap.add_argument("--out", default="attack_analytics_report.html", help="ไฟล์รายงาน HTML (ดีฟอลต์: attack_analytics_report.html)")

    # ====== เครือข่าย/ดีบั๊ก ======
    ap.add_argument("--base-url", default="https://api.imperva.com/analytics",
                    help="เปลี่ยน API base ถ้าจำเป็น (เช่น https://api.imperva.com/attack-analytics หรือโฮสต์ EU)")
    ap.add_argument("--debug", action="store_true", help="พิมพ์ URL/Headers/Params (ซ่อน API Key)")

    # ====== ประสิทธิภาพ ======
    ap.add_argument("--concurrency", type=int, default=10, help="จำนวนงานขนานระหว่างดึง stats (ดีฟอลต์ 10)")
    ap.add_argument("--max-incidents", type=int, default=300, help="จำกัดจำนวน incident สูงสุดเพื่อเรนเดอร์ (ดีฟอลต์ 300)")
    ap.add_argument("--timeout", type=int, default=40, help="timeout ต่อคำขอ (วินาที)")
    ap.add_argument("--retries", type=int, default=3, help="จำนวนครั้ง retry เมื่อเจอข้อผิดพลาดชั่วคราว")
    ap.add_argument("--chunk-days", type=int, default=0, help="ดึง incidents แบบแบ่งช่วง N วัน (0 = ดึงครั้งเดียว)")

    # ====== ตัวกรอง ======
    ap.add_argument("--severity-filter", default="", help="ตัวกรอง Severity (คั่นด้วย comma เช่น CRITICAL,MAJOR)")
    ap.add_argument("--host-filter", default="", help="ตัวกรอง Hostname แบบ exact (คั่นด้วย comma)")
    ap.add_argument("--violation-filter", default="", help="ตัวกรองชื่อ Violation (คั่นด้วย comma)")
    ap.add_argument("--country-filter", default="", help="ตัวกรองประเทศ/โค้ดประเทศ (คั่นด้วย comma)")
    ap.add_argument("--min-events", type=int, default=0, help="ตัด incident ที่ events_count < N")

    # ====== รายละเอียดในรายงาน ======
    ap.add_argument("--host-breakdown", type=int, default=5, help="จำนวน top hosts ในส่วน breakdown ต่อ host")
    ap.add_argument("--include-sample", type=int, default=0, help="ดึง sample-events ของ incident เด่น N รายการแรก")

    # ====== ส่งออก/เปรียบเทียบ ======
    ap.add_argument("--export-json", default="", help="บันทึกสรุปรวมเป็นไฟล์ JSON")
    ap.add_argument("--prev-export", default="", help="ไฟล์ JSON ของเดือนก่อนเพื่อคำนวณ MoM delta")

    # ====== ชื่อกฎ (Rules Mapping) ======
    ap.add_argument("--rules-map", default="", help="ไฟล์แม็พ rule id→name (.json หรือ .csv ที่มีคอลัมน์ id,name)")
    ap.add_argument("--rule-label", default="name_id", choices=["name", "name_id"],
                    help="รูปแบบป้ายชื่อกฎในรายงาน: name | name_id (ดีฟอลต์ name_id)")

    # ====== PDF & Slack ======
    ap.add_argument("--pdf-out", default="", help="Export HTML to PDF (requires Chrome/Chromium or wkhtmltopdf)")
    ap.add_argument("--slack-webhook", default="", help="Slack Incoming Webhook URL (ส่งสรุปรายงาน)")
    ap.add_argument("--slack-mention", default="", help="ข้อความ mention เช่น @soc-team")

    # ====== Config preload ======
    ap.add_argument("--config", default="", help="YAML config file to pre-fill CLI args")

    # preload config (if any)
    if len(sys.argv) == 1:
        ap.print_help()
        sys.exit(0)
    partial = ap.parse_known_args()[0]
    if partial.config:
        try:
            import yaml
            with open(partial.config, "r", encoding="utf-8") as f:
                conf = yaml.safe_load(f) or {}
            # inject defaults (still overridable by explicit CLI later)
            inject = []
            for k, v in conf.items():
                k2 = f"--{k.replace('_','-')}"
                if isinstance(v, bool):
                    if v: inject += [k2]
                else:
                    inject += [k2, str(v)]
            # place after program name
            sys.argv[1:1] = inject
        except Exception as e:
            print(f"[WARN] failed to read config: {e}")

    args = ap.parse_args()

    BASE_URL = args.base_url.rstrip("/")
    headers = {
        "x-API-Id": args.api_id,
        "x-API-Key": args.api_key,
        "X-API-Id": args.api_id,
        "X-API-Key": args.api_key,
    }
    from_ms = parse_date_to_ms(args.from_date)
    to_ms   = end_of_day_ms(args.to_date)
    session = create_session(args.timeout, args.retries)

    rules_map = load_rules_map(args.rules_map)

    # 1) incidents
    t0 = time.time()
    print("🔎 Fetching incidents ...")
    if args.chunk_days and args.chunk_days > 0:
        incidents = fetch_incidents_chunked(session, BASE_URL, headers, args.caid, from_ms, to_ms, step_days=args.chunk_days, debug=args.debug)
    else:
        incidents = fetch_incidents(session, BASE_URL, headers, args.caid, from_ms, to_ms, debug=args.debug)
    if not isinstance(incidents, list):
        print("Unexpected incidents response:", incidents, file=sys.stderr)
        incidents = []
    print(f"✅ Incidents fetched: {len(incidents)} in {round(time.time()-t0,1)}s")

    # 1.1 apply filters
    sev_filter = set(s.strip().upper() for s in args.severity_filter.split(",") if s.strip())
    host_filter = set(s.strip().lower() for s in args.host_filter.split(",") if s.strip())
    vio_filter  = set(s.strip().lower() for s in args.violation_filter.split(",") if s.strip())
    ctry_filter = set(s.strip().lower() for s in args.country_filter.split(",") if s.strip())
    if args.min_events > 0:
        incidents = [i for i in incidents if (i.get("events_count") or 0) >= args.min_events]
    if sev_filter:
        incidents = [i for i in incidents if ((i.get("severity") or "").upper() in sev_filter)]
        print(f"🎯 After severity filter {sev_filter}: {len(incidents)} incidents")
    if host_filter:
        incidents = [i for i in incidents if ((i.get("dominant_attacked_host") or {}).get("value","").lower() in host_filter)]
    if vio_filter:
        incidents = [i for i in incidents if (i.get("dominant_attack_violation","").lower() in vio_filter)]
    if ctry_filter:
        def inc_country(i):
            c = (i.get("dominant_attack_country") or {})
            return (c.get("country") or c.get("country_code") or "").lower()
        incidents = [i for i in incidents if inc_country(i) in ctry_filter]

    if len(incidents) > args.max_incidents:
        print(f"⚠️ Limiting to first {args.max_incidents} incidents (use --max-incidents to change)")
        incidents = incidents[:args.max_incidents]

    # 2) stats (parallel)
    print("📦 Fetching incident stats ...")
    t1 = time.time()
    stats_list = []
    futs = []
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        for inc in incidents:
            iid = inc.get("id")
            if not iid: continue
            futs.append(ex.submit(http_get, session, BASE_URL, f"/v1/incidents/{iid}/stats", headers, {"caid": args.caid}, args.debug))
        done = 0
        for fut in as_completed(futs):
            try:
                st = fut.result()
                if isinstance(st, dict): stats_list.append(st)
            except Exception as e:
                print(f"  [WARN] stats failed: {e}")
            done += 1
            pct = int(done*100/len(futs))
            if done % max(1, len(futs)//20) == 0 or done == len(futs):
                print(f"   ↳ progress: {done}/{len(futs)} ({pct}%)")
    print(f"✅ Stats fetched: {len(stats_list)} in {round(time.time()-t1,1)}s")

    # 3) insights
    print("💡 Fetching insights ...")
    t2 = time.time()
    insights = []
    try:
        resp = http_get(session, BASE_URL, "/v1/insights", headers, params={"caid": args.caid}, debug=args.debug)
        if isinstance(resp, dict):
            for ins in resp.get("insights", []):
                insights.append({
                    "mainSentence": ins.get("mainSentence"),
                    "secondarySentence": ins.get("secondarySentence"),
                    "recommendation": ins.get("recommendation"),
                    "moreInfo": ins.get("moreInfo"),
                })
    except Exception as e:
        print(f"  [WARN] insights failed: {e}")
    print(f"✅ Insights fetched: {len(insights)} in {round(time.time()-t2,1)}s")

    # 4) aggregate
    print("🧮 Aggregating ...")
    agg = aggregate_global(incidents, stats_list)
    per_host = aggregate_per_host(stats_list, top_n_hosts=args.host_breakdown)

    # featured incidents
    featured = sorted(incidents, key=lambda x: (
        0 if (x.get("severity") or "").upper() == "CRITICAL" else (1 if (x.get("severity") or "").upper() == "MAJOR" else 2),
        -(x.get("events_count") or 0)
    ))[:min(50, len(incidents))]

    # 5) optional sample events
    samples_by_id = {}
    include_n = args.include_sample
    if include_n and featured:
        print(f"🧪 Fetching sample-events for first {min(include_n, len(featured))} featured incidents ...")
        t3 = time.time()
        samples_futs = []
        with ThreadPoolExecutor(max_workers=max(1, min(6, include_n))) as ex:
            for inc in featured[:include_n]:
                iid = inc.get("id")
                if not iid: continue
                samples_futs.append((iid, ex.submit(http_get, session, BASE_URL, f"/v1/incidents/{iid}/sample-events", headers, {"caid": args.caid}, args.debug)))
            for iid, fut in samples_futs:
                try:
                    ev = fut.result()
                    if isinstance(ev, dict): samples_by_id[iid] = [ev]
                    elif isinstance(ev, list): samples_by_id[iid] = ev
                    else: samples_by_id[iid] = []
                except Exception as e:
                    print(f"  [WARN] sample-events failed for {iid}: {e}")
                    samples_by_id[iid] = []
        print(f"✅ Sample-events done in {round(time.time()-t3,1)}s")

    # 6) export json
    if args.export_json:
        export_obj = {
            "range": {"from_ms": from_ms, "to_ms": to_ms},
            "severity_filter": args.severity_filter,
            "kpis": {
                "incident_total": len(incidents),
                "overall_block_rate": agg["overall_block_rate"],
                "hosts_unique": len(agg["hosts"]),
                "ips_unique": len(agg["ips"]),
            },
            "tops": {
                "countries": agg["geos"].most_common(50),
                "ips": agg["ips"].most_common(50),
                "agents": agg["agents"].most_common(50),
                "tools": agg["tools"].most_common(50),
                "tool_types": agg["tool_types"].most_common(50),
                "urls": agg["urls"].most_common(50),
                "hosts": agg["hosts"].most_common(50),
                "classC": agg["classc"].most_common(50),
                "rules": agg["rules"].most_common(50),
                "vio_blocked": agg["vio_blocked"].most_common(50),
                "vio_alerted": agg["vio_alerted"].most_common(50),
                "cves": agg["cves"].most_common(100),
            },
            "featured_incidents": [
                {
                    "id": i.get("id"), "severity": i.get("severity"),
                    "host": (i.get("dominant_attacked_host") or {}).get("value"),
                    "violation": i.get("dominant_attack_violation"),
                    "ip": (i.get("dominant_attack_ip") or {}).get("ip"),
                    "events_count": i.get("events_count"),
                    "blocked_percent": i.get("events_blocked_percent"),
                    "first_event_time": i.get("first_event_time"),
                    "last_event_time": i.get("last_event_time"),
                    "main_sentence": i.get("main_sentence")
                } for i in featured
            ]
        }
        with open(args.export_json, "w", encoding="utf-8") as f:
            json.dump(export_obj, f, ensure_ascii=False, indent=2)
        print(f"💾 Exported JSON -> {args.export_json}")

    # 6.1 MoM delta if prev-export provided
    mom = None
    if args.prev_export and os.path.exists(args.prev_export):
        try:
            with open(args.prev_export, "r", encoding="utf-8") as f:
                prev = json.load(f)
            mom = {
                "incidents_delta": len(incidents) - int(prev.get("kpis", {}).get("incident_total", 0)),
                "block_rate_delta": round(agg["overall_block_rate"] - float(prev.get("kpis", {}).get("overall_block_rate", 0.0)), 2),
                "hosts_delta": len(agg["hosts"]) - int(prev.get("kpis", {}).get("hosts_unique", 0)),
                "ips_delta": len(agg["ips"]) - int(prev.get("kpis", {}).get("ips_unique", 0)),
            }
        except Exception as e:
            print(f"  [WARN] failed to read prev-export: {e}")

    # 7) render HTML
    print("🖨️ Rendering HTML ...")
    html = render_html(
        params={"caid": args.caid, "from_ms": from_ms, "to_ms": to_ms, "severity_filter": args.severity_filter},
        agg=agg, per_host=per_host, incidents=incidents, featured=featured,
        samples_by_id=samples_by_id, insights=insights, mom=mom,
        rules_map=rules_map, rule_label_style=args.rule_label
    )
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"🎉 Done -> {args.out}")

    # 8) optional PDF export
    if args.pdf_out:
        pdf_ok = False
        chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
        if chrome:
            try:
                subprocess.check_call([chrome, "--headless", "--disable-gpu",
                                       f"--print-to-pdf={args.pdf_out}", os.path.abspath(args.out)])
                print(f"🧾 PDF exported via Chrome -> {args.pdf_out}")
                pdf_ok = True
            except Exception as e:
                print(f"[WARN] Chrome PDF failed: {e}")
        if not pdf_ok and shutil.which("wkhtmltopdf"):
            try:
                subprocess.check_call(["wkhtmltopdf", os.path.abspath(args.out), args.pdf_out])
                print(f"🧾 PDF exported via wkhtmltopdf -> {args.pdf_out}")
                pdf_ok = True
            except Exception as e:
                print(f"[WARN] wkhtmltopdf failed: {e}")
        if not pdf_ok:
            print("[WARN] No PDF engine found. Install Chrome/Chromium or wkhtmltopdf, or open HTML and print to PDF.")

    # 9) optional Slack notify
    if args.slack_webhook:
        try:
            files = [os.path.abspath(args.out)]
            if args.pdf_out and os.path.exists(args.pdf_out):
                files.append(os.path.abspath(args.pdf_out))
            text = (
                f"Attack Analytics report ready for CAID {args.caid}\n"
                f"Range: {ms_to_local_str(from_ms)} – {ms_to_local_str(to_ms)}\n"
                f"Incidents: {len(incidents)} | Block rate: {agg['overall_block_rate']}%\n"
            )
            if args.slack_mention:
                text = f"{args.slack_mention} {text}"
            requests.post(args.slack_webhook, json={"text": text + "\n" + "\n".join(files)}, timeout=10)
            print("📣 Slack notified.")
        except Exception as e:
            print(f"[WARN] Slack notify failed: {e}")

if __name__ == "__main__":
    main()
