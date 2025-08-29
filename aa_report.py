#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Imperva Cloud WAF - Attack Analytics HTML Report

- ใช้ข้อมูลจาก API เท่านั้น (events_count, dominant_* ฯลฯ)
- Threat Activities แบบ stacked bar (hour/day) ตามช่วงเวลา incident active
- Top N: Signatures, Countries, IPs, Hosts, Tools (name+type) โดยดึงจาก events_count
- ค่าว่าง/ไม่มีค่า => "Other" และแสดงบรรทัดล่างสุดเสมอ
- Breakdown รายเว็บไซต์ (--breakdown-hosts) เป็นการ์ดย่อ/ขยาย + โดนัท
- UI: Dark/Light toggle, ปรับฟอนต์, sort/filter/export ตาราง (CSV/JSON)
- TLS/Proxy/Retry: --use-certifi/--ca-bundle/--insecure/--https-proxy
"""

import argparse
import concurrent.futures as cf
import datetime as dt
import html
import json
import os
import re
import ssl
import sys
import urllib.parse
import urllib.request
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple, Optional

try:
    from zoneinfo import ZoneInfo  # py3.9+
except Exception:
    ZoneInfo = None

API_HOST = "api.imperva.com"
BASE_PATH = "/analytics"
INCIDENTS_PATH = "/v1/incidents"
STATS_PATH_TMPL = "/v1/incidents/{incidentId}/stats"


# ---------------- HTTP/SSL ----------------
def build_ssl_context(ca_bundle: Optional[str], use_certifi: bool, insecure: bool) -> ssl.SSLContext:
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    if ca_bundle:
        return ssl.create_default_context(cafile=ca_bundle)
    if use_certifi:
        try:
            import certifi  # type: ignore
            return ssl.create_default_context(cafile=certifi.where())
        except Exception:
            pass
    return ssl.create_default_context()


def build_opener(https_proxy: Optional[str], context: Optional[ssl.SSLContext]):
    handlers = []
    proxies = {}
    if https_proxy:
        proxies["https"] = https_proxy
    else:
        envp = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        if envp:
            proxies["https"] = envp
    if proxies:
        handlers.append(urllib.request.ProxyHandler(proxies))
    handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def http_get(url: str, headers: Dict[str, str], timeout: int,
             context: Optional[ssl.SSLContext], opener,
             max_retries: int = 2, backoff: float = 0.5) -> Any:
    last_err = None
    for i in range(max_retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with opener.open(req, timeout=timeout) as resp:
                charset = resp.headers.get_content_charset() or "utf-8"
                data = resp.read().decode(charset, errors="replace")
                if resp.status != 200:
                    raise RuntimeError(f"GET {url} -> HTTP {resp.status}: {data[:200]}")
                return json.loads(data)
        except Exception as e:
            last_err = e
            if i < max_retries:
                import time
                time.sleep(backoff * (2 ** i))
    raise RuntimeError(f"HTTP GET failed after {max_retries+1} attempts: {last_err}")


def build_url(path: str, params: Dict[str, Any]) -> str:
    q = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    return f"https://{API_HOST}{BASE_PATH}{path}?{q}" if q else f"https://{API_HOST}{BASE_PATH}{path}"


def default_headers(api_id: str, api_key: str) -> Dict[str, str]:
    return {
        "Accept": "application/json",
        "x-API-Id": api_id,
        "x-API-Key": api_key,
        "User-Agent": "AA-Report/3.4",
    }


# ---------------- Models ----------------
@dataclass
class Incident:
    id: str
    severity: str
    first_event_time: int
    last_event_time: int
    dominant_attack_violation: Optional[str]
    dominant_attacked_host: Optional[str]
    dominant_attack_country: Optional[str]
    dominant_attack_tool_name: Optional[str]
    dominant_attack_tool_types: List[str]


@dataclass
class IncidentStats:
    id: str
    events_count: int
    violations_blocked: List[Dict[str, int]]
    violations_alerted: List[Dict[str, int]]
    attack_ips: List[Dict[str, Any]]
    attack_tools: List[Dict[str, Any]]
    attacked_hosts: List[Dict[str, Any]]


# ---------------- Utils ----------------
def kv_fix(x: Dict[str, Any]) -> Dict[str, int]:
    if x is None:
        return {"key": "Other", "value": 0}
    key = x.get("key", "Other")
    val = x.get("value", x.get("count", 0))
    try:
        val = int(val)
    except Exception:
        val = 0
    return {"key": "Other" if not key else key, "value": val}


def normalize_severity(s: Any) -> str:
    s = str(s or "").strip().upper()
    return s if s else "Other"


def safe_other(v: Any) -> Optional[str]:
    if v is None:
        return "Other"
    s = str(v).strip()
    return s if s else "Other"


def to_int_or_zero(v: Any) -> int:
    try:
        return int(v)
    except Exception:
        try:
            return int(float(v))
        except Exception:
            return 0


def parse_date_yyyymmdd(s: str) -> dt.date:
    return dt.datetime.strptime(s, "%Y-%m-%d").date()


def range_bounds(start_date: dt.date, end_date: dt.date, tz: Optional[str]) -> Tuple[int, int, str]:
    if tz and ZoneInfo:
        z = ZoneInfo(tz)
        start = dt.datetime.combine(start_date, dt.time.min).replace(tzinfo=z)
        end = dt.datetime.combine(end_date, dt.time.max).replace(tzinfo=z)
    else:
        start = dt.datetime.combine(start_date, dt.time.min)
        end = dt.datetime.combine(end_date, dt.time.max)
    return int(start.timestamp() * 1000), int(end.timestamp() * 1000), (tz or "UTC")


def epochms_to_human(ms: int, tz: Optional[str]) -> str:
    if ms <= 0:
        return "-"
    if tz and ZoneInfo:
        z = ZoneInfo(tz)
        return dt.datetime.fromtimestamp(ms / 1000, tz=z).strftime("%Y-%m-%d %H:%M:%S %Z")
    return dt.datetime.utcfromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M:%S UTC")


def bucketize(from_ms: int, to_ms: int, tz: Optional[str], granularity: str) -> List[Tuple[int, str, int]]:
    if tz and ZoneInfo:
        z = ZoneInfo(tz)
        cur = dt.datetime.fromtimestamp(from_ms / 1000, tz=z)
        end_dt = dt.datetime.fromtimestamp(to_ms / 1000, tz=z)
    else:
        cur = dt.datetime.utcfromtimestamp(from_ms / 1000)
        end_dt = dt.datetime.utcfromtimestamp(to_ms / 1000)

    if granularity == "day":
        cur = cur.replace(hour=0, minute=0, second=0, microsecond=0)
        step = dt.timedelta(days=1)
        fmt = "%m-%d"
    else:
        cur = cur.replace(minute=0, second=0, microsecond=0)
        step = dt.timedelta(hours=1)
        fmt = "%m-%d %H:00" if (end_dt - cur).days >= 1 else "%H:00"

    out = []
    while cur <= end_dt:
        s_ms = int(cur.timestamp() * 1000)
        e_ms = int((cur + step - dt.timedelta(milliseconds=1)).timestamp() * 1000)
        out.append((s_ms, cur.strftime(fmt), e_ms))
        cur += step
    return out


def build_stacks(incidents: List[Incident], stats_map: Dict[str, "IncidentStats"],
                 from_ms: int, to_ms: int, tz: str, granularity: str):
    cats = ["CRITICAL", "MAJOR", "MINOR", "CUSTOM", "Other"]
    buckets = bucketize(from_ms, to_ms, tz, granularity)
    mat = [{c: 0 for c in cats} for _ in buckets]

    for inc in incidents:
        st = stats_map.get(inc.id)
        events = st.events_count if st else 0
        if events <= 0:
            continue
        idxs = []
        for i, (b_start, _lbl, b_end) in enumerate(buckets):
            if inc.first_event_time <= b_end and inc.last_event_time >= b_start:
                idxs.append(i)
        if not idxs:
            continue
        base, rem = events // len(idxs), events % len(idxs)
        sev = inc.severity if inc.severity in cats else "Other"
        for j, i in enumerate(idxs):
            mat[i][sev] += base + (1 if j < rem else 0)

    labels = [lbl for _, lbl, _ in buckets]
    series = {c: [row[c] for row in mat] for c in cats}
    earliest = min((x.first_event_time for x in incidents), default=0)
    latest = max((x.last_event_time for x in incidents), default=0)
    return labels, series, earliest, latest


# ---------------- Fetchers ----------------
def fetch_incidents(headers: Dict[str, str], caid: int, ts_from: int, ts_to: int,
                    context: ssl.SSLContext, opener, timeout: int, retries: int, backoff: float) -> List[Incident]:
    url = build_url(INCIDENTS_PATH, {"caid": caid, "from_timestamp": ts_from, "to_timestamp": ts_to})
    raw = http_get(url, headers, timeout, context, opener, retries, backoff)
    out: List[Incident] = []
    for it in raw or []:
        tool = it.get("dominant_attack_tool") or {}
        host_val = (it.get("dominant_attacked_host") or {}).get("value") if isinstance(it.get("dominant_attacked_host"), dict) else None
        country = (it.get("dominant_attack_country") or {}).get("country") if isinstance(it.get("dominant_attack_country"), dict) else None
        tname = tool.get("name")
        ttype = tool.get("type")
        types: List[str] = []
        if isinstance(ttype, list):
            types = [str(x).strip() for x in ttype if str(x).strip()]
        elif ttype is not None:
            s = str(ttype).strip()
            if s:
                types = [s]
        out.append(Incident(
            id=str(it.get("id", "")),
            severity=normalize_severity(it.get("severity")),
            first_event_time=int(it.get("first_event_time") or 0),
            last_event_time=int(it.get("last_event_time") or 0),
            dominant_attack_violation=safe_other(it.get("dominant_attack_violation")),
            dominant_attacked_host=safe_other(host_val),
            dominant_attack_country=safe_other(country),
            dominant_attack_tool_name=safe_other(tname),
            dominant_attack_tool_types=types,
        ))
    return out


def fetch_incident_stats(headers: Dict[str, str], caid: int, incident_id: str,
                         context: ssl.SSLContext, opener, timeout: int, retries: int, backoff: float) -> IncidentStats:
    path = STATS_PATH_TMPL.format(incidentId=urllib.parse.quote(incident_id))
    url = build_url(path, {"caid": caid})
    r = http_get(url, headers, timeout, context, opener, retries, backoff)
    return IncidentStats(
        id=str(r.get("id", "")),
        events_count=int(r.get("events_count") or 0),
        violations_blocked=[kv_fix(x) for x in (r.get("violations_blocked") or [])],
        violations_alerted=[kv_fix(x) for x in (r.get("violations_alerted") or [])],
        attack_ips=[x for x in (r.get("attack_ips") or [])],
        attack_tools=[x for x in (r.get("attack_tools") or [])],
        attacked_hosts=[x for x in (r.get("attacked_hosts") or [])],
    )


# ---------------- Aggregation ----------------
def top_with_other(sum_dict: Dict[str, int], top_n: int = 10) -> List[Tuple[str, int]]:
    d = dict(sum_dict)
    other = d.pop("Other", 0)
    items = sorted(d.items(), key=lambda kv: kv[1], reverse=True)
    if other > 0:
        return items[:max(0, top_n - 1)] + [("Other", other)]
    return items[:top_n]


def top_tools_with_other(sum_dict: Dict[str, int], type_map: Dict[str, set], top_n: int = 10) -> List[Tuple[str, int]]:
    d = dict(sum_dict)
    other = d.pop("Other", 0)
    items = sorted(d.items(), key=lambda kv: kv[1], reverse=True)
    out = []
    keep = max(0, top_n - (1 if other > 0 else 0))
    for name, val in items[:keep]:
        types = sorted([t for t in type_map.get(name, set()) if t])
        suffix = "".join(f"({t})" for t in types)
        out.append((f"{name}{suffix}" if suffix else name, val))
    if other > 0:
        out.append(("Other", other))
    return out


def aggregate(incidents: List[Incident], stats_map: Dict[str, IncidentStats], top_n: int,
              mask_ips: bool, mask_cidr: Optional[int]):
    threat_events = 0
    block_events = 0
    high_sec = 0
    sig_sum = defaultdict(int)
    ctry_sum = defaultdict(int)
    host_sum = defaultdict(int)
    tool_sum = defaultdict(int)
    tool_types: Dict[str, set] = defaultdict(set)

    for inc in incidents:
        st = stats_map.get(inc.id)
        ev = st.events_count if st else 0
        if st:
            threat_events += st.events_count
            block_events += sum((kv.get("value", 0) for kv in st.violations_blocked))
        if inc.severity in ("CRITICAL", "MAJOR"):
            high_sec += 1
        sig_sum[safe_other(inc.dominant_attack_violation)] += ev
        ctry_sum[safe_other(inc.dominant_attack_country)] += ev
        host_sum[safe_other(inc.dominant_attacked_host)] += ev
        tname = safe_other(inc.dominant_attack_tool_name)
        tool_sum[tname] += ev
        for t in inc.dominant_attack_tool_types:
            t = str(t).strip()
            if t:
                tool_types[tname].add(t)

    def mask_ip(ip: str, cidr: Optional[int]) -> str:
        if not ip or ip == "Other":
            return ip or "Other"
        m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
        if not m:
            return ip
        a, b, c, d = [int(x) for x in m.groups()]
        for part in (a, b, c, d):
            if part < 0 or part > 255:
                return ip
        if not cidr:
            return f"{a}.{b}.{c}.x"
        if cidr <= 8:
            return f"{a}.x.x.x"
        if cidr <= 16:
            return f"{a}.{b}.x.x"
        return f"{a}.{b}.{c}.x"

    ip_sum = defaultdict(int)
    for st in stats_map.values():
        for rec in st.attack_ips:
            key = rec.get("key")
            ip = "Other"
            if isinstance(key, dict):
                ip = safe_other(key.get("ip"))
            else:
                ip = safe_other(key)
            val = rec.get("value")
            if val is None:
                val = rec.get("count", 0)
            lbl = mask_ip(ip, mask_cidr) if (mask_ips and ip != "Other") else ip
            ip_sum[lbl] += to_int_or_zero(val)

    return {
        "threat_events": threat_events,
        "block_events": block_events,
        "high_security_incidents": high_sec,
        "sig_top": top_with_other(sig_sum, top_n),
        "country_top": top_with_other(ctry_sum, top_n),
        "host_top": top_with_other(host_sum, top_n),
        "tool_top": top_tools_with_other(tool_sum, tool_types, top_n),
        "ip_top": top_with_other(ip_sum, top_n),
    }


def per_host_breakdowns(incidents: List[Incident], stats_map: Dict[str, IncidentStats],
                        selected_hosts: List[str], top_n: int, mask_ips: bool, mask_cidr: Optional[int]):
    results = []

    def mask_ip(ip: str, cidr: Optional[int]) -> str:
        if not ip or ip == "Other":
            return ip or "Other"
        m = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", ip)
        if not m:
            return ip
        a, b, c, d = [int(x) for x in m.groups()]
        for part in (a, b, c, d):
            if part < 0 or part > 255:
                return ip
        if not cidr:
            return f"{a}.x.x.x"
        if cidr <= 8:
            return f"{a}.x.x.x"
        if cidr <= 16:
            return f"{a}.{b}.x.x"
        return f"{a}.{b}.{c}.x"

    for host in sorted(set(selected_hosts)):
        sig = defaultdict(int)
        ctry = defaultdict(int)
        tool = defaultdict(int)
        tool_types: Dict[str, set] = defaultdict(set)
        ip = defaultdict(int)
        total = 0
        earliest = 0
        latest = 0

        for inc in incidents:
            if safe_other(inc.dominant_attacked_host) != host:
                continue
            earliest = inc.first_event_time if earliest == 0 else min(earliest, inc.first_event_time)
            latest = max(latest, inc.last_event_time)
            st = stats_map.get(inc.id)
            ev = st.events_count if st else 0
            total += ev
            sig[safe_other(inc.dominant_attack_violation)] += ev
            ctry[safe_other(inc.dominant_attack_country)] += ev
            tname = safe_other(inc.dominant_attack_tool_name)
            tool[tname] += ev
            for t in inc.dominant_attack_tool_types:
                t = str(t).strip()
                if t:
                    tool_types[tname].add(t)
            if st:
                for rec in st.attack_ips:
                    key = rec.get("key")
                    ipaddr = "Other"
                    if isinstance(key, dict):
                        ipaddr = safe_other(key.get("ip"))
                    else:
                        ipaddr = safe_other(key)
                    val = rec.get("value")
                    if val is None:
                        val = rec.get("count", 0)
                    lbl = mask_ip(ipaddr, mask_cidr) if (mask_ips and ipaddr != "Other") else ipaddr
                    ip[lbl] += to_int_or_zero(val)

        if total == 0 and not (sig or ctry or tool or ip):
            continue
        results.append({
            "host": host, "events": total, "earliest": earliest, "latest": latest,
            "sig_top": top_with_other(sig, top_n),
            "country_top": top_with_other(ctry, top_n),
            "ip_top": top_with_other(ip, top_n),
            "tool_top": top_tools_with_other(tool, tool_types, top_n),
        })
    return results


# ---------------- HTML helpers ----------------
def html_escape(s: Any) -> str:
    return html.escape(str(s))


def as_table_rows(pairs: List[Tuple[str, int]], table_id: str) -> str:
    total = sum(v for _, v in pairs) or 1
    rows = pairs or [("Other", 0)]
    out = []
    for i, (label, val) in enumerate(rows, 1):
        pct = (val * 100.0) / total if total > 0 else 0.0
        out.append(f"""
        <tr>
          <td class="rank">{i}</td>
          <td class="label">{html_escape(label)}</td>
          <td class="value" data-sort="{val}">{val:,}</td>
          <td class="pct" data-sort="{pct:.6f}">
            <div class="pct-wrap"><span class="pct-bar" style="width:{pct:.1f}%"></span><span class="pct-text">{pct:.1f}%</span></div>
          </td>
        </tr>""")
    data_json = json.dumps([{"label": l, "value": int(v)} for (l, v) in rows], ensure_ascii=False)
    out.append(f'<script id="data-{table_id}" type="application/json">{html_escape(data_json)}</script>')
    return "\n".join(out)


# ---------------- HTML render ----------------
def render_html(date_str: str, end_date_str: str, tz: str, bounds: Tuple[int, int, str],
                incidents: List[Incident], agg: Dict[str, Any], host_bds: List[Dict[str, Any]],
                hourly_labels: List[str], hourly_series: Dict[str, List[int]],
                earliest: int, latest: int, initial_theme: str, granularity: str,
                partial_fail_count: int) -> str:

    from_ms, to_ms, _ = bounds

    # chart data
    colors = {"CRITICAL": "#D55E00", "MAJOR": "#E69F00", "MINOR": "#56B4E9", "CUSTOM": "#009E73", "Other": "#999999"}
    datasets = [{"label": k, "data": hourly_series.get(k, []), "backgroundColor": colors.get(k, "#999999"), "stack": "incidents"}
                for k in ["CRITICAL", "MAJOR", "MINOR", "CUSTOM", "Other"]]
    datasets_js = json.dumps(datasets, ensure_ascii=False)
    labels_js = json.dumps(hourly_labels, ensure_ascii=False)

    base_cfg = {
        "type": "bar",
        "data": "__DATA__",  # will be replaced in JS
        "options": {
            "responsive": True,
            "plugins": {"legend": {"position": "top"}, "title": {"display": False}},
            "scales": {"x": {"stacked": True}, "y": {"stacked": True, "beginAtZero": True}}
        }
    }
    config_js = json.dumps(base_cfg, ensure_ascii=False).replace('"__DATA__"', "data")
    init_theme_js = json.dumps(initial_theme)

    def pairs_to_ld(pairs: List[Tuple[str, int]]):
        return ([p[0] for p in pairs], [int(p[1]) for p in pairs]) if pairs else (["Other"], [0])

    sigL, sigD = pairs_to_ld(agg["sig_top"])
    cL, cD = pairs_to_ld(agg["country_top"])
    ipL, ipD = pairs_to_ld(agg["ip_top"])
    hL, hD = pairs_to_ld(agg["host_top"])
    tL, tD = pairs_to_ld(agg["tool_top"])
    sigL_js, sigD_js = json.dumps(sigL, ensure_ascii=False), json.dumps(sigD)
    cL_js, cD_js = json.dumps(cL, ensure_ascii=False), json.dumps(cD)
    ipL_js, ipD_js = json.dumps(ipL, ensure_ascii=False), json.dumps(ipD)
    hL_js, hD_js = json.dumps(hL, ensure_ascii=False), json.dumps(hD)
    tL_js, tD_js = json.dumps(tL, ensure_ascii=False), json.dumps(tD)

    # per-host cards + datasets
    def slugify(s: str) -> str:
        s = re.sub(r"[^A-Za-z0-9._-]+", "-", s.strip())
        return re.sub(r"-+", "-", s).strip("-").lower() or "host"

    host_cards_html = []
    host_datasets = []
    for i, bd in enumerate(host_bds, 1):
        key = slugify(bd["host"])

        def ld(x): return ([p[0] for p in x], [int(p[1]) for p in x]) if x else (["Other"], [0])
        HsigL, HsigD = ld(bd["sig_top"])
        HctL, HctD = ld(bd["country_top"])
        HipL, HipD = ld(bd["ip_top"])
        HtlL, HtlD = ld(bd["tool_top"])
        host_datasets.append({"host": bd["host"], "key": key, "sigL": HsigL, "sigD": HsigD,
                              "ctL": HctL, "ctD": HctD, "ipL": HipL, "ipD": HipD, "tlL": HtlL, "tlD": HtlD})

        e_h = html_escape(epochms_to_human(bd.get("earliest", 0), tz))
        l_h = html_escape(epochms_to_human(bd.get("latest", 0), tz))
        open_attr = " open" if i <= 2 else ""

        rows_sig = as_table_rows(bd["sig_top"], f"host-{key}-sig")
        rows_cty = as_table_rows(bd["country_top"], f"host-{key}-country")
        rows_ip = as_table_rows(bd["ip_top"], f"host-{key}-ip")
        rows_tl = as_table_rows(bd["tool_top"], f"host-{key}-tool")

        host_cards_html.append(f"""
        <details class="card span-12 hostcard"{open_attr} data-host="{html_escape(bd['host'])}">
          <summary class="hostheader">
            <div class="hosttitle">{html_escape(bd['host'])}</div>
            <div class="hostinfo"><span class="badge">Events: {bd['events']:,}</span>
              <span class="badge">Active: {e_h} → {l_h}</span></div>
          </summary>
          <div class="hostgrid">
            <div class="hostcol">
              <div class="section-subtitle">Signatures</div>
              <div class="table-actions"><input placeholder="Filter..." class="filter-input" data-for="tbl-host-{key}-sig">
                <div class="exports" data-for="data-host-{key}-sig"></div></div>
              <table id="tbl-host-{key}-sig" data-name="Host {html_escape(bd['host'])} – Signatures">
                <thead><tr><th>#</th><th>Signature</th><th data-sort="num">Events</th><th data-sort="num">%</th></tr></thead>
                <tbody>{rows_sig}</tbody></table>
              <div class="donut s"><canvas id="pie-host-{key}-sig"></canvas></div>
            </div>
            <div class="hostcol">
              <div class="section-subtitle">Countries</div>
              <div class="table-actions"><input placeholder="Filter..." class="filter-input" data-for="tbl-host-{key}-country">
                <div class="exports" data-for="data-host-{key}-country"></div></div>
              <table id="tbl-host-{key}-country" data-name="Host {html_escape(bd['host'])} – Countries">
                <thead><tr><th>#</th><th>Country</th><th data-sort="num">Events</th><th data-sort="num">%</th></tr></thead>
                <tbody>{rows_cty}</tbody></table>
              <div class="donut s"><canvas id="pie-host-{key}-country"></canvas></div>
            </div>
            <div class="hostcol">
              <div class="section-subtitle">Attack IPs</div>
              <div class="table-actions"><input placeholder="Filter..." class="filter-input" data-for="tbl-host-{key}-ip">
                <div class="exports" data-for="data-host-{key}-ip"></div></div>
              <table id="tbl-host-{key}-ip" data-name="Host {html_escape(bd['host'])} – IPs">
                <thead><tr><th>#</th><th>IP Address</th><th data-sort="num">Requests</th><th data-sort="num">%</th></tr></thead>
                <tbody>{rows_ip}</tbody></table>
              <div class="donut s"><canvas id="pie-host-{key}-ip"></canvas></div>
            </div>
            <div class="hostcol">
              <div class="section-subtitle">Attack Tools</div>
              <div class="table-actions"><input placeholder="Filter..." class="filter-input" data-for="tbl-host-{key}-tool">
                <div class="exports" data-for="data-host-{key}-tool"></div></div>
              <table id="tbl-host-{key}-tool" data-name="Host {html_escape(bd['host'])} – Tools">
                <thead><tr><th>#</th><th>Tool</th><th data-sort="num">Events</th><th data-sort="num">%</th></tr></thead>
                <tbody>{rows_tl}</tbody></table>
              <div class="donut s"><canvas id="pie-host-{key}-tool"></canvas></div>
            </div>
          </div>
        </details>
        """)

    host_cards_html = "\n".join(host_cards_html) if host_cards_html else "<div class='card span-12' style='color:var(--muted);font-size:13px;'>No website breakdown (no matching hosts in data).</div>"
    host_datasets_js = json.dumps(host_datasets, ensure_ascii=False)

    # -------- JS blocks moved out of f-string --------
    helpers_head_js = r"""
function cssVar(n){return getComputedStyle(document.documentElement).getPropertyValue(n).trim();}
function cbPalette(n){
  const base=['#000000','#E69F00','#56B4E9','#009E73','#F0E442','#0072B2','#D55E00','#CC79A7','#999999'];
  const a=[]; for(let i=0;i<n;i++) a.push(base[i%base.length]); return a;
}
function applyChartTheme(chart){
  try{
    if(!chart) return;
    const t=cssVar('--text'), b=cssVar('--border');
    if(chart.options && chart.options.plugins && chart.options.plugins.legend && chart.options.plugins.legend.labels){
      chart.options.plugins.legend.labels.color=t;
    }
    if(chart.config && chart.config.type==='bar'){
      chart.options.scales.x.ticks={color:t};
      chart.options.scales.y.ticks={precision:0,color:t};
      chart.options.scales.x.grid={color:b};
      chart.options.scales.y.grid={color:b};
    }
    chart.update('none');
  }catch(e){ console.warn('theme apply err', e); }
}
""".strip()

    theme_js = r"""
(function(){
  const STORAGE_KEY='aa-theme', FONT_KEY='aa-font', provided=__INIT_THEME__;
  let theme = localStorage.getItem(STORAGE_KEY) || provided || 'dark';
  if(theme==='auto'){
    theme = (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) ? 'dark' : 'light';
  }
  document.documentElement.setAttribute('data-theme', theme);
  const btn=document.getElementById('themeToggle'), label=document.getElementById('themeLabel');
  function setLabel(){ label.textContent=(document.documentElement.getAttribute('data-theme')==='light')?'Light':'Dark'; } setLabel();
  btn.addEventListener('click',()=>{
    const cur=document.documentElement.getAttribute('data-theme')||'dark';
    const nxt=(cur==='dark')?'light':'dark';
    document.documentElement.setAttribute('data-theme',nxt);
    localStorage.setItem(STORAGE_KEY,nxt);
    setLabel();
    applyChartTheme(window.__aaChart);
    (window.__pies||[]).forEach(applyChartTheme);
    (window.__hostPies||[]).forEach(applyChartTheme);
  });
  const fPlus=document.getElementById('fontPlus'), fMinus=document.getElementById('fontMinus');
  function setFont(sz){ document.documentElement.style.setProperty('--base-font', sz+'px'); localStorage.setItem(FONT_KEY,String(sz)); }
  setFont(parseInt(localStorage.getItem(FONT_KEY)||'16',10));
  fPlus.addEventListener('click',()=>setFont(Math.min(22,(parseInt(getComputedStyle(document.documentElement).getPropertyValue('--base-font'))||16)+1)));
  fMinus.addEventListener('click',()=>setFont(Math.max(12,(parseInt(getComputedStyle(document.documentElement).getPropertyValue('--base-font'))||16)-1)));
})();
""".strip()

    hourly_js = r"""
(function(){
  function ready(fn){ if(document.readyState!=='loading'){fn()} else {document.addEventListener('DOMContentLoaded', fn)}}
  ready(function(){
    try{
      if(typeof Chart==='undefined'){ throw new Error('Chart.js not loaded'); }
      const ctx=document.getElementById('hourlyChart').getContext('2d');
      const data={ labels: __LABELS__, datasets: __DATASETS__ };
      const config=__CONFIG__;
      window.__aaChart=new Chart(ctx,config);
      applyChartTheme(window.__aaChart);
      const total=(data.datasets||[]).reduce((a,ds)=>a+(ds.data||[]).reduce((x,y)=>x+(+y||0),0),0);
      if(!total){
        document.getElementById('threat-activities').insertAdjacentHTML('beforeend','<div class="banner warn">No Threat Activities in this period.</div>');
      }
    }catch(e){
      console.error('[AA Report] hourly chart error:', e);
      document.getElementById('threat-activities').insertAdjacentHTML('beforeend','<div class="banner warn">Chart error: '+(e&&e.message||e)+'</div>');
    }
  });
})();
""".strip()

    pies_js = r"""
window.__pies=[];
function createDoughnut(id,labels,values){
  try{
    const el=document.getElementById(id); if(!el) return;
    const ch=new Chart(el.getContext('2d'),{
      type:'doughnut',
      data:{labels:labels,datasets:[{data:values,backgroundColor:cbPalette(labels.length),borderColor:cssVar('--border')}]},
      options:{
        responsive:true,
        maintainAspectRatio:false,
        resizeDelay:80,
        cutout:'60%',
        layout:{padding:8},
        plugins:{
          legend:{position:'right',labels:{color:cssVar('--text')}},
          tooltip:{callbacks:{label:function(ctx){
            const t=(ctx.dataset.data||[]).reduce((a,b)=>a+b,0)||1; const v=+ctx.raw||0;
            const p=(v*100/t).toFixed(1)+'%'; return ctx.label+': '+v.toLocaleString()+' ('+p+')';
          }}}
        }
      }
    });
    window.__pies.push(ch); applyChartTheme(ch);
  }catch(e){ console.error('[AA Report] doughnut error', id, e); }
}
createDoughnut('pieSig', __SIG_L__, __SIG_D__);
createDoughnut('pieCountry', __C_L__, __C_D__);
createDoughnut('pieIP', __IP_L__, __IP_D__);
createDoughnut('pieHost', __H_L__, __H_D__);
createDoughnut('pieTool', __T_L__, __T_D__);
""".strip()

    host_pies_js = r"""
(function(){
  function safeDoughnut(id, labels, values){
    try{
      const el=document.getElementById(id); if(!el) return;
      const cfg={
        type:'doughnut',
        data:{ labels, datasets:[{ data:values, backgroundColor:cbPalette(labels.length), borderColor:cssVar('--border') }] },
        options:{
          responsive:true,
          maintainAspectRatio:false,
          resizeDelay:80,
          cutout:'60%',
          plugins:{ legend:{ display:false } },
          layout:{padding:6}
        }
      };
      const ch=new Chart(el.getContext('2d'), cfg);
      window.__hostPies.push(ch); applyChartTheme(ch);
    }catch(e){ console.error('[AA Report] host pie error', id, e); }
  }
  try{
    (window.hostDatasets||[]).forEach(h=>{
      safeDoughnut(`pie-host-${h.key}-sig`,     h.sigL, h.sigD);
      safeDoughnut(`pie-host-${h.key}-country`, h.ctL,  h.ctD);
      safeDoughnut(`pie-host-${h.key}-ip`,      h.ipL,  h.ipD);
      safeDoughnut(`pie-host-${h.key}-tool`,    h.tlL,  h.tlD);
    });
  }catch(e){ console.error('[AA Report] iterate host pies error', e); }
})();
""".strip()

    helpers_js = r"""
function attachSort(table){
  const ths=table.querySelectorAll('thead th');
  ths.forEach((th,idx)=>{
    th.addEventListener('click',()=>{
      const isNum=th.getAttribute('data-sort')==='num'||th.textContent.toLowerCase().includes('event')||th.textContent.toLowerCase().includes('%');
      const rows=Array.from(table.querySelectorAll('tbody tr')); const asc=!(th.classList.contains('asc'));
      ths.forEach(x=>x.classList.remove('asc','desc')); th.classList.add(asc?'asc':'desc');
      rows.sort((a,b)=>{
        let av,bv;
        if(isNum){
          av=parseFloat(a.children[idx].getAttribute('data-sort')||a.children[idx].textContent.replace(/[, %]/g,'')||'0');
          bv=parseFloat(b.children[idx].getAttribute('data-sort')||b.children[idx].textContent.replace(/[, %]/g,'')||'0');
        }else{
          av=a.children[idx].textContent.trim().toLowerCase();
          bv=b.children[idx].textContent.trim().toLowerCase();
        }
        return asc?(av>bv?1:av<bv?-1:0):(av>bv?-1:av<bv?1:0);
      });
      const tb=table.querySelector('tbody'); rows.forEach(r=>tb.appendChild(r));
    });
  });
}
function attachFilter(input){
  const id=input.getAttribute('data-for'); const table=document.getElementById(id); if(!table) return;
  input.addEventListener('input',()=>{
    const q=input.value.trim().toLowerCase();
    table.querySelectorAll('tbody tr').forEach(tr=>{
      const label=tr.querySelector('.label')?.textContent?.toLowerCase()||'';
      tr.style.display = (!q || label.includes(q)) ? '' : 'none';
    });
  });
}
function makeBlobUrl(str,mime){ const blob=new Blob([str],{type:mime}); return URL.createObjectURL(blob); }
function exportCSV(name,rows){
  const header=['Rank','Label','Value','Percent'];
  const total=rows.reduce((a,b)=>a+(b.value||0),0)||1;
  const body=rows.map((r,i)=>[i+1,r.label,r.value,((r.value*100/total).toFixed(1)+'%')]);
  const all=[header].concat(body).map(cols=>cols.join(',')).join('\n');
  const url=makeBlobUrl(all,'text/csv;charset=utf-8'); const a=document.createElement('a'); a.href=url; a.download=(name||'table')+'.csv'; a.click();
}
function exportJSON(name,rows){
  const url=makeBlobUrl(JSON.stringify(rows,null,2),'application/json'); const a=document.createElement('a'); a.href=url; a.download=(name||'table')+'.json'; a.click();
}
function attachExports(){
  document.querySelectorAll('.exports').forEach(box=>{
    const forId=box.getAttribute('data-for'); const script=document.getElementById(forId);
    const table=box.closest('.split, .hostcol, .card').querySelector('table'); const name=table?.getAttribute('data-name')||'table';
    if(!script||!table) return;
    const rows=JSON.parse(script.textContent||'[]');
    const btnCsv=document.createElement('button'); btnCsv.className='btn'; btnCsv.textContent='Download CSV';
    const btnJson=document.createElement('button'); btnJson.className='btn'; btnJson.textContent='Download JSON';
    btnCsv.addEventListener('click',()=>exportCSV(name,rows));
    btnJson.addEventListener('click',()=>exportJSON(name,rows));
    box.appendChild(btnCsv); box.appendChild(btnJson);
  });
}
document.querySelectorAll('table').forEach(attachSort);
document.querySelectorAll('.filter-input').forEach(attachFilter);
attachExports();
""".strip()

    expand_js = r"""
(function(){
  const ex = document.getElementById('expandAll');
  const col = document.getElementById('collapseAll');
  if (ex && col) {
    ex.addEventListener('click', function(){
      document.querySelectorAll('details.hostcard').forEach(function(d){ d.setAttribute('open',''); });
    });
    col.addEventListener('click', function(){
      document.querySelectorAll('details.hostcard').forEach(function(d){ d.removeAttribute('open'); });
    });
  }
})();
""".strip()

    partial_banner = ""
    if partial_fail_count > 0:
        partial_banner = f"""<div class="banner warn">Partial data: {partial_fail_count} incident stats failed to fetch. KPI/Top counts may be slightly lower.</div>"""

    csp = ("default-src 'self'; "
           "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
           "font-src https://fonts.gstatic.com; "
           "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
           "img-src 'self' data:; connect-src 'self';")

    html_out = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="{html_escape(csp)}">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Attack Analytics Report – {html_escape(date_str if end_date_str==date_str else (date_str+' → '+end_date_str))} ({html_escape(tz)})</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;800&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {{ --base-font:16px; --page-bg:radial-gradient(1200px 800px at 80% -10%, #152040 0%, #0a0f1f 60%); --bg:#0a0f1f; --panel:#0f1833; --muted:#8ea2c5; --text:#e8efff; --accent:#6ab0ff; --good:#2ecc71; --warn:#f1c40f; --bad:#e74c3c; --border:#1b2647; --ring:rgba(106,176,255,.25); }}
html[data-theme="light"] {{ --page-bg:radial-gradient(1200px 800px at 80% -10%, #f2f6ff 0%, #f7f9fc 60%); --bg:#f7f9fc; --panel:#fff; --muted:#5a6b86; --text:#101522; --accent:#0d6efd; --good:#16a34a; --warn:#b7791f; --bad:#d43f3a; --border:#e5eaf2; --ring:rgba(13,110,253,.15); }}
* {{ box-sizing:border-box; }} html,body {{ height:100%; background:var(--page-bg); }}
body {{ margin:0; padding:28px; color:var(--text); font-family:'Inter',system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; font-size:var(--base-font); }}
header {{ display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; margin-bottom:18px; }}
.brand {{ font-weight:800; font-size:1.4rem; }} .datepill {{ font-size:.8rem;color:var(--muted);border:1px solid var(--border);padding:6px 10px;border-radius:999px; }}
.grid {{ display:grid; gap:16px; grid-template-columns:repeat(12, minmax(0,1fr)); }} .card {{ background:linear-gradient(180deg,rgba(255,255,255,.03),rgba(255,255,255,.0)); border:1px solid var(--border); border-radius:16px; padding:16px; box-shadow:0 8px 28px rgba(0,0,0,.12); }}
.kpi {{ grid-column:span 4; position:relative; overflow:hidden; }} .kpi::after {{ content:''; position:absolute; right:-40px; top:-40px; width:120px; height:120px; border-radius:50%; background:var(--ring); filter:blur(8px); }}
.span-12 {{ grid-column:span 12; }} .span-6 {{ grid-column:span 6; }}
.section-title {{ margin:0 0 8px; font-size:1rem; font-weight:700; }} .section-subtitle {{ font-size:.9rem; font-weight:700; color:var(--muted); margin:4px 0 8px; }}
.nav {{ display:flex; gap:10px; flex-wrap:wrap; margin:6px 0 14px; }} .nav a {{ padding:6px 10px; border:1px solid var(--border); border-radius:999px; color:var(--text); text-decoration:none; font-size:.8rem; }}
.banner.warn {{ border:1px solid var(--warn); color:#000; background:#f6d365; padding:8px 12px; border-radius:10px; }}
.split {{ display:grid; grid-template-columns:1.6fr 1fr; gap:14px; align-items:start; }} @media (max-width:1100px) {{ .split {{ grid-template-columns:1fr; }} }}
table {{ width:100%; border-collapse:collapse; font-size:.9rem; }} thead th {{ position:sticky; top:0; background:var(--panel); z-index:2; cursor:pointer; user-select:none; }}
th,td {{ padding:10px 12px; border-bottom:1px solid var(--border); text-align:left; }} th {{ color:var(--muted); text-transform:uppercase; letter-spacing:.6px; font-size:.75rem; }}
td.value,td.pct,td.rank {{ text-align:right; }} tr:hover {{ background:rgba(255,255,255,.03); }}
.footer {{ margin-top:22px; color:var(--muted); font-size:.75rem; }}
.pct-wrap {{ position:relative; width:100%; height:18px; background:color-mix(in srgb, var(--panel) 80%, #0000); border:1px solid var(--border); border-radius:999px; overflow:hidden; }}
.pct-bar {{ position:absolute; left:0; top:0; bottom:0; background:linear-gradient(90deg, var(--accent), #7cc7ff); }}
.pct-text {{ position:absolute; inset:0; display:flex; align-items:center; justify-content:center; font-size:.75rem; color:var(--text); text-shadow:0 1px 0 rgba(0,0,0,.15); }}
.hostheader {{ display:flex; align-items:center; justify-content:space-between; gap:12px; cursor:pointer; }} details.hostcard>summary {{ list-style:none; }} details.hostcard>summary::-webkit-details-marker {{ display:none; }}
.hosttitle {{ font-size:1rem; font-weight:800; }} .badge {{ display:inline-block; padding:4px 10px; border-radius:999px; border:1px solid var(--border); color:var(--muted); font-size:.75rem; }}
.hostgrid {{ display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:14px; margin-top:10px; }} @media (max-width:1100px) {{ .hostgrid {{ grid-template-columns:1fr; }} }}
.actions {{ display:flex; gap:8px; flex-wrap:wrap; }} .btn {{ appearance:none; border:1px solid var(--border); background:var(--panel); color:var(--text); padding:8px 12px; border-radius:10px; font-size:.8rem; cursor:pointer; }}
.toggle {{ display:inline-flex; align-items:center; gap:8px; border:1px solid var(--border); background:var(--panel); color:var(--text); padding:8px 12px; border-radius:999px; cursor:pointer; font-size:.8rem; }}
.table-actions {{ display:flex; align-items:center; justify-content:space-between; gap:8px; margin:4px 0 8px; }} .filter-input {{ padding:6px 10px; border:1px solid var(--border); background:var(--panel); color:var(--text); border-radius:8px; width:180px; }}
/* Donut containers: คุมขนาดกราฟแบบ responsive */
.donut{{ position:relative; height:clamp(200px, 30vh, 340px); }}
.donut.s{{ height:clamp(180px, 26vh, 300px); }}
.donut canvas{{ position:absolute; inset:0; width:100% !important; height:100% !important; }}
@media print {{ html[data-theme="light"] body,body {{ background:#fff; color:#000; }} .card {{ box-shadow:none; }} thead th {{ background:#eee; }} .toggle,.actions,.table-actions,.nav {{ display:none; }} }}
</style>
</head>
<body>
<header id="top">
  <div class="brand">Attack Analytics – Report</div>
  <div class="datepill">Date: <strong>{html_escape(date_str if end_date_str==date_str else (date_str+' → '+end_date_str))}</strong> • TZ: <strong>{html_escape(tz)}</strong> • Window: {html_escape(epochms_to_human(from_ms, tz))} → {html_escape(epochms_to_human(to_ms, tz))} • Granularity: {granularity}</div>
  <div class="actions">
    <button id="themeToggle" class="toggle"><span class="dot"></span><span id="themeLabel">Theme</span></button>
    <button id="fontMinus" class="btn">A-</button><button id="fontPlus" class="btn">A+</button>
  </div>
</header>

<div class="nav">
  <a href="#kpi">KPI</a><a href="#threat-activities">Threat Activities</a><a href="#top-signatures">Top Signatures</a>
  <a href="#top-countries">Top Countries</a><a href="#top-ips">Top IPs</a><a href="#top-hosts">Top Hosts</a>
  <a href="#top-tools">Top Tools</a><a href="#per-website">Per-Website</a>
</div>

{partial_banner}

<div class="grid">
  <div class="card kpi" id="kpi"><div class="label">Threat Events (sum of events_count)</div><h2>{agg["threat_events"]:,}</h2></div>
  <div class="card kpi"><div class="label">Block Events (sum of violations_blocked)</div><h2>{agg["block_events"]:,}</h2></div>
  <div class="card kpi"><div class="label">High-Security Incidents (CRITICAL + MAJOR)</div><h2>{agg["high_security_incidents"]:,}</h2></div>

  <div class="card span-12" id="threat-activities">
    <div class="section-title">Threat Activities by {granularity.title()} (Active Incidents, Stacked by Severity)</div>
    <canvas id="hourlyChart" height="120"></canvas>
  </div>

  <div class="card span-6" id="top-signatures">
    <div class="section-title">Top Signatures (dominant_attack_violation)</div>
    <div class="split">
      <div>
        <div class="table-actions"><input placeholder="Filter..." class="filter-input" data-for="tbl-sig"><div class="exports" data-for="data-global-sig"></div></div>
        <table id="tbl-sig" data-name="Top Signatures"><thead><tr><th>#</th><th>Signature</th><th data-sort="num">Events (events_count)</th><th data-sort="num">%</th></tr></thead><tbody>{as_table_rows(agg["sig_top"], "global-sig")}</tbody></table>
      </div><div><div class="donut"><canvas id="pieSig"></canvas></div></div>
    </div>
  </div>

  <div class="card span-6" id="top-countries">
    <div class="section-title">Top Attack Countries (dominant_attack_country.country)</div>
    <div class="split">
      <div>
        <div class="table-actions"><input placeholder="Filter..." class="filter-input" data-for="tbl-country"><div class="exports" data-for="data-global-country"></div></div>
        <table id="tbl-country" data-name="Top Countries"><thead><tr><th>#</th><th>Country</th><th data-sort="num">Events (events_count)</th><th data-sort="num">%</th></tr></thead><tbody>{as_table_rows(agg["country_top"], "global-country")}</tbody></table>
      </div><div><div class="donut"><canvas id="pieCountry"></canvas></div></div>
    </div>
  </div>

  <div class="card span-6" id="top-ips">
    <div class="section-title">Top Attack IPs (from incident stats)</div>
    <div class="split">
      <div>
        <div class="table-actions"><input placeholder="Filter..." class="filter-input" data-for="tbl-ip"><div class="exports" data-for="data-global-ip"></div></div>
        <table id="tbl-ip" data-name="Top IPs"><thead><tr><th>#</th><th>IP Address</th><th data-sort="num">Requests</th><th data-sort="num">%</th></tr></thead><tbody>{as_table_rows(agg["ip_top"], "global-ip")}</tbody></table>
      </div><div><div class="donut"><canvas id="pieIP"></canvas></div></div>
    </div>
  </div>

  <div class="card span-6" id="top-hosts">
    <div class="section-title">Top Target Websites (dominant_attacked_host.value)</div>
    <div class="split">
      <div>
        <div class="table-actions"><input placeholder="Filter..." class="filter-input" data-for="tbl-host"><div class="exports" data-for="data-global-host"></div></div>
        <table id="tbl-host" data-name="Top Hosts"><thead><tr><th>#</th><th>Host</th><th data-sort="num">Events (events_count)</th><th data-sort="num">%</th></tr></thead><tbody>{as_table_rows(agg["host_top"], "global-host")}</tbody></table>
      </div><div><div class="donut"><canvas id="pieHost"></canvas></div></div>
    </div>
  </div>

  <div class="card span-12" id="top-tools">
    <div class="section-title">Top Attack Tools (dominant_attack_tool.name + type)</div>
    <div class="split">
      <div>
        <div class="table-actions"><input placeholder="Filter..." class="filter-input" data-for="tbl-tool"><div class="exports" data-for="data-global-tool"></div></div>
        <table id="tbl-tool" data-name="Top Tools"><thead><tr><th>#</th><th>Tool</th><th data-sort="num">Events (events_count)</th><th data-sort="num">%</th></tr></thead><tbody>{as_table_rows(agg["tool_top"], "global-tool")}</tbody></table>
      </div><div><div class="donut"><canvas id="pieTool"></canvas></div></div>
    </div>
  </div>

  <div class="card span-12" id="per-website">
    <div class="section-title">Per-Website Breakdown (Selected Target Websites)</div>
    <div class="actions"><button id="expandAll" class="btn">Expand All</button><button id="collapseAll" class="btn">Collapse All</button><a class="btn" href="#top">Back to top</a></div>
    {host_cards_html}
  </div>

  <div class="span-12 footer">Built from Imperva Attack Analytics API responses only. Empty/unknown values are grouped as “Other” and shown last in each table.</div>
</div>

<script>
{helpers_head_js}

/* theme & font */
{theme_js.replace('__INIT_THEME__', init_theme_js)}

/* hourly stacked bar */
{hourly_js.replace('__LABELS__', labels_js).replace('__DATASETS__', datasets_js).replace('__CONFIG__', config_js)}

/* global pies */
{pies_js.replace('__SIG_L__', sigL_js).replace('__SIG_D__', sigD_js)
        .replace('__C_L__', cL_js).replace('__C_D__', cD_js)
        .replace('__IP_L__', ipL_js).replace('__IP_D__', ipD_js)
        .replace('__H_L__', hL_js).replace('__H_D__', hD_js)
        .replace('__T_L__', tL_js).replace('__T_D__', tD_js)}

/* host pies */
window.__hostPies=[]; window.hostDatasets={host_datasets_js};
{host_pies_js}

/* tables: sort/filter/export */
{helpers_js}

/* expand/collapse (moved out of f-string) */
{expand_js}
</script>
</body></html>"""
    return html_out


# ---------------- Main ----------------
def generate_report(api_id, api_key, caid, date_str, end_date_str=None, tz="Asia/Bangkok", 
                   granularity="hour", severity_filter=None, breakdown_limit=10, 
                   breakdown_hosts=None, mask_ips=False, mask_cidr=None, timeout=30, 
                   concurrency=8, https_proxy=None, max_retries=2, retry_backoff=0.5, 
                   theme="dark", ca_bundle=None, use_certifi=False, insecure=False):
    """
    Generate Attack Analytics HTML report
    Returns: (html_content, output_filename, error_message)
    """
    try:
        sdt = parse_date_yyyymmdd(date_str)
        edt = parse_date_yyyymmdd(end_date_str) if end_date_str else sdt
    except Exception as e:
        return None, None, f"Invalid date format: {e}"
    
    if edt < sdt:
        sdt, edt = edt, sdt

    ctx = build_ssl_context(ca_bundle, use_certifi, insecure)
    opener = build_opener(https_proxy, ctx)
    headers = default_headers(api_id, api_key)
    from_ms, to_ms, tz_name = range_bounds(sdt, edt, tz)

    try:
        inc_all = fetch_incidents(headers, caid, from_ms, to_ms, ctx, opener, timeout, max_retries, retry_backoff)
    except Exception as e:
        return None, None, f"Error fetching incidents: {e}"

    if severity_filter:
        allow = {s.strip().upper() for s in severity_filter.split(",") if s.strip()}
        incidents = [x for x in inc_all if x.severity in allow]
    else:
        incidents = inc_all

    stats_map: Dict[str, IncidentStats] = {}
    fail = 0
    if incidents:
        with cf.ThreadPoolExecutor(max_workers=max(1, concurrency)) as ex:
            futs = {ex.submit(fetch_incident_stats, headers, caid, inc.id, ctx, opener,
                              timeout, max_retries, retry_backoff): inc.id for inc in incidents}
            for fut in cf.as_completed(futs):
                inc_id = futs[fut]
                try:
                    stats_map[inc_id] = fut.result()
                except Exception as e:
                    fail += 1
                    sys.stderr.write(f"WARNING: stats failed for incident {inc_id}: {e}\n")

    limit = max(1, min(breakdown_limit, 25))
    agg = aggregate(incidents, stats_map, top_n=limit, mask_ips=mask_ips, mask_cidr=mask_cidr or 24)

    if breakdown_hosts:
        sel = [h.strip() for h in breakdown_hosts.split(",") if h.strip()]
        sel = [h for h in sel if h != "Other"]
    else:
        sel = [label for (label, _v) in agg["host_top"] if label != "Other"]

    host_bds = per_host_breakdowns(incidents, stats_map, sel, top_n=limit,
                                   mask_ips=mask_ips, mask_cidr=mask_cidr or 24)

    labels, series, earliest, latest = build_stacks(incidents, stats_map, from_ms, to_ms, tz, granularity)

    out_html = render_html(
        date_str=sdt.strftime("%Y-%m-%d"), end_date_str=edt.strftime("%Y-%m-%d"),
        tz=tz, bounds=(from_ms, to_ms, tz_name),
        incidents=incidents, agg=agg, host_bds=host_bds,
        hourly_labels=labels, hourly_series=series,
        earliest=earliest, latest=latest, initial_theme=theme,
        granularity=granularity, partial_fail_count=fail
    )

    out_filename = f"attack_analytics_caid{caid}_{sdt.strftime('%Y%m%d')}_{edt.strftime('%Y%m%d')}.html"
    return out_html, out_filename, None


def main():
    p = argparse.ArgumentParser(description="Generate Imperva Attack Analytics HTML report (API-only data).",
                                formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--api-id", default=os.environ.get("IMPERVA_API_ID"))
    p.add_argument("--api-key", default=os.environ.get("IMPERVA_API_KEY"))
    p.add_argument("--caid", type=int, required=True)
    p.add_argument("--date", required=True)                    # YYYY-MM-DD
    p.add_argument("--end-date", default=None)                # YYYY-MM-DD
    p.add_argument("--tz", default="Asia/Bangkok")
    p.add_argument("--granularity", choices=["hour", "day"], default="hour")
    p.add_argument("--severity-filter", default=None)         # e.g. CRITICAL,MAJOR
    p.add_argument("--breakdown-limit", type=int, default=10)
    p.add_argument("--breakdown-hosts", default=None)         # comma-separated hostnames to include
    p.add_argument("--mask-ips", action="store_true")
    p.add_argument("--mask-cidr", type=int, default=None)
    p.add_argument("--timeout", type=int, default=30)
    p.add_argument("--concurrency", type=int, default=8)
    p.add_argument("--https-proxy", default=None)
    p.add_argument("--max-retries", type=int, default=2)
    p.add_argument("--retry-backoff", type=float, default=0.5)
    p.add_argument("--out", default=None)
    p.add_argument("--theme", choices=["dark", "light", "auto"], default="dark")
    p.add_argument("--ca-bundle", default=None)
    p.add_argument("--use-certifi", action="store_true")
    p.add_argument("--insecure", action="store_true")

    args = p.parse_args()
    if not args.api_id or not args.api_key:
        print("ERROR: provide --api-id/--api-key or set IMPERVA_API_ID / IMPERVA_API_KEY", file=sys.stderr)
        sys.exit(2)

    try:
        sdt = parse_date_yyyymmdd(args.date)
        edt = parse_date_yyyymmdd(args.end_date) if args.end_date else sdt
    except Exception:
        print("ERROR: --date/--end-date must be YYYY-MM-DD", file=sys.stderr)
        sys.exit(2)
    if edt < sdt:
        sdt, edt = edt, sdt

    ctx = build_ssl_context(args.ca_bundle, args.use_certifi, args.insecure)
    opener = build_opener(args.https_proxy, ctx)
    headers = default_headers(args.api_id, args.api_key)
    from_ms, to_ms, tz_name = range_bounds(sdt, edt, args.tz)

    try:
        inc_all = fetch_incidents(headers, args.caid, from_ms, to_ms, ctx, opener, args.timeout, args.max_retries, args.retry_backoff)
    except Exception as e:
        print(f"ERROR fetching incidents: {e}", file=sys.stderr)
        sys.exit(1)

    if args.severity_filter:
        allow = {s.strip().upper() for s in args.severity_filter.split(",") if s.strip()}
        incidents = [x for x in inc_all if x.severity in allow]
    else:
        incidents = inc_all

    stats_map: Dict[str, IncidentStats] = {}
    fail = 0
    if incidents:
        with cf.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
            futs = {ex.submit(fetch_incident_stats, headers, args.caid, inc.id, ctx, opener,
                              args.timeout, args.max_retries, args.retry_backoff): inc.id for inc in incidents}
            for fut in cf.as_completed(futs):
                inc_id = futs[fut]
                try:
                    stats_map[inc_id] = fut.result()
                except Exception as e:
                    fail += 1
                    sys.stderr.write(f"WARNING: stats failed for incident {inc_id}: {e}\n")

    limit = max(1, min(args.breakdown_limit, 25))
    agg = aggregate(incidents, stats_map, top_n=limit, mask_ips=args.mask_ips, mask_cidr=args.mask_cidr or 24)

    if args.breakdown_hosts:
        sel = [h.strip() for h in args.breakdown_hosts.split(",") if h.strip()]
        sel = [h for h in sel if h != "Other"]
    else:
        sel = [label for (label, _v) in agg["host_top"] if label != "Other"]

    host_bds = per_host_breakdowns(incidents, stats_map, sel, top_n=limit,
                                   mask_ips=args.mask_ips, mask_cidr=args.mask_cidr or 24)

    labels, series, earliest, latest = build_stacks(incidents, stats_map, from_ms, to_ms, args.tz, args.granularity)

    out_html = render_html(
        date_str=sdt.strftime("%Y-%m-%d"), end_date_str=edt.strftime("%Y-%m-%d"),
        tz=args.tz, bounds=(from_ms, to_ms, tz_name),
        incidents=incidents, agg=agg, host_bds=host_bds,
        hourly_labels=labels, hourly_series=series,
        earliest=earliest, latest=latest, initial_theme=args.theme,
        granularity=args.granularity, partial_fail_count=fail
    )

    out_path = args.out or f"attack_analytics_caid{args.caid}_{sdt.strftime('%Y%m%d')}_{edt.strftime('%Y%m%d')}.html"
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(out_html)
    print(out_path)


if __name__ == "__main__":
    main()
