"""Overview-screen analytics. Pure functions: pipeline-time table builders and read-time queries over the
dataset SQLite file. The UI renders these numbers and sentences as they are; it computes nothing itself."""
from __future__ import annotations

import datetime as dt
import sqlite3

import numpy as np
import pandas as pd

from .config import PRIVILEGED_USERS
from .rules import (ANOMALY_RULE, ATTACKER_SEVERITY_TEXT, GAP_MIN_HOURS, RECOMMENDED_ACTION, RULES,
                    SEVERITY_ORDER)

RANGES = ("24h", "7d", "all")
RANGE_HOURS = {"24h": 24, "7d": 24 * 7}
SEVERITIES = ["Critical", "High", "Medium", "Low", "No incident"]
NO_ACTION = "No action needed; keep monitoring."


# ----------------------------------------------------------------------------- pipeline-time builders
def dataset_meta(events: pd.DataFrame, stats: dict, source: str, year: int, reports_dir: str = "") -> pd.DataFrame:
    total = int(stats.get("lines_total", len(events)))
    unmatched = int(stats.get("lines_unmatched", 0))
    other = int((events["event_type"] == "OTHER").sum())
    rows = {
        "filename": source, "year": year, "lines_total": total, "lines_unmatched": unmatched,
        "lines_other": other, "unparsed_pct": round(100 * unmatched / max(total, 1), 4),
        "events": int(len(events)), "period_start": str(events["ts"].min()), "period_end": str(events["ts"].max()),
        "reports_dir": str(reports_dir),
        "run_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    }
    return pd.DataFrame({"key": list(rows), "value": [str(v) for v in rows.values()]})


def log_gaps(events: pd.DataFrame, min_hours: int = GAP_MIN_HOURS) -> pd.DataFrame:
    """Runs of >= min_hours consecutive whole hours holding no log line at all."""
    hrs = events["ts"].dt.floor("h")
    full = pd.date_range(hrs.min(), hrs.max(), freq="h")
    present = full.isin(hrs.unique())
    out, start = [], None
    for t, p in zip(full, present):
        if not p and start is None:
            start = t
        if p and start is not None:
            end = t
            if (end - start) >= pd.Timedelta(hours=min_hours):
                out.append((start, end))
            start = None
    return pd.DataFrame([{"start_ts": s.strftime("%Y-%m-%d %H:%M:%S"), "end_ts": e.strftime("%Y-%m-%d %H:%M:%S"),
                          "hours": int((e - s) / pd.Timedelta(hours=1))} for s, e in out],
                        columns=["start_ts", "end_ts", "hours"])


def anomaly_spans(spikes: pd.DataFrame) -> pd.DataFrame:
    cols = ["start_ts", "end_ts", "peak_attempts", "hours", "rule_id", "rule"]
    if spikes.empty:
        return pd.DataFrame(columns=cols)
    h = pd.to_datetime(spikes["hour"]).sort_values()
    grp = (h.diff() > pd.Timedelta(hours=1)).cumsum()
    rows = []
    for _, idx in h.groupby(grp).groups.items():
        s = spikes.loc[idx]
        hh = pd.to_datetime(s["hour"])
        rows.append({"start_ts": hh.min().strftime("%Y-%m-%d %H:%M:%S"),
                     "end_ts": (hh.max() + pd.Timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
                     "peak_attempts": int(s["attempts"].max()), "hours": int(len(s)),
                     "rule_id": ANOMALY_RULE["id"], "rule": ANOMALY_RULE["label"]})
    return pd.DataFrame(rows, columns=cols)


def attackers_table(incidents: pd.DataFrame, ip_risk: pd.DataFrame) -> pd.DataFrame:
    """One row per source IP with failed attempts. Severity = highest severity among its incidents."""
    rows = []
    inc = incidents.copy()
    inc["_o"] = inc["severity"].map(SEVERITY_ORDER)
    by_ip = {ip: g.sort_values(["_o", "attempts"], ascending=[False, False]) for ip, g in inc.groupby("ip")}
    for r in ip_risk.itertuples(index=False):
        g = by_ip.get(r.ip)
        if g is None:
            sev, techs, action, top_id, reason = "No incident", "", NO_ACTION, "", \
                "No detection rule fired for this IP. " + ATTACKER_SEVERITY_TEXT
        else:
            top = g.iloc[0]
            sev, top_id = top["severity"], top["incident_id"]
            techs = ",".join(sorted(set(g["technique_id"])))
            action = RECOMMENDED_ACTION[top["rule"]]
            reason = f"{sev}: {top['title']}. {top['evidence']}."
        rows.append({"ip": r.ip, "severity": sev, "techniques": techs, "action": action, "top_incident_id": top_id,
                     "reason": reason, "risk_score": r.risk_score, "risk_tier": r.risk_tier,
                     "incident_count": int(len(g)) if g is not None else 0,
                     "c_volume": r.c_volume, "c_intensity": r.c_intensity, "c_breadth": r.c_breadth,
                     "c_persistence": r.c_persistence, "c_privileged": r.c_privileged, "c_invalid": r.c_invalid})
    return pd.DataFrame(rows)


def ip_daily(events: pd.DataFrame) -> pd.DataFrame:
    fa = events[events["is_failed_attempt"] & events["ip_resolved"].notna()]
    d = fa.groupby(["ip_resolved", fa["ts"].dt.strftime("%Y-%m-%d")])["weight"].sum().reset_index()
    d.columns = ["ip", "day", "attempts"]
    d["attempts"] = d["attempts"].astype(int)
    return d


def build_tables(events, incidents, ip_risk, spikes, stats, source, year, reports_dir: str = "") -> dict[str, pd.DataFrame]:
    return {"dataset_meta": dataset_meta(events, stats, source, year, reports_dir), "attackers": attackers_table(incidents, ip_risk),
            "ip_daily": ip_daily(events), "log_gaps": log_gaps(events), "anomaly_spans": anomaly_spans(spikes)}


# ----------------------------------------------------------------------------- read-time queries
def meta(conn: sqlite3.Connection) -> dict:
    return dict(conn.execute("SELECT key, value FROM dataset_meta").fetchall())


def _window(m: dict, rng: str):
    end = pd.Timestamp(m["period_end"])
    start0 = pd.Timestamp(m["period_start"])
    if rng == "all":
        return start0, end, None, None
    h = pd.Timedelta(hours=RANGE_HOURS[rng])
    start = end - h
    pstart, pend = start - h, start
    covered = pstart >= start0
    return start, end, (pstart, pend) if covered else None, None


def _failed(conn, start=None, end=None) -> pd.DataFrame:
    q = ("SELECT ts, ip_resolved AS ip, username, weight FROM events "
         "WHERE is_failed_attempt = 1 AND ip_resolved IS NOT NULL")
    p: list = []
    if start is not None:
        q += " AND ts > ? AND ts <= ?"
        p = [start.strftime("%Y-%m-%d %H:%M:%S"), end.strftime("%Y-%m-%d %H:%M:%S")]
    df = pd.read_sql_query(q, conn, params=p)
    df["ts"] = pd.to_datetime(df["ts"])
    return df


def _incs(conn, start, end) -> pd.DataFrame:
    df = pd.read_sql_query("SELECT incident_id, severity, start_ts FROM incidents", conn)
    df["start_ts"] = pd.to_datetime(df["start_ts"])
    if start is not None:
        df = df[(df["start_ts"] > start) & (df["start_ts"] <= end)]
    return df


def _cell_values(f: pd.DataFrame, inc: pd.DataFrame) -> dict:
    return {"failed_attempts": int(f["weight"].sum()), "unique_ips": int(f["ip"].nunique()),
            "high_critical": int(inc["severity"].isin(["Critical", "High"]).sum()),
            "targeted_accounts": int(f["username"].dropna().nunique())}


def _spark(f: pd.DataFrame, inc: pd.DataFrame, start, end, hourly: bool) -> dict:
    freq = "h" if hourly else "D"
    s0, e0 = start.floor(freq), end.floor(freq)
    idx = pd.date_range(s0, e0, freq=freq)
    if hourly and len(idx) > 24:
        idx = idx[-24:]
    if not hourly and len(idx) > 60:
        idx = idx[-60:]
    b = f["ts"].dt.floor(freq)
    inb = inc["start_ts"].dt.floor(freq)
    return {
        "failed_attempts": f.groupby(b)["weight"].sum().reindex(idx, fill_value=0).astype(int).tolist(),
        "unique_ips": f.groupby(b)["ip"].nunique().reindex(idx, fill_value=0).astype(int).tolist(),
        "high_critical": inc[inc["severity"].isin(["Critical", "High"])].groupby(inb).size().reindex(idx, fill_value=0).astype(int).tolist(),
        "targeted_accounts": f.dropna(subset=["username"]).groupby(b)["username"].nunique().reindex(idx, fill_value=0).astype(int).tolist(),
    }


def _pct(cur: int, prev: int):
    return None if prev == 0 else round(100 * (cur - prev) / prev, 1)


def trust(conn) -> dict:
    m = meta(conn)
    gaps = pd.read_sql_query("SELECT * FROM log_gaps", conn).to_dict("records")
    return {"filename": m["filename"], "period_start": m["period_start"], "period_end": m["period_end"],
            "lines_total": int(m["lines_total"]), "lines_unmatched": int(m["lines_unmatched"]),
            "lines_other": int(m["lines_other"]), "unparsed_pct": float(m["unparsed_pct"]),
            "last_upload": m["run_at"], "year_assumed": int(m["year"]), "gaps": gaps}


def overview(conn: sqlite3.Connection, rng: str = "7d") -> dict:
    if rng not in RANGES:
        raise ValueError(f"range must be one of {RANGES}")
    m = meta(conn)
    start, end, prev, _ = _window(m, rng)
    kw = (None, None) if rng == "all" else (start, end)
    f, inc = _failed(conn, *kw), _incs(conn, *kw)
    cur = _cell_values(f, inc)
    prv, prev_gap_h, gaps_df = None, 0, pd.read_sql_query("SELECT * FROM log_gaps", conn)
    if prev is not None:
        prv = _cell_values(_failed(conn, *prev), _incs(conn, *prev))
        for g in gaps_df.itertuples():
            lo, hi = max(pd.Timestamp(g.start_ts), prev[0]), min(pd.Timestamp(g.end_ts), prev[1])
            prev_gap_h += max(0, int((hi - lo) / pd.Timedelta(hours=1)))
    reliable = prv is not None and prev_gap_h == 0
    spark = _spark(f, inc, start, end, hourly=(rng == "24h"))
    ctl = pd.read_sql_query("SELECT result FROM control_matrix", conn)["result"].value_counts().to_dict()
    tested = int(sum(v for k, v in ctl.items() if k != "Not tested"))
    eff = int(ctl.get("Effective", 0))
    labels = {"failed_attempts": "Failed login attempts", "unique_ips": "Unique source IPs",
              "high_critical": "High and Critical incidents", "targeted_accounts": "Targeted accounts"}
    cells = []
    for k, label in labels.items():
        cells.append({"key": k, "label": label, "value": cur[k],
                      "previous": None if prv is None else prv[k],
                      "change_pct": _pct(cur[k], prv[k]) if reliable else None,
                      "spark": spark[k]})
    cells.append({"key": "controls_effective", "label": "Controls effective", "value": eff,
                  "of": tested, "previous": None, "change_pct": None, "spark": None})

    # time series: hourly attempts, null inside no-activity gaps
    hourly = pd.read_sql_query("SELECT hour, attempts FROM hourly_attempts", conn)
    hourly["hour"] = pd.to_datetime(hourly["hour"])
    hs = hourly[(hourly["hour"] > start.floor("h") - pd.Timedelta(hours=1)) & (hourly["hour"] <= end)] if rng != "all" else hourly
    gaps = pd.read_sql_query("SELECT * FROM log_gaps", conn)
    gap_list = [{"start": g.start_ts, "end": g.end_ts, "hours": int(g.hours)} for g in gaps.itertuples()
                if pd.Timestamp(g.end_ts) > start and pd.Timestamp(g.start_ts) <= end]
    pts = []
    for t, a in zip(hs["hour"], hs["attempts"]):
        in_gap = any(pd.Timestamp(g["start"]) <= t < pd.Timestamp(g["end"]) for g in gap_list)
        pts.append([t.strftime("%Y-%m-%d %H:%M:%S"), None if in_gap else int(a)])
    spans = pd.read_sql_query("SELECT * FROM anomaly_spans", conn)
    spans = spans[(pd.to_datetime(spans["end_ts"]) > start) & (pd.to_datetime(spans["start_ts"]) <= end)]
    span_list = spans.to_dict("records")

    # attempts by attacker severity (severity of the IP, whole log)
    sev = pd.read_sql_query("SELECT ip, severity FROM attackers", conn).set_index("ip")["severity"]
    fs = f.assign(sev=f["ip"].map(sev).fillna("No incident"))
    by_sev = fs.groupby("sev")["weight"].sum().reindex(SEVERITIES, fill_value=0).astype(int)
    by_severity = [{"severity": s, "attempts": int(v)} for s, v in by_sev.items()]

    label = {"24h": "the last 24 hours", "7d": "the last 7 days", "all": "the whole log"}[rng]
    peak = hs.loc[hs["attempts"].idxmax()] if len(hs) and hs["attempts"].max() > 0 else None
    cap_ts = (f"Failed login attempts per hour over {label} (ends {end:%Y-%m-%d %H:%M})."
              + (f" Peak hour: {int(peak['attempts']):,} on {peak['hour']:%Y-%m-%d %H:00}." if peak is not None else "")
              + (f" Shaded: {len(gap_list)} period(s) with no log lines." if gap_list else "")
              + (f" {len(span_list)} unusual spike(s) marked." if span_list else " No unusual spikes found by the rule."))
    top = by_sev.drop("No incident", errors="ignore")
    cap_sev = (f"Failed attempts in {label} grouped by the highest severity of the source IP. "
               f"{int(by_sev.sum()):,} attempts in total.")
    return {"range": rng, "window": {"start": str(start), "end": str(end)},
            "previous_window": None if prev is None else {"start": str(prev[0]), "end": str(prev[1])},
            "change_note": ("No previous period to compare with." if prev is None else
                            f"Not compared: the previous period holds {prev_gap_h} hours with no log lines, so a change would mislead."
                            if prev_gap_h else "Change is against the equal-length period just before this one."),
            "trust": trust(conn), "cells": cells,
            "timeseries": {"points": pts, "gaps": gap_list, "anomalies": span_list, "anomaly_rule": ANOMALY_RULE,
                           "caption": cap_ts},
            "by_severity": {"rows": by_severity, "caption": cap_sev, "rule": ATTACKER_SEVERITY_TEXT}}


def attackers(conn, rng="7d", sort="attempts", direction="desc", q: str | None = None,
              severity: str | None = None, limit: int = 25, offset: int = 0) -> dict:
    m = meta(conn)
    start, end, _, _ = _window(m, rng)
    f = _failed(conn, *((None, None) if rng == "all" else (start, end)))
    agg = f.groupby("ip").agg(attempts=("weight", "sum"), first_seen=("ts", "min"), last_seen=("ts", "max"),
                              accounts=("username", lambda s: int(s.dropna().nunique()))).reset_index()
    agg["attempts"] = agg["attempts"].astype(int)
    att = pd.read_sql_query("SELECT * FROM attackers", conn)
    df = agg.merge(att, on="ip", how="left")
    df["severity"] = df["severity"].fillna("No incident")
    df = df.sort_values("attempts", ascending=False).reset_index(drop=True)
    df.insert(0, "rank", df.index + 1)
    if q:
        df = df[df["ip"].str.contains(q.strip(), regex=False)]
    if severity:
        df = df[df["severity"] == severity]
    keymap = {"severity": df["severity"].map({**SEVERITY_ORDER, "No incident": 0}) if len(df) else None}
    if sort in df.columns and len(df):
        key = keymap.get(sort) if sort == "severity" else df[sort]
        df = df.assign(_k=key).sort_values("_k", ascending=(direction == "asc"), kind="stable").drop(columns="_k")
    total = int(len(df))
    page = df.iloc[offset: offset + limit]
    end_day = pd.Timestamp(m["period_end"]).floor("D")
    days = pd.date_range(end_day - pd.Timedelta(days=13), end_day, freq="D").strftime("%Y-%m-%d")
    daily = pd.read_sql_query("SELECT ip, day, attempts FROM ip_daily WHERE day >= ?", conn, params=[days[0]])
    dmap = {ip: g.set_index("day")["attempts"] for ip, g in daily.groupby("ip")}
    rows = []
    for r in page.to_dict("records"):
        s = dmap.get(r["ip"])
        r["spark14"] = [int(s.get(d, 0)) if s is not None else 0 for d in days]
        r["first_seen"] = r["first_seen"].strftime("%Y-%m-%d %H:%M:%S")
        r["last_seen"] = r["last_seen"].strftime("%Y-%m-%d %H:%M:%S")
        r["techniques"] = [t for t in (r.get("techniques") or "").split(",") if t]
        rows.append({k: (None if isinstance(v, float) and np.isnan(v) else v) for k, v in r.items()})
    return {"range": rng, "total": total, "limit": limit, "offset": offset, "rows": rows,
            "caption": f"{total:,} source IPs with failed attempts in the selected range, ranked by attempts. "
                       "Severity is the highest severity among that IP's incidents over the whole log."}


def attacker_detail(conn, ip: str, max_lines: int = 200) -> dict | None:
    a = pd.read_sql_query("SELECT * FROM attackers WHERE ip = ?", conn, params=[ip])
    if a.empty:
        return None
    r = a.iloc[0].to_dict()
    from .rules import RISK_COMPONENTS, RISK_FORMULA_TEXT, RISK_WEIGHTS
    comps = [{"key": c["key"], "label": c["label"], "formula": c["formula"], "meaning": c["meaning"],
              "weight": RISK_WEIGHTS[c["key"]], "points": r[f"c_{c['key']}"]} for c in RISK_COMPONENTS]
    inc = pd.read_sql_query("SELECT incident_id, rule, title, technique_id, severity, priority, start_ts, end_ts, "
                            "attempts, evidence FROM incidents WHERE ip = ? ORDER BY start_ts", conn, params=[ip])
    risk = pd.read_sql_query("SELECT * FROM ip_risk WHERE ip = ?", conn, params=[ip]).iloc[0]
    return {"ip": ip, "severity": r["severity"], "reason": r["reason"], "action": r["action"],
            "techniques": [t for t in (r["techniques"] or "").split(",") if t],
            "risk": {"score": r["risk_score"], "tier": r["risk_tier"], "components": comps,
                     "formula": RISK_FORMULA_TEXT, "compromise_flag": bool(risk["compromise_flag"])},
            "incidents": inc.to_dict("records"),
            "first_seen": risk["first_seen"], "last_seen": risk["last_seen"]}


def attacker_events(conn, ip: str, limit: int = 50) -> dict:
    total = conn.execute("SELECT COUNT(*) FROM events WHERE ip_resolved = ?", (ip,)).fetchone()[0]
    df = pd.read_sql_query("SELECT ts, raw FROM events WHERE ip_resolved = ? ORDER BY ts LIMIT ?", conn, params=[ip, limit])
    return {"ip": ip, "total": int(total), "shown": int(len(df)), "lines": df.to_dict("records")}


# ----------------------------------------------------------------------------- accounts, incidents, controls
def accounts(conn, rng="7d", sort="attempts", direction="desc", q: str | None = None, limit: int = 25, offset: int = 0) -> dict:
    m = meta(conn)
    start, end, _, _ = _window(m, rng)
    f = _failed(conn, *((None, None) if rng == "all" else (start, end))).dropna(subset=["username"])
    inv = pd.read_sql_query("SELECT DISTINCT username FROM events WHERE is_failed_attempt = 1 AND is_invalid_user = 1", conn)["username"]
    ok = pd.read_sql_query("SELECT username, COUNT(*) AS n FROM events WHERE is_success = 1 GROUP BY username", conn).set_index("username")["n"]
    total = int(f["weight"].sum())
    g = f.groupby("username").agg(attempts=("weight", "sum"), source_ips=("ip", "nunique"), last_seen=("ts", "max")).reset_index()
    g["attempts"] = g["attempts"].astype(int)
    g["share_pct"] = (100 * g["attempts"] / max(total, 1)).round(2)
    g["privileged"] = g["username"].str.lower().isin(PRIVILEGED_USERS)
    g["exists"] = ~g["username"].isin(set(inv))
    g["successful_logins"] = g["username"].map(ok).fillna(0).astype(int)
    g = g.sort_values("attempts", ascending=False)
    if q:
        g = g[g["username"].str.contains(q.strip(), case=False, regex=False)]
    if sort in g.columns:
        g = g.sort_values(sort, ascending=(direction == "asc"), kind="stable")
    page = g.iloc[offset: offset + limit].copy()
    page["last_seen"] = page["last_seen"].dt.strftime("%Y-%m-%d %H:%M:%S")
    top = g.sort_values("attempts", ascending=False).head(10)
    top3 = float(top["attempts"].head(3).sum() / max(total, 1) * 100)
    return {"range": rng, "total": int(len(g)), "limit": limit, "offset": offset,
            "rows": page.to_dict("records"),
            "top": [{"username": r.username, "attempts": int(r.attempts)} for r in top.itertuples()],
            "caption": f"{len(g):,} usernames received failed attempts in the selected range. The top 3 account for "
                       f"{top3:.1f}% of the {total:,} attempts. 'Exists' is No when the server rejected the name as invalid "
                       "(the attacker guessed it)."}


def incidents(conn, rng="7d", rule: str | None = None, severity: str | None = None, q: str | None = None,
              sort="start_ts", direction="desc", limit: int = 25, offset: int = 0) -> dict:
    m = meta(conn)
    start, end, _, _ = _window(m, rng)
    df = pd.read_sql_query("SELECT * FROM incidents", conn)
    df["_s"] = pd.to_datetime(df["start_ts"])
    if rng != "all":
        df = df[(df["_s"] > start) & (df["_s"] <= end)]
    counts = df["severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"], fill_value=0)
    if rule:
        df = df[df["rule"] == rule]
    if severity:
        df = df[df["severity"] == severity]
    if q:
        qq = q.strip().lower()
        df = df[df["ip"].fillna("").str.contains(qq, regex=False) | df["incident_id"].str.lower().str.contains(qq, regex=False)
                | df["username"].fillna("").str.lower().str.contains(qq, regex=False)]
    df = df.assign(_o=df["severity"].map(SEVERITY_ORDER))
    key = "_o" if sort == "severity" else sort if sort in df.columns else "start_ts"
    df = df.sort_values(key, ascending=(direction == "asc"), kind="stable")
    from .rules import RESPONSE_TARGET
    page = df.iloc[offset: offset + limit]
    rows = []
    for r in page.to_dict("records"):
        r["response_target"] = RESPONSE_TARGET.get(r["priority"], "")
        r["username"] = r["username"] if isinstance(r["username"], str) else None
        r["ip"] = r["ip"] if isinstance(r["ip"], str) else None
        rows.append({k: v for k, v in r.items() if k not in ("_s", "_o")})
    return {"range": rng, "total": int(len(df)), "limit": limit, "offset": offset, "rows": rows,
            "by_severity": [{"severity": s, "count": int(v)} for s, v in counts.items()],
            "rules": [{"id": k, "title": v["title"]} for k, v in RULES.items()],
            "caption": f"{len(df):,} incidents started in the selected range. Severity comes from the detection rule; "
                       "priority (P1 to P4) is the ITIL response urgency and is a separate field."}


def controls(conn) -> dict:
    df = pd.read_sql_query("SELECT * FROM control_matrix", conn)
    counts = df["result"].value_counts().to_dict()
    order = ["Effective", "Partially effective", "Ineffective", "Not tested"]
    return {"rows": df.to_dict("records"),
            "summary": [{"result": r, "count": int(counts.get(r, 0))} for r in order],
            "caption": f"{len(df)} controls tested against the log. Each result states the population tested and how many exceptions were found. "
                       "References are to ISO/IEC 27001:2022 and NIST CSF 2.0."}


# ----------------------------------------------------------------------------- forecast and reports
def forecast(conn) -> dict:
    import json
    from .config import DEFAULT as C
    k = {r[0]: json.loads(r[1]) for r in conn.execute("SELECT key, value FROM kpis")}
    out = k["outlook"]
    out.setdefault("last24h", 0); out.setdefault("next24h", 0); out.setdefault("baseline_daily", 0); out.setdefault("ratio", 0.0)
    out.setdefault("confidence", "None"); out.setdefault("headline", out.get("level", "")); out.setdefault("message", "")
    hourly = pd.read_sql_query("SELECT hour, attempts FROM hourly_attempts", conn)
    hourly["hour"] = pd.to_datetime(hourly["hour"])
    gaps = pd.read_sql_query("SELECT * FROM log_gaps", conn)
    def table(t):
        try:
            return pd.read_sql_query(f"SELECT * FROM {t}", conn)
        except Exception:          # the forecast refused to run (not enough history): show no forecast, say why
            return pd.DataFrame(columns=["ts", "yhat", "lo", "hi"])
    fh, fd = table("forecast_hourly"), table("forecast_daily")
    last = hourly["hour"].max()
    hist_h = hourly[hourly["hour"] > last - pd.Timedelta(days=7)]
    daily = hourly.groupby(hourly["hour"].dt.floor("D"))["attempts"].sum()
    in_gap = lambda d: any(pd.Timestamp(g.start_ts) <= d and pd.Timestamp(g.end_ts) >= d + pd.Timedelta(days=1) for g in gaps.itertuples())
    f = lambda t: t.strftime("%Y-%m-%d %H:%M:%S")
    def met(t):
        try:
            return pd.read_sql_query(f"SELECT * FROM {t}", conn).to_dict("records")
        except Exception:
            return []
    rules = [
        f"The hourly model must beat a simple repeat-last-week baseline by at least {C.outlook_min_skill_pct:.0f}% in backtests.",
        f"The next-24-hour forecast must be within {C.outlook_runrate_band[0]}x to {C.outlook_runrate_band[1]}x of the last 24 hours actually seen.",
        f"The upper end of the forecast range must be no more than {C.outlook_interval_ratio:.0f}x the forecast itself.",
        f"The hourly and daily forecasts must agree within {C.outlook_model_agree[0]:.2f}x to {C.outlook_model_agree[1]:.0f}x of each other.",
    ]
    return {
        "outlook": {"level": out["level"], "headline": str(out.get("headline") or out["level"]), "message": str(out.get("message") or ""), "confidence": str(out.get("confidence") or "None"),
                    "reasons": out.get("reasons", []), "last24h": int(out["last24h"] or 0), "next24h": int(out["next24h"] or 0),
                    "baseline_daily": int(out["baseline_daily"] or 0), "ratio": float(out["ratio"] or 0)},
        "models": {"hourly": k.get("forecast_model_hourly"), "daily": k.get("forecast_model_daily")},
        "hourly": {"actual": [[f(t), int(a)] for t, a in zip(hist_h["hour"], hist_h["attempts"])],
                   "forecast": [[f(pd.Timestamp(r.ts)), float(r.yhat), float(r.lo), float(r.hi)] for r in fh.itertuples()]},
        "daily": {"actual": [[f(d), None if in_gap(d) else int(v)] for d, v in daily.items()],
                  "forecast": [[f(pd.Timestamp(r.ts)), float(r.yhat), float(r.lo), float(r.hi)] for r in fd.itertuples()]},
        "backtest": {"hourly": met("forecast_hourly_metrics"), "daily": met("forecast_daily_metrics")},
        "confidence_rules": rules,
        "caption": "Forecasts come from the model that did best in a rolling backtest. The shaded band is built from that model's real past errors. "
                   "The outlook is only called Rising, Falling or Stable when every confidence check passes.",
    }


REPORT_FILES = [
    ("incident_report.md", "Incident report", "Findings, incidents and recommended actions in plain language.", "Analyst"),
    ("deliverables/client_assessment_report.docx", "Client assessment report", "Word report in a consulting format: scope, method, findings, recommendations.", "Client"),
    ("deliverables/executive_summary.pptx", "Executive summary", "Six slides for a leadership briefing.", "Leadership"),
    ("deliverables/control_workpaper.xlsx", "Control testing workpaper", "Audit-style workpaper: population, exceptions and result per control, with live formulas.", "Auditor"),
    ("deliverables/incident_response_runbook.md", "Incident response runbook", "Step-by-step response for each type of incident.", "Responder"),
    ("incidents.csv", "Incidents (CSV)", "Every incident with severity, priority, technique and evidence.", "Data"),
    ("ip_risk.csv", "Attacker risk scores (CSV)", "Every source IP with its 0 to 100 risk score and its parts.", "Data"),
    ("control_tests.csv", "Basic control checks (CSV)", "Pass, warn or fail checks used on the Controls page.", "Data"),
    ("blocklist.txt", "Blocklist", "Source IPs recommended for blocking.", "Operations"),
    ("fail2ban_jail.local", "fail2ban configuration", "Ready-to-use jail settings that add rate limiting on the server.", "Operations"),
    ("kpis.json", "KPI values (JSON)", "Every headline number in machine-readable form.", "Data"),
    ("forecast_daily.csv", "Daily forecast (CSV)", "Forecast values with lower and upper range.", "Data"),
    ("forecast_hourly.csv", "Hourly forecast (CSV)", "Forecast values with lower and upper range.", "Data"),
]


def reports_dir(meta_: dict, dataset_id: str):
    import os
    from pathlib import Path
    env = os.environ.get("SLA_REPORTS_DIR", "data/reports")
    if env and (Path(env) / dataset_id).exists():
        return Path(env) / dataset_id
    p = Path(meta_.get("reports_dir", ""))
    return p if str(p) and p.exists() else None


def reports(conn, dataset_id: str) -> dict:
    d = reports_dir(meta(conn), dataset_id)
    rows = []
    for rel, title, desc, audience in REPORT_FILES:
        p = d / rel if d else None
        rows.append({"file": rel, "title": title, "description": desc, "audience": audience,
                     "size_bytes": p.stat().st_size if p and p.exists() else None, "available": bool(p and p.exists())})
    return {"rows": rows, "caption": "Reports are generated by the analysis and describe this dataset only. Download any file; nothing is hidden."}
