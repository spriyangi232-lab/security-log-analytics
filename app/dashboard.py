"""SOC-style dashboard. Run:  streamlit run app/dashboard.py
Reads the SQLite database produced by `python -m sla run ...` (path via sidebar or SLA_DB)."""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sla import db  # noqa: E402
from sla.mitre import RESPONSE_TARGET  # noqa: E402

st.set_page_config(page_title="SSH Security Analytics", page_icon=None, layout="wide")

# Palette from the validated reference set (categorical order fixed; sequential = blue ramp)
BLUE, ORANGE, AQUA, YELLOW, RED = "#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e34948"
INK, MUTED, GRID = "#0b0b0b", "#52514e", "#e6e5e1"
SEV_COLOR = {"Critical": RED, "High": ORANGE, "Medium": YELLOW, "Low": BLUE}
SEV_ORDER = ["Critical", "High", "Medium", "Low"]
BLUE_SEQ = [[0, "#cde2fb"], [0.5, "#3987e5"], [1, "#0d366b"]]

st.markdown("""<style>
.block-container{padding-top:1.4rem;} h1,h2,h3{letter-spacing:-0.01em;}
div[data-testid="stMetric"]{background:#fafaf8;border:1px solid #e6e5e1;border-radius:8px;padding:10px 14px;}
</style>""", unsafe_allow_html=True)


def style(fig: go.Figure, height: int = 340, legend: bool = False) -> go.Figure:
    fig.update_layout(height=height, margin=dict(l=8, r=8, t=56, b=8), paper_bgcolor="white", plot_bgcolor="white",
                      font=dict(color=MUTED, size=12), showlegend=legend, hoverlabel=dict(bgcolor="white", font_color=INK),
                      title=dict(x=0, y=0.97, yanchor="top"),
                      legend=dict(orientation="h", y=1.0, x=1, xanchor="right", yanchor="bottom"))
    fig.update_xaxes(showgrid=False, linecolor=GRID, zeroline=False)
    fig.update_yaxes(gridcolor=GRID, zeroline=False)
    return fig


@st.cache_data(show_spinner=False)
def load(path: str, mtime: float):
    conn = db.connect(path)
    out = {
        "events": pd.read_sql_query("SELECT ts, day, hod, ip_resolved AS ip, username, event_type, weight, is_failed_attempt, is_success, is_invalid_user FROM events", conn, parse_dates=["ts"]),
        "incidents": pd.read_sql_query("SELECT * FROM incidents", conn, parse_dates=["start_ts", "end_ts"]),
        "ip_risk": pd.read_sql_query("SELECT * FROM ip_risk", conn, parse_dates=["first_seen", "last_seen"]),
        "controls": pd.read_sql_query("SELECT * FROM controls", conn),
        "spikes": pd.read_sql_query("SELECT * FROM spikes", conn, parse_dates=["hour"]),
        "kpis": db.read_kpis(conn),
    }
    for name in ("forecast_hourly", "forecast_hourly_metrics", "forecast_daily", "forecast_daily_metrics"):
        try:
            out[name] = pd.read_sql_query(f"SELECT * FROM {name}", conn, parse_dates=["ts"] if "metrics" not in name else None)
        except Exception:
            out[name] = None
    out["hourly"] = pd.read_sql_query("SELECT * FROM hourly_attempts", conn, parse_dates=["hour"])
    out["grc"] = {}
    for name in ("control_matrix", "access_review", "itil_incidents", "itil_problems", "itil_changes"):
        try:
            out["grc"][name] = pd.read_sql_query(f"SELECT * FROM {name}", conn)
        except Exception:
            out["grc"][name] = None
    conn.close()
    return out


# ------------------------------------------------------------------ sidebar
st.sidebar.title("Filters")
db_path = st.sidebar.text_input("Database", os.environ.get("SLA_DB", "data/processed/security.db"))
if not Path(db_path).exists():
    st.title("SSH Security Analytics")
    st.warning(f"Database not found: `{db_path}`. Build it first:")
    st.code("python -m sla run --log data/raw/OpenSSH_full.log --db data/processed/security.db", language="bash")
    st.stop()

D = load(db_path, Path(db_path).stat().st_mtime)
ev, inc, risk, K = D["events"], D["incidents"], D["ip_risk"], D["kpis"]
fa_all = ev[ev["is_failed_attempt"] == 1]

d0, d1 = ev["ts"].min().date(), ev["ts"].max().date()
rng = st.sidebar.date_input("Date range", (d0, d1), min_value=d0, max_value=d1)
lo, hi = (rng[0], rng[1]) if isinstance(rng, (tuple, list)) and len(rng) == 2 else (d0, d1)
sev_sel = st.sidebar.multiselect("Incident severity", SEV_ORDER, default=SEV_ORDER)
rule_opts = sorted(inc["rule"].unique()) if len(inc) else []
rule_sel = st.sidebar.multiselect("Detection rule", rule_opts, default=rule_opts)
tier_sel = st.sidebar.multiselect("IP risk tier", SEV_ORDER, default=SEV_ORDER)
ip_q = st.sidebar.text_input("IP contains")
st.sidebar.caption("Filters apply to every tab except Forecast, which always uses the full history.")

mask = (fa_all["ts"].dt.date >= lo) & (fa_all["ts"].dt.date <= hi)
fa = fa_all[mask]
if ip_q:
    fa = fa[fa["ip"].fillna("").str.contains(ip_q)]
inc_f = inc[(inc["severity"].isin(sev_sel)) & (inc["rule"].isin(rule_sel)) & (inc["start_ts"].dt.date <= hi) & (inc["end_ts"].dt.date >= lo)] if len(inc) else inc
if ip_q and len(inc_f):
    inc_f = inc_f[inc_f["ip"].fillna("").str.contains(ip_q)]
risk_f = risk[risk["risk_tier"].isin(tier_sel)]
if ip_q:
    risk_f = risk_f[risk_f["ip"].str.contains(ip_q)]

# ------------------------------------------------------------------ header + KPIs
st.title("SSH Security Analytics")
st.caption(f"Log period {K['period_start']} to {K['period_end']}  |  {K['log_events']:,} events  |  source database: {db_path}")

total = int(fa["weight"].sum())
_evr = ev[(ev["ts"].dt.date >= lo) & (ev["ts"].dt.date <= hi)]
hours_span = max((_evr["ts"].max() - _evr["ts"].min()).total_seconds() / 3600, 1) if len(_evr) else 1   # first to last log line, as in KPI_DEFINITIONS
success = int(ev[(ev["is_success"] == 1) & (ev["ts"].dt.date >= lo) & (ev["ts"].dt.date <= hi)]["weight"].sum())
by_ip = fa.groupby("ip")["weight"].sum().sort_values(ascending=False)
top10 = 100 * by_ip.head(10).sum() / total if total else 0
c = st.columns(6)
c[0].metric("Failed attempts", f"{total:,}")
c[1].metric("Unique attacker IPs", f"{fa['ip'].nunique():,}")
c[2].metric("Attempts / hour", f"{total / hours_span:,.1f}")
c[3].metric("Top-10 IP share", f"{top10:.1f}%")
c[4].metric("Incidents (High+Critical)", f"{int(inc_f['severity'].isin(['Critical', 'High']).sum()) if len(inc_f) else 0:,}")
c[5].metric("Successful logins", f"{success:,}")

tabs = st.tabs(["Overview", "Attackers", "Targets", "Incidents", "Forecast", "Controls", "Audit and ITIL", "Report"])

# ------------------------------------------------------------------ overview
with tabs[0]:
    a, b = st.columns([3, 2])
    with a:
        hourly = fa.groupby(fa["ts"].dt.floor("h"))["weight"].sum()
        if len(hourly):
            idx = pd.date_range(hourly.index.min(), hourly.index.max(), freq="h")
            hourly = hourly.reindex(idx, fill_value=0)
        fig = go.Figure(go.Scatter(x=hourly.index, y=hourly.values, mode="lines", line=dict(color=BLUE, width=2),
                                   hovertemplate="%{x|%b %d %H:%M}<br>%{y:,} attempts<extra></extra>"))
        sp = D["spikes"][(D["spikes"]["hour"].dt.date >= lo) & (D["spikes"]["hour"].dt.date <= hi)]
        if len(sp):
            fig.add_trace(go.Scatter(x=sp["hour"], y=sp["attempts"], mode="markers", name="Spike",
                                     marker=dict(color=RED, size=9, line=dict(color="white", width=2)),
                                     hovertemplate="Spike %{x|%b %d %H:%M}<br>%{y:,} attempts<extra></extra>"))
        fig.update_layout(title="Failed login attempts per hour (red = anomalous spike)")
        st.plotly_chart(style(fig), width="stretch")
    with b:
        hod = fa.groupby("hod")["weight"].sum().reindex(range(24), fill_value=0)
        fig = go.Figure(go.Bar(x=hod.index, y=hod.values, marker=dict(color=BLUE), hovertemplate="%{x}:00<br>%{y:,} attempts<extra></extra>"))
        fig.update_layout(title="Attempts by hour of day (server time)")
        fig.update_xaxes(dtick=3)
        st.plotly_chart(style(fig), width="stretch")
    hm = fa.groupby(["day", "hod"])["weight"].sum().unstack(fill_value=0).reindex(columns=range(24), fill_value=0)
    if len(hm):
        fig = go.Figure(go.Heatmap(z=hm.values, x=list(range(24)), y=hm.index, colorscale=BLUE_SEQ, xgap=2, ygap=2,
                                   hovertemplate="%{y} at %{x}:00<br>%{z:,} attempts<extra></extra>",
                                   colorbar=dict(title="attempts", thickness=10)))
        fig.update_layout(title="Heatmap: hour of day vs date")
        fig.update_yaxes(autorange="reversed", type="category", gridcolor="white")
        fig.update_xaxes(dtick=3)
        st.plotly_chart(style(fig, height=max(240, 18 * len(hm) + 90)), width="stretch")
    else:
        st.info("No failed attempts in the selected range.")

# ------------------------------------------------------------------ attackers
with tabs[1]:
    a, b = st.columns([3, 2])
    top = risk_f.head(15)
    with a:
        fig = go.Figure(go.Bar(x=top["attempts"][::-1], y=top["ip"][::-1], orientation="h",
                               marker=dict(color=[SEV_COLOR[t] for t in top["risk_tier"][::-1]]),
                               customdata=top[["risk_score", "risk_tier"]][::-1].values,
                               hovertemplate="%{y}<br>%{x:,} attempts<br>risk %{customdata[0]} (%{customdata[1]})<extra></extra>"))
        fig.update_layout(title="Top attacking IPs (bar colour = risk tier)")
        fig.update_yaxes(type="category")
        st.plotly_chart(style(fig, height=460), width="stretch")
        st.caption("Tier colours: Critical red, High orange, Medium yellow, Low blue. Tiers are also stated in the table below.")
    with b:
        if len(by_ip):
            cum = (by_ip.cumsum() / by_ip.sum() * 100).reset_index(drop=True)
            fig = go.Figure(go.Scatter(x=list(range(1, len(cum) + 1)), y=cum, mode="lines", line=dict(color=BLUE, width=2),
                                       hovertemplate="Top %{x} IPs<br>%{y:.1f}% of attempts<extra></extra>"))
            fig.update_layout(title="Concentration: cumulative share of attempts")
            fig.update_xaxes(title="number of IPs (ranked)", type="log")
            fig.update_yaxes(title="% of attempts", range=[0, 101])
            st.plotly_chart(style(fig, height=460), width="stretch")
    show = risk_f[["ip", "risk_score", "risk_tier", "attempts", "distinct_users", "peak_window_attempts", "active_hours", "incidents", "first_seen", "last_seen"]]
    st.dataframe(show, width="stretch", hide_index=True, height=300)
    with st.expander("Why is an IP scored this way?"):
        ip_pick = st.selectbox("IP", risk_f["ip"].head(50).tolist()) if len(risk_f) else None
        if ip_pick:
            row = risk[risk["ip"] == ip_pick].iloc[0]
            comp = {k[2:].title(): row[k] for k in risk.columns if k.startswith("c_")}
            fig = go.Figure(go.Bar(x=list(comp.values()), y=list(comp.keys()), orientation="h", marker=dict(color=BLUE),
                                   hovertemplate="%{y}: %{x} points<extra></extra>"))
            fig.update_layout(title=f"Score components for {ip_pick} (total {row['risk_score']})")
            st.plotly_chart(style(fig, height=280), width="stretch")

# ------------------------------------------------------------------ targets
with tabs[2]:
    a, b = st.columns(2)
    with a:
        u = fa.dropna(subset=["username"]).groupby("username")["weight"].sum().sort_values(ascending=False).head(12)
        fig = go.Figure(go.Bar(x=u.values[::-1], y=u.index[::-1], orientation="h", marker=dict(color=BLUE),
                               hovertemplate="%{y}: %{x:,} attempts<extra></extra>"))
        fig.update_layout(title="Most targeted usernames")
        fig.update_yaxes(type="category")
        st.plotly_chart(style(fig, height=400), width="stretch")
    with b:
        valid = int(fa.loc[fa["is_invalid_user"] == 0, "weight"].sum())
        invalid = int(fa.loc[fa["is_invalid_user"] == 1, "weight"].sum())
        fig = go.Figure(go.Bar(x=["Existing accounts", "Non-existent accounts"], y=[valid, invalid],
                               marker=dict(color=[BLUE, ORANGE]), text=[f"{valid:,}", f"{invalid:,}"], textposition="outside",
                               hovertemplate="%{x}: %{y:,}<extra></extra>"))
        fig.update_layout(title="Attack type split: guessing real vs invalid usernames")
        st.plotly_chart(style(fig, height=400), width="stretch")
    if len(inc_f):
        t = inc_f.groupby("title").size().sort_values()
        fig = go.Figure(go.Bar(x=t.values, y=t.index, orientation="h", marker=dict(color=BLUE), hovertemplate="%{y}: %{x} incidents<extra></extra>"))
        fig.update_layout(title="Incidents by detection rule")
        st.plotly_chart(style(fig, height=70 + 55 * len(t)), width="stretch")

# ------------------------------------------------------------------ incidents
with tabs[3]:
    if len(inc_f):
        st.caption(f"{len(inc_f):,} incidents match the filters. Priority follows ITIL: P1 {RESPONSE_TARGET['P1'].lower()}, P2 {RESPONSE_TARGET['P2'].lower()}.")
        cols = ["incident_id", "priority", "severity", "title", "technique_id", "ip", "username", "start_ts", "end_ts", "attempts", "distinct_users", "distinct_ips", "evidence"]
        st.dataframe(inc_f[cols], width="stretch", hide_index=True, height=520)
        st.download_button("Download incidents (CSV)", inc_f.to_csv(index=False), "incidents.csv", "text/csv")
    else:
        st.info("No incidents match the current filters.")

# ------------------------------------------------------------------ forecast
with tabs[4]:
    O = K.get("outlook", {})
    lvl = O.get("level", "Insufficient data")
    (st.error if lvl == "Rising" else st.warning if lvl in ("Elevated", "Low confidence") else st.info)(O.get("message", f"Risk outlook: {lvl}."))
    fh, fd = D["forecast_hourly"], D["forecast_daily"]
    if fh is not None and len(fh):
        hist = D["hourly"].tail(24 * 7)
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=fh["ts"], y=fh["hi"], mode="lines", line=dict(width=0), showlegend=False, hoverinfo="skip"))
        fig.add_trace(go.Scatter(x=fh["ts"], y=fh["lo"], mode="lines", line=dict(width=0), fill="tonexty", fillcolor="rgba(42,120,214,0.15)",
                                 name="80% interval", hoverinfo="skip"))
        fig.add_trace(go.Scatter(x=hist["hour"], y=hist["attempts"], mode="lines", name="Observed", line=dict(color=INK, width=1.5),
                                 hovertemplate="%{x|%b %d %H:%M}<br>%{y:,} observed<extra></extra>"))
        fig.add_trace(go.Scatter(x=fh["ts"], y=fh["yhat"], mode="lines", name="Forecast", line=dict(color=BLUE, width=2),
                                 hovertemplate="%{x|%b %d %H:%M}<br>%{y:,.0f} forecast<extra></extra>"))
        fig.update_layout(title="Next 72 hours: failed attempts per hour (last 7 days observed)")
        st.plotly_chart(style(fig, height=380, legend=True), width="stretch")
    if fd is not None and len(fd):
        dh = D["hourly"].set_index("hour")["attempts"].resample("D").sum().tail(21)
        fig = go.Figure()
        fig.add_trace(go.Bar(x=dh.index, y=dh.values, name="Observed", marker=dict(color=INK), hovertemplate="%{x|%b %d}<br>%{y:,} observed<extra></extra>"))
        fig.add_trace(go.Bar(x=fd["ts"], y=fd["yhat"], name="Forecast", marker=dict(color=BLUE),
                             error_y=dict(type="data", symmetric=False, array=fd["hi"] - fd["yhat"], arrayminus=fd["yhat"] - fd["lo"], color=MUTED),
                             hovertemplate="%{x|%b %d}<br>%{y:,.0f} forecast<extra></extra>"))
        fig.update_layout(title="Next 7 days: daily failed attempts", barmode="group")
        st.plotly_chart(style(fig, height=340, legend=True), width="stretch")
    if fh is None and fd is None:
        st.info("The log is too short to forecast (needs at least 7 days). Run the pipeline on the full Loghub OpenSSH log.")
    for label, m in (("Hourly model backtest", D["forecast_hourly_metrics"]), ("Daily model backtest", D["forecast_daily_metrics"])):
        if m is not None and len(m):
            st.markdown(f"**{label}** (rolling-origin, lower MAE is better; `skill_vs_naive_pct` > 0 means it beats the seasonal-naive baseline)")
            st.dataframe(m, width="stretch", hide_index=True)

# ------------------------------------------------------------------ controls
with tabs[5]:
    ctl = D["controls"]
    icon = {"PASS": "PASS", "WARN": "WARN", "FAIL": "FAIL"}
    counts = ctl["status"].value_counts()
    st.write("  |  ".join(f"{s}: {int(counts.get(s, 0))}" for s in ("FAIL", "WARN", "PASS")))
    st.dataframe(ctl[["control_id", "control", "status", "evidence", "recommendation", "reference"]], width="stretch", hide_index=True)

# ------------------------------------------------------------------ audit and ITIL
with tabs[6]:
    G = D["grc"]
    if G["control_matrix"] is None:
        st.info("Re-run the pipeline to generate the audit and ITIL tables.")
    else:
        cm = G["control_matrix"]
        RES_FILL = {"Ineffective": "#f8d7d3", "Partially effective": "#fce8c3", "Effective": "#d5eedd", "Not tested": "#e4e7eb"}
        st.subheader("Control test matrix")
        st.caption("Audit-style tests from log evidence. A control with no population is Not tested, never Effective.")
        st.dataframe(cm[["control_id", "domain", "control_objective", "population", "exceptions", "result", "evidence", "framework_reference"]]
                     .style.map(lambda v: f"background-color: {RES_FILL.get(v, 'white')}", subset=["result"]), width="stretch", hide_index=True)
        st.subheader("Access review")
        st.dataframe(G["access_review"], width="stretch", hide_index=True, height=280)
        a, b = st.columns(2)
        with a:
            st.subheader("ITIL problem register")
            st.dataframe(G["itil_problems"][["problem_id", "title", "linked_incidents", "highest_priority", "status"]], width="stretch", hide_index=True)
        with b:
            st.subheader("Proposed changes")
            st.dataframe(G["itil_changes"][["change_id", "description", "change_type", "risk", "status"]], width="stretch", hide_index=True)
        st.subheader("ITIL incident register (SLA due times)")
        st.dataframe(G["itil_incidents"][["incident_id", "priority", "subcategory", "source", "detected_at", "response_due", "resolution_due", "status", "linked_problem"]],
                     width="stretch", hide_index=True, height=320)
        dl = Path(db_path).resolve().parent.parent / "reports" / "deliverables" / "control_workpaper.xlsx"
        if dl.exists():
            st.download_button("Download Excel control workpaper", dl.read_bytes(), "control_workpaper.xlsx")

# ------------------------------------------------------------------ report
with tabs[7]:
    rp = Path(db_path).resolve().parent.parent / "reports" / "incident_report.md"
    cand = [rp, Path("reports/incident_report.md"), Path("reports/demo/incident_report.md")]
    found = next((p for p in cand if p.exists()), None)
    if found:
        txt = found.read_text(encoding="utf-8")
        st.download_button("Download report (Markdown)", txt, "incident_report.md")
        st.markdown(txt)
    else:
        st.info("Run the pipeline to generate reports/incident_report.md.")
