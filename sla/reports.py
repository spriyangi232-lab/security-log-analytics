"""Plain-language incident report, recommendations and ready-to-use response artefacts
(IP block list, fail2ban jail). Every sentence is generated from the computed results, so the
report can never drift from the data."""
from __future__ import annotations

from datetime import datetime

import pandas as pd

from .config import DEFAULT, Config
from .mitre import RESPONSE_TARGET, RULES

MIN_HOURS_FOR_TIME_CLAIMS = 72


def ip_phrase(n: int) -> str:
    return f"{n} IP address accounts" if n == 1 else f"{n} IP addresses account"


def _fmt(n) -> str:
    return f"{int(n):,}"


def _md_table(df: pd.DataFrame) -> str:
    if df.empty:
        return "_None._"
    head = "| " + " | ".join(df.columns) + " |\n|" + "|".join("---" for _ in df.columns) + "|\n"
    body = "\n".join("| " + " | ".join("" if pd.isna(v) else str(v) for v in row) + " |" for row in df.itertuples(index=False))
    return head + body


def coverage_hours(kpis: dict) -> float:
    return (pd.Timestamp(kpis["period_end"]) - pd.Timestamp(kpis["period_start"])).total_seconds() / 3600


def executive_summary(k: dict, incidents: pd.DataFrame, outlook: dict) -> str:
    hrs = coverage_hours(k)
    span = f"{hrs / 24:.1f} days" if hrs >= 48 else f"{hrs:.1f} hours"
    parts = [f"Over {span} of SSH logs ({_fmt(k['log_events'])} events) the server received {_fmt(k['failed_attempts'])} failed "
             f"password attempts from {_fmt(k['unique_attacker_ips'])} distinct IP addresses, against {_fmt(k['successful_logins'])} successful login(s)."]
    if k.get("ips_for_50pct"):
        parts.append(f"Activity is highly concentrated: {ip_phrase(k['ips_for_50pct'])} for half of all attempts and "
                     f"{k['ips_for_80pct']} for 80%, so targeted blocking is effective.")
    lead = "Attackers overwhelmingly guess privileged usernames" if k["root_admin_share_pct"] >= 50 else "Privileged usernames are a common target"
    parts.append(f"{lead}: root and admin make up {k['root_admin_share_pct']}% of attempts.")
    n_crit = int((incidents["severity"] == "Critical").sum()) if len(incidents) else 0
    n_high = int((incidents["severity"] == "High").sum()) if len(incidents) else 0
    if n_crit:
        parts.append(f"**{n_crit} incident(s) indicate a possible account compromise (a login succeeded after repeated failures) and need immediate review.**")
    else:
        parts.append("No login succeeded after a run of failures, so there is no evidence of a compromised account in this period.")
    parts.append(f"{n_high} incident(s) are rated High.")
    if outlook.get("ratio") is not None:
        parts.append(outlook["message"])
    return " ".join(parts)


def key_findings(k: dict, incidents: pd.DataFrame) -> list[str]:
    f = []
    f.append(f"**Concentration.** The top 10 IPs generate {k['top10_ip_share_pct']}% of all failed attempts; the median attacking IP makes only {k['median_attempts_per_ip']:.0f}, "
             "so a few persistent sources sit on top of a long tail of one-off probes.")
    top = list(k["top_usernames"].items())[:3]
    f.append("**Targeted accounts.** Most-guessed usernames: " + ", ".join(f"`{u}` ({_fmt(n)})" for u, n in top) + ".")
    f.append(f"**Account enumeration.** {k['invalid_user_share_pct']}% of attempts target usernames that do not exist on the server, which is the signature of automated dictionary attacks rather than users mistyping.")
    if coverage_hours(k) >= MIN_HOURS_FOR_TIME_CLAIMS:
        f.append(f"**Timing.** {k['night_share_pct']}% of attempts fall between 22:00 and 05:59 (server time), versus {k['night_expected_pct']}% expected if activity were uniform "
                 f"({k['night_lift']}x). Peak hour: {k['peak_hour']} with {_fmt(k['attempts_per_hour_peak'])} attempts.")
    else:
        f.append(f"**Timing.** Only {coverage_hours(k):.1f} hours of logs are available, which is too short to make a reliable time-of-day statement. Peak hour: {k['peak_hour']} with {_fmt(k['attempts_per_hour_peak'])} attempts.")
    if len(incidents):
        by = incidents.groupby("rule").size().sort_values(ascending=False)
        f.append("**Detections.** " + "; ".join(f"{RULES[r]['title']}: {n}" for r, n in by.items()) + ".")
    return f


def recommendations(k: dict, risk: pd.DataFrame, incidents: pd.DataFrame, controls: pd.DataFrame) -> list[tuple[str, str]]:
    recs: list[tuple[str, str]] = []
    n_comp = int((incidents["rule"] == "SUCCESS_AFTER_FAILURES").sum()) if len(incidents) else 0
    if n_comp:
        who = ", ".join(sorted(set(incidents.loc[incidents["rule"] == "SUCCESS_AFTER_FAILURES", "username"].dropna().astype(str))))
        recs.append(("Immediate", f"Investigate and reset credentials for account(s) {who}; review their sessions since the first failed attempt."))
    blk = risk[risk["risk_tier"].isin(["Critical", "High"])] if len(risk) else risk
    if len(blk):
        share = 100 * blk["attempts"].sum() / max(k["failed_attempts"], 1)
        recs.append(("Immediate", f"Block the {len(blk)} High/Critical-risk IPs in `blocklist.txt`; together they produced {share:.0f}% of failed attempts. Verify none is a shared/NAT address before enforcing."))
    recs.append(("Short term", "Alert after 5 failed logins from one IP in 5 minutes and ban automatically (see `fail2ban_jail.local`)."))
    if k["root_admin_share_pct"] >= 20:
        recs.append(("Short term", "Disable direct root login (`PermitRootLogin no`) and use named accounts with sudo; root/admin are the dominant targets."))
    recs.append(("Short term", "Move to key-based authentication or MFA and disable password login (`PasswordAuthentication no`); this removes the attack surface these attempts are aimed at."))
    if len(incidents) and (incidents["rule"] == "DISTRIBUTED_ATTACK").any():
        recs.append(("Short term", "A distributed attack was seen; per-IP blocking alone will not stop it. Add account-level throttling and restrict SSH to a VPN or allow-list."))
    failing = controls[controls["status"] == "FAIL"]["control_id"].tolist() if len(controls) else []
    if failing:
        recs.append(("Governance", f"Remediate failed control test(s) {', '.join(failing)} and re-run this assessment to evidence the improvement."))
    recs.append(("Governance", "Forward these alerts to the SIEM / ticketing queue and review thresholds monthly against the false-positive rate."))
    return recs


def build_report(k, incidents, risk, controls, results, outlook, spikes, cfg: Config = DEFAULT, source: str = "") -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    L = [f"# SSH Security Log Analysis: Incident Report",
         f"_Source: {source or 'sshd logs'} | Period: {k['period_start']} to {k['period_end']} | Generated: {now}_", "",
         "## 1. Executive summary", executive_summary(k, incidents, outlook), "", "## 2. Key findings"]
    L += [f"{i}. {t}" for i, t in enumerate(key_findings(k, incidents), 1)]
    L += ["", "## 3. Priority incidents (top 10)"]
    if len(incidents):
        t = incidents.head(10).copy()
        t["source"] = t["ip"].fillna("multiple IPs") + t["username"].fillna("").map(lambda u: f" / {u}" if u else "")
        t["window"] = pd.to_datetime(t["start_ts"]).dt.strftime("%m-%d %H:%M") + " to " + pd.to_datetime(t["end_ts"]).dt.strftime("%H:%M")
        t["response"] = t["priority"].map(RESPONSE_TARGET)
        L.append(_md_table(t[["incident_id", "priority", "title", "technique_id", "source", "window", "attempts", "response"]]))
    else:
        L.append("_No incidents detected._")
    L += ["", "## 4. Top attackers by risk score"]
    if len(risk):
        r = risk.head(10)[["ip", "attempts", "distinct_users", "peak_window_attempts", "risk_score", "risk_tier"]]
        L.append(_md_table(r))
        L.append("\n_Risk score (0-100) = weighted volume, burst intensity, username breadth, persistence, privileged-account targeting and invalid-user share. Component points per IP are in `ip_risk.csv`._")
    L += ["", "## 5. IT control assessment", _md_table(controls[["control_id", "control", "status", "evidence"]]), "",
          "## 6. Forecast and risk outlook"]
    h, d = results.get("hourly"), results.get("daily")
    if h is not None and h.status == "ok":
        L.append(outlook["message"])
        L.append(f"\nHourly model: **{h.model}** (backtest MAE {h.metrics.iloc[0]['MAE']:.1f} attempts/hour; {h.skill_vs_baseline:+.1f}% vs a seasonal-naive baseline). "
                 f"Intervals are {int(cfg.interval_coverage * 100)}% empirical backtest intervals.")
        if d is not None and d.status == "ok":
            fc = d.forecast.copy(); fc["ts"] = fc["ts"].dt.strftime("%Y-%m-%d")
            L.append("\nNext 7 days (daily model: **" + d.model + f"**, {d.skill_vs_baseline:+.1f}% vs naive):\n")
            L.append(_md_table(fc.rename(columns={"ts": "date", "yhat": "forecast", "lo": "low", "hi": "high"}).round(0).astype({"forecast": int, "low": int, "high": int})))
    else:
        L.append(f"Forecast not produced: {h.status if h else 'no data'}. A reliable forecast needs at least 7 days of logs.")
    if len(spikes):
        L.append(f"\n{len(spikes)} anomalous hourly spike(s) were detected; the largest was {_fmt(spikes['attempts'].max())} attempts at {spikes.sort_values('attempts').iloc[-1]['hour']}.")
    L += ["", "## 7. Recommendations"]
    for tier in ("Immediate", "Short term", "Governance"):
        items = [t for g, t in recommendations(k, risk, incidents, controls) if g == tier]
        if items:
            L.append(f"**{tier}**")
            L += [f"- {t}" for t in items]
            L.append("")
    L += ["## 8. Method, assumptions and limitations",
          "- A failed attempt is one `Failed password` line (repeat-compressed lines expanded); PAM and pre-auth lines are never double counted.",
          "- Syslog has no year; the year is a parameter and rolls over on a December to January wrap.",
          "- Rules and thresholds are in `sla/config.py`; they are heuristics tuned for SSH on a single host, not universal constants.",
          "- IP address does not equal person: NAT, proxies and botnets mean blocking should be reviewed before enforcement.",
          "- Forecasts describe likely volume given past behaviour; they cannot predict a new campaign starting."]
    return "\n".join(L) + "\n"


def blocklist(risk: pd.DataFrame) -> str:
    ips = risk[risk["risk_tier"].isin(["Critical", "High"])]["ip"].tolist() if len(risk) else []
    return ("# High/Critical risk source IPs. Review for shared/NAT addresses before blocking.\n" + "\n".join(ips) + "\n")


FAIL2BAN = """# Drop into /etc/fail2ban/jail.local  (thresholds mirror the detection rule: 5 failures / 5 minutes)
[sshd]
enabled  = true
port     = ssh
maxretry = 5
findtime = 5m
bantime  = 24h
"""
