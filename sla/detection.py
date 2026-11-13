"""Rule-based detection engine. Each rule returns incidents with the same schema so they can
be stored, ranked and reported uniformly. Rules are deliberately simple and explainable:
an analyst can read the evidence column and reproduce the finding with a SQL query."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import DEFAULT, PRIVILEGED_USERS, Config
from .rules import ITIL_PRIORITY, RULES, SEVERITY_RULES

INCIDENT_COLUMNS = ["incident_id", "rule", "title", "technique_id", "severity", "priority", "ip", "username",
                    "start_ts", "end_ts", "attempts", "distinct_users", "distinct_ips", "peak_window_attempts",
                    "targets_privileged", "evidence"]


def failed_attempts(events: pd.DataFrame) -> pd.DataFrame:
    fa = events[events["is_failed_attempt"] & events["ip_resolved"].notna()]
    return fa[["ts", "ip_resolved", "username", "weight", "is_invalid_user"]].rename(columns={"ip_resolved": "ip"})


def _peak_in_window(ts_ns: np.ndarray, w: np.ndarray, window_ns: int) -> int:
    """Max total weight inside any sliding window (ts sorted ascending)."""
    cw = np.concatenate([[0], np.cumsum(w)])
    j = np.searchsorted(ts_ns, ts_ns + window_ns, side="right")
    return int((cw[j] - cw[np.arange(len(ts_ns))]).max())


def _severity_brute_force(attempts: int, peak: int, privileged: bool) -> str:
    r = SEVERITY_RULES["SSH_BRUTE_FORCE"]
    score = 0
    score += 2 if attempts >= r["attempts_2pts"] else 1 if attempts >= r["attempts_1pt"] else 0
    score += 1 if peak >= r["peak_pts"] else 0
    score += 1 if privileged else 0
    return "High" if score >= r["high_at"] else "Medium" if score >= r["medium_at"] else "Low"


def _episodes(fa: pd.DataFrame, cfg: Config) -> pd.DataFrame:
    """Group each IP's failed attempts into episodes separated by quiet gaps."""
    fa = fa.sort_values(["ip", "ts"])
    gap = fa.groupby("ip")["ts"].diff() > pd.Timedelta(minutes=cfg.episode_gap_minutes)
    fa = fa.assign(episode=gap.groupby(fa["ip"]).cumsum().astype(int))
    return fa


def detect_ip_episodes(fa: pd.DataFrame, cfg: Config = DEFAULT) -> list[dict]:
    """Brute force + password spraying, both computed per attacker episode."""
    out: list[dict] = []
    if fa.empty:
        return out
    fa = _episodes(fa, cfg)
    window_ns = int(cfg.bf_window_minutes * 60 * 1e9)
    for (ip, _ep), g in fa.groupby(["ip", "episode"], sort=False):
        ts_ns = g["ts"].values.astype("datetime64[ns]").astype("int64")
        w = g["weight"].values
        attempts = int(w.sum())
        peak = _peak_in_window(ts_ns, w, window_ns)
        users = g["username"].dropna()
        n_users = int(users.nunique())
        priv = bool(users.str.lower().isin(PRIVILEGED_USERS).any())
        start, end = g["ts"].min(), g["ts"].max()
        top_user = users.value_counts().index[0] if n_users else None
        base = dict(ip=ip, start_ts=start, end_ts=end, attempts=attempts, distinct_users=n_users,
                    distinct_ips=1, peak_window_attempts=peak, targets_privileged=priv)
        spray = n_users >= cfg.spray_min_users and attempts / max(n_users, 1) <= cfg.spray_max_attempts_per_user
        if spray:
            sev = "High" if n_users >= SEVERITY_RULES["PASSWORD_SPRAYING"]["high_users"] or priv else "Medium"
            out.append({**base, "rule": "PASSWORD_SPRAYING", "severity": sev, "username": None,
                        "evidence": f"{attempts} attempts across {n_users} usernames "
                                    f"({attempts / n_users:.1f} per user) between {start:%H:%M} and {end:%H:%M}"})
        elif peak >= cfg.bf_min_attempts:
            out.append({**base, "rule": "SSH_BRUTE_FORCE", "severity": _severity_brute_force(attempts, peak, priv),
                        "username": top_user,
                        "evidence": f"{attempts} failed attempts, peak {peak} in {cfg.bf_window_minutes} min, "
                                    f"{n_users} username(s), top target '{top_user}'"})
    return out


def detect_distributed(fa: pd.DataFrame, cfg: Config = DEFAULT) -> list[dict]:
    """One username attacked by many different IPs inside the same hour."""
    out: list[dict] = []
    f = fa.dropna(subset=["username"]).copy()
    if f.empty:
        return out
    f["hour"] = f["ts"].dt.floor("h")
    g = f.groupby(["username", "hour"]).agg(ips=("ip", "nunique"), attempts=("weight", "sum"),
                                            start=("ts", "min"), end=("ts", "max")).reset_index()
    hit = g[(g["ips"] >= cfg.distributed_min_ips) & (g["attempts"] / g["ips"] <= cfg.distributed_max_attempts_per_ip)]
    for user, h in hit.groupby("username"):
        # merge consecutive hours into one incident
        h = h.sort_values("hour")
        block = (h["hour"].diff() > pd.Timedelta(hours=1)).cumsum()
        for _, b in h.groupby(block):
            n_ips = int(f[(f["username"] == user) & (f["hour"] >= b["hour"].min()) & (f["hour"] <= b["hour"].max())]["ip"].nunique())
            attempts = int(b["attempts"].sum())
            priv = user.lower() in PRIVILEGED_USERS
            out.append(dict(rule="DISTRIBUTED_ATTACK", severity="High" if priv or n_ips >= SEVERITY_RULES["DISTRIBUTED_ATTACK"]["high_ips"] else "Medium",
                            ip=None, username=user, start_ts=b["start"].min(), end_ts=b["end"].max(),
                            attempts=attempts, distinct_users=1, distinct_ips=n_ips,
                            peak_window_attempts=int(b["attempts"].max()), targets_privileged=priv,
                            evidence=f"{n_ips} distinct IPs made {attempts} attempts against '{user}'"))
    return out


def detect_success_after_failures(events: pd.DataFrame, fa: pd.DataFrame, cfg: Config = DEFAULT) -> list[dict]:
    out: list[dict] = []
    acc = events[events["is_success"] & events["ip_resolved"].notna()]
    if acc.empty or fa.empty:
        return out
    look = pd.Timedelta(minutes=cfg.compromise_lookback_minutes)
    by_ip = {ip: g for ip, g in fa.groupby("ip")}
    for _, a in acc.iterrows():
        g = by_ip.get(a["ip_resolved"])
        if g is None:
            continue
        prior = g[(g["ts"] <= a["ts"]) & (g["ts"] >= a["ts"] - look)]
        n = int(prior["weight"].sum())
        if n >= cfg.compromise_min_failures:
            priv = str(a["username"]).lower() in PRIVILEGED_USERS
            out.append(dict(rule="SUCCESS_AFTER_FAILURES", severity=SEVERITY_RULES["SUCCESS_AFTER_FAILURES"]["fixed"], ip=a["ip_resolved"],
                            username=a["username"], start_ts=prior["ts"].min(), end_ts=a["ts"], attempts=n,
                            distinct_users=int(prior["username"].nunique()), distinct_ips=1,
                            peak_window_attempts=n, targets_privileged=priv,
                            evidence=f"{n} failures in the {cfg.compromise_lookback_minutes} min before a successful "
                                     f"login as '{a['username']}' ({a['auth_method']})"))
    return out


def detect_recon(events: pd.DataFrame, cfg: Config = DEFAULT) -> list[dict]:
    out: list[dict] = []
    p = events[events["event_type"].isin(["NO_IDENT", "CONN_CLOSED_PREAUTH"]) & events["ip_resolved"].notna()]
    if p.empty:
        return out
    win = pd.Timedelta(minutes=cfg.recon_window_minutes)
    for ip, g in p.groupby("ip_resolved"):
        ts = g["ts"].sort_values().reset_index(drop=True)
        # an IP is a scanner if >= N probes land inside a rolling window
        arr = ts.values.astype("datetime64[ns]").astype("int64")
        j = np.searchsorted(arr, arr + int(win.value), side="right")
        peak = int((j - np.arange(len(arr))).max())
        if peak >= cfg.recon_min_events:
            out.append(dict(rule="RECON_SCAN", severity=SEVERITY_RULES["RECON_SCAN"]["fixed"], ip=ip, username=None, start_ts=ts.min(), end_ts=ts.max(),
                            attempts=len(ts), distinct_users=0, distinct_ips=1, peak_window_attempts=peak,
                            targets_privileged=False,
                            evidence=f"{len(ts)} pre-authentication probes, up to {peak} within {cfg.recon_window_minutes} min"))
    return out


def run_all(events: pd.DataFrame, cfg: Config = DEFAULT) -> pd.DataFrame:
    fa = failed_attempts(events)
    rows = (detect_ip_episodes(fa, cfg) + detect_distributed(fa, cfg)
            + detect_success_after_failures(events, fa, cfg) + detect_recon(events, cfg))
    if not rows:
        return pd.DataFrame(columns=INCIDENT_COLUMNS)
    inc = pd.DataFrame(rows)
    inc["title"] = inc["rule"].map(lambda r: RULES[r]["title"])
    inc["technique_id"] = inc["rule"].map(lambda r: RULES[r]["technique_id"])
    inc["priority"] = inc["severity"].map(ITIL_PRIORITY)
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    inc = inc.sort_values(by=["severity", "attempts"], key=lambda s: s.map(order) if s.name == "severity" else -s)
    inc = inc.reset_index(drop=True)
    inc.insert(0, "incident_id", [f"INC-{i + 1:05d}" for i in range(len(inc))])
    return inc[INCIDENT_COLUMNS]
