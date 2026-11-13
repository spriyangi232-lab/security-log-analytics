"""Security KPIs. Every KPI has a precise definition (see docs/KPI_DEFINITIONS.md)."""
from __future__ import annotations

import numpy as np
import pandas as pd
from scipy import stats

from .config import DEFAULT, Config
from .detection import failed_attempts


def hourly_attempts(events: pd.DataFrame) -> pd.Series:
    """Failed attempts per hour on a gap-free hourly index (zeros where nothing happened)."""
    fa = failed_attempts(events)
    if fa.empty:
        return pd.Series(dtype=float, name="attempts")
    s = fa.groupby(fa["ts"].dt.floor("h"))["weight"].sum()
    idx = pd.date_range(events["ts"].min().floor("h"), events["ts"].max().floor("h"), freq="h")
    return s.reindex(idx, fill_value=0).rename("attempts")


def complete_hours(events: pd.DataFrame, min_covered_minutes: int = 55) -> pd.Series:
    """Hourly attempts for modelling: drops a partial first or last hour. A log that starts at 06:55 or
    ends at 17:22 holds only part of those hours, and a part-hour looks like a collapse in volume to a
    forecasting model. An edge hour is kept only if the log covers at least `min_covered_minutes` of it."""
    s = hourly_attempts(events)
    if s.empty:
        return s
    t0, t1 = events["ts"].min(), events["ts"].max()
    if len(s) and (60 - t0.minute) < min_covered_minutes:      # minutes of the first hour covered
        s = s.iloc[1:]
    if len(s) and (t1.minute + 1) < min_covered_minutes:       # minutes of the last hour covered
        s = s.iloc[:-1]
    return s


def compute_kpis(events: pd.DataFrame, ip_risk: pd.DataFrame, incidents: pd.DataFrame, cfg: Config = DEFAULT) -> dict:
    fa = failed_attempts(events)
    total = int(fa["weight"].sum())
    success = int(events.loc[events["is_success"], "weight"].sum())
    hours = hourly_attempts(events)
    # documented definition: hours between the first and last log line (not the number of hourly buckets)
    span_h = max((events["ts"].max() - events["ts"].min()).total_seconds() / 3600, 1)
    k: dict = {
        "log_events": int(len(events)),
        "period_start": str(events["ts"].min()), "period_end": str(events["ts"].max()),
        "failed_attempts": total, "successful_logins": success,
        "failed_login_rate_pct": round(100 * total / max(total + success, 1), 2),
        "unique_attacker_ips": int(fa["ip"].nunique()),
        "attempts_per_hour_mean": round(total / span_h, 2),
        "attempts_per_hour_peak": int(hours.max()) if len(hours) else 0,
        "peak_hour": str(hours.idxmax()) if len(hours) else None,
        "incidents_total": int(len(incidents)),
        "incidents_critical_high": int(incidents["severity"].isin(["Critical", "High"]).sum()) if len(incidents) else 0,
    }
    if total:
        by_ip = fa.groupby("ip")["weight"].sum().sort_values(ascending=False)
        k["top10_ip_share_pct"] = round(100 * by_ip.head(10).sum() / total, 1)
        cum = by_ip.cumsum() / total
        k["ips_for_50pct"] = int((cum < 0.5).sum() + 1)
        k["ips_for_80pct"] = int((cum < 0.8).sum() + 1)
        k["median_attempts_per_ip"] = float(by_ip.median())
        k["invalid_user_share_pct"] = round(100 * fa.loc[fa["is_invalid_user"], "weight"].sum() / total, 1)
        users = fa.dropna(subset=["username"]).groupby("username")["weight"].sum().sort_values(ascending=False)
        k["top_usernames"] = {str(u): int(v) for u, v in users.head(10).items()}
        k["root_admin_share_pct"] = round(100 * users[users.index.str.lower().isin(["root", "admin"])].sum() / total, 1)
        hod = fa.groupby(fa["ts"].dt.hour)["weight"].sum().reindex(range(24), fill_value=0)
        night = int(hod[list(cfg.night_hours)].sum())
        expected = len(cfg.night_hours) / 24
        k["night_share_pct"] = round(100 * night / total, 1)
        k["night_expected_pct"] = round(100 * expected, 1)
        k["night_lift"] = round((night / total) / expected, 2)
        # exact binomial test vs the uniform-hours null; with hour-level data it is almost always
        # significant, so we report the lift (effect size) alongside the p-value.
        k["night_binom_p"] = float(stats.binomtest(min(night, total), total, expected).pvalue) if total < 5_000_000 else None
        by_hour = {int(h): int(v) for h, v in hod.items()}
        k["attempts_by_hour_of_day"] = by_hour
    return k
