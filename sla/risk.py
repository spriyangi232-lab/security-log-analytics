"""Explainable per-IP risk score (0-100). Each component is normalised to 0-1 and weighted;
weights live in config.py. A confirmed success-after-failures forces the Critical tier."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import DEFAULT, PRIVILEGED_USERS, Config
from .detection import failed_attempts
from .rules import COMPROMISE_SCORE_FLOOR, RISK_PARAMS


def ip_profile(events: pd.DataFrame, incidents: pd.DataFrame, cfg: Config = DEFAULT) -> pd.DataFrame:
    fa = failed_attempts(events)
    if fa.empty:
        return pd.DataFrame(columns=["ip", "attempts", "risk_score", "risk_tier"])
    fa = fa.assign(hour=fa["ts"].dt.floor("h"),
                   priv=fa["username"].fillna("").str.lower().isin(PRIVILEGED_USERS),
                   w_inv=fa["weight"] * fa["is_invalid_user"], w_priv=fa["weight"] * fa["username"].fillna("").str.lower().isin(PRIVILEGED_USERS))
    g = fa.groupby("ip").agg(attempts=("weight", "sum"), first_seen=("ts", "min"), last_seen=("ts", "max"),
                             active_hours=("hour", "nunique"), distinct_users=("username", "nunique"),
                             invalid_w=("w_inv", "sum"), priv_w=("w_priv", "sum")).reset_index()
    g["invalid_share"] = g["invalid_w"] / g["attempts"]
    g["privileged_share"] = g["priv_w"] / g["attempts"]
    peak = (incidents.groupby("ip")["peak_window_attempts"].max() if not incidents.empty else pd.Series(dtype=float))
    g["peak_window_attempts"] = g["ip"].map(peak).fillna(1).astype(int)
    compromised = set(incidents.loc[incidents["rule"] == "SUCCESS_AFTER_FAILURES", "ip"]) if not incidents.empty else set()
    g["compromise_flag"] = g["ip"].isin(compromised)
    n_inc = incidents.groupby("ip").size() if not incidents.empty else pd.Series(dtype=int)
    g["incidents"] = g["ip"].map(n_inc).fillna(0).astype(int)

    volume = np.minimum(1, np.log10(1 + g["attempts"]) / np.log10(1 + RISK_PARAMS["volume_ref_attempts"]))
    intensity = np.minimum(1, g["peak_window_attempts"] / RISK_PARAMS["intensity_ref_window_attempts"])
    breadth = np.minimum(1, g["distinct_users"] / RISK_PARAMS["breadth_ref_users"])
    persistence = np.minimum(1, g["active_hours"] / RISK_PARAMS["persistence_ref_hours"])
    comp = {"volume": volume, "intensity": intensity, "breadth": breadth, "persistence": persistence,
            "privileged": g["privileged_share"], "invalid": g["invalid_share"]}
    weights = {"volume": cfg.w_volume, "intensity": cfg.w_intensity, "breadth": cfg.w_breadth,
               "persistence": cfg.w_persistence, "privileged": cfg.w_privileged, "invalid": cfg.w_invalid}
    score = sum(comp[k] * weights[k] for k in comp) * 100
    score = np.where(g["compromise_flag"], np.maximum(score, COMPROMISE_SCORE_FLOOR), score)
    g["risk_score"] = np.round(score, 1)
    g["risk_tier"] = pd.cut(g["risk_score"], [-1, cfg.tier_medium, cfg.tier_high, cfg.tier_critical, 101],
                            labels=["Low", "Medium", "High", "Critical"], right=False).astype(str)
    for k, v in comp.items():
        g[f"c_{k}"] = np.round(v * weights[k] * 100, 1)   # points contributed, so the score is explainable
    return g.drop(columns=["invalid_w", "priv_w"]).sort_values("risk_score", ascending=False).reset_index(drop=True)
