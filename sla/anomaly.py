"""Spike detection on hourly volume.

Method: work on log1p(count) so heavy-tailed bursts are tamed; subtract the median of the *same
hour of day* over the previous 7 days (removes the daily cycle); then scale the residual by a
trailing robust spread (1.4826 x median absolute deviation). A spike is a residual above
``anomaly_z`` robust standard deviations AND an absolute volume above ``anomaly_min_count``."""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import DEFAULT, Config


def detect_spikes(hourly: pd.Series, cfg: Config = DEFAULT) -> pd.DataFrame:
    empty = pd.DataFrame(columns=["hour", "attempts", "baseline", "robust_z"])
    if len(hourly) < 24 * 4:
        return empty
    ly = np.log1p(hourly.astype(float))
    base = ly.groupby(ly.index.hour).transform(lambda s: s.shift(1).rolling(7, min_periods=3).median())
    resid = ly - base
    scale = (1.4826 * resid.shift(1).abs().rolling(cfg.anomaly_window_hours, min_periods=48).median()).clip(lower=0.3)
    z = resid / scale
    mask = (z >= cfg.anomaly_z) & (hourly >= cfg.anomaly_min_count)
    return pd.DataFrame({"hour": hourly.index[mask], "attempts": hourly[mask].astype(int).values,
                         "baseline": np.expm1(base[mask]).round(1).values, "robust_z": z[mask].round(1).values})
