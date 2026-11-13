"""Risk forecasting with honest evaluation.

For each series (hourly and daily) several candidate models compete in a rolling-origin
backtest against simple baselines. The winner (lowest MAE) produces the forecast, and its
prediction interval comes from the *empirical* backtest errors, so the band reflects how
wrong the model has actually been rather than an assumed distribution. If no model beats
the seasonal-naive baseline, the baseline is used and the report says so.
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from statsmodels.tsa.holtwinters import ExponentialSmoothing
from statsmodels.tsa.statespace.sarimax import SARIMAX

from .config import DEFAULT, Config

warnings.filterwarnings("ignore")


# ---- candidate models: each takes (train: np.ndarray, h: int, season: int) -> np.ndarray --------
def m_seasonal_naive(y, h, s):
    if len(y) < s:
        return np.repeat(y[-1], h)
    return np.resize(y[-s:], h)


def m_mean_profile(y, h, s):
    """Average of the last few seasons, position by position (e.g. mean hour-of-day profile)."""
    k = min(len(y) // s, 7)
    if k < 1:
        return np.repeat(y.mean(), h)
    prof = y[len(y) - k * s:].reshape(k, s).mean(axis=0)
    return np.resize(prof, h)


def m_ets(y, h, s):
    ly = np.log1p(y)
    seasonal = "add" if len(y) >= 2 * s and s > 1 else None
    fit = ExponentialSmoothing(ly, trend="add", damped_trend=True, seasonal=seasonal,
                               seasonal_periods=s if seasonal else None, initialization_method="estimated").fit()
    return np.expm1(fit.forecast(h))


def m_sarima(y, h, s):
    ly = np.log1p(y)
    seas = (1, 1, 0, s) if (s > 1 and len(y) >= 3 * s) else (0, 0, 0, 0)
    order = (1, 0, 1) if s > 1 else (1, 1, 1)
    fit = SARIMAX(ly, order=order, seasonal_order=seas, enforce_stationarity=False,
                  enforce_invertibility=False).fit(disp=False, maxiter=50)
    return np.expm1(fit.forecast(h))


MODELS = {"seasonal_naive": m_seasonal_naive, "mean_profile": m_mean_profile, "ets": m_ets, "sarima": m_sarima}


@dataclass
class ForecastResult:
    freq: str
    status: str                       # "ok" or a reason the forecast was skipped
    model: str | None = None
    metrics: pd.DataFrame = field(default_factory=pd.DataFrame)
    forecast: pd.DataFrame = field(default_factory=pd.DataFrame)   # ts, yhat, lo, hi
    skill_vs_baseline: float | None = None


def _safe(fn, y, h, s):
    try:
        out = np.clip(np.asarray(fn(y, h, s), dtype=float), 0, None)
        return out if np.all(np.isfinite(out)) else None
    except Exception:
        return None


def forecast_series(series: pd.Series, freq: str, season: int, horizon: int, test_h: int,
                    min_len: int, cfg: Config = DEFAULT) -> ForecastResult:
    y = series.astype(float).values
    if len(y) < min_len:
        return ForecastResult(freq, f"not enough history ({len(y)} {freq} points, need {min_len})")
    folds = cfg.backtest_folds
    origins = [len(y) - test_h * (folds - i) for i in range(folds)]
    origins = [o for o in origins if o >= max(min_len - test_h, season + 1)]
    if not origins:
        return ForecastResult(freq, "not enough history for a backtest")

    errs: dict[str, list[np.ndarray]] = {m: [] for m in MODELS}
    for o in origins:
        actual = y[o:o + test_h]
        for name, fn in MODELS.items():
            pred = _safe(fn, y[:o], len(actual), season)
            if pred is not None:
                errs[name].append(actual - pred)
    rows = []
    for name, e in errs.items():
        if len(e) == len(origins):
            cat = np.concatenate(e)
            rows.append({"model": name, "MAE": float(np.abs(cat).mean()), "RMSE": float(np.sqrt((cat ** 2).mean())),
                         "bias": float(cat.mean()), "folds": len(e)})
    if not rows:
        return ForecastResult(freq, "all models failed to fit")
    metrics = pd.DataFrame(rows).sort_values("MAE").reset_index(drop=True)
    base = float(metrics.loc[metrics["model"] == "seasonal_naive", "MAE"].iloc[0])
    metrics["skill_vs_naive_pct"] = (100 * (1 - metrics["MAE"] / base)).round(1) if base > 0 else 0.0
    best = metrics.loc[0, "model"]

    point = _safe(MODELS[best], y, horizon, season)
    if point is None:
        best, point = "seasonal_naive", m_seasonal_naive(y, horizon, season)
    resid = np.concatenate(errs[best]) if errs.get(best) else np.zeros(1)
    lo_q, hi_q = np.quantile(resid, [(1 - cfg.interval_coverage) / 2, 1 - (1 - cfg.interval_coverage) / 2])
    step = pd.Timedelta(hours=1) if freq == "hourly" else pd.Timedelta(days=1)
    idx = pd.date_range(series.index[-1] + step, periods=horizon, freq="h" if freq == "hourly" else "D")
    fc = pd.DataFrame({"ts": idx, "yhat": point, "lo": np.clip(point + lo_q, 0, None), "hi": point + hi_q})
    skill = float(metrics.loc[metrics["model"] == best, "skill_vs_naive_pct"].iloc[0])
    fc[["yhat", "lo", "hi"]] = fc[["yhat", "lo", "hi"]].round(1)
    return ForecastResult(freq, "ok", best, metrics.round(2), fc, skill)


def complete_days(hourly: pd.Series) -> pd.Series:
    """Daily totals for days that have all 24 hourly points. A partial first or last day would drag
    the series down and bias the daily forecast, so it is excluded."""
    if not len(hourly):
        return hourly
    full = hourly.resample("D").count() == 24
    return hourly.resample("D").sum()[full]


def run_forecasts(hourly: pd.Series, cfg: Config = DEFAULT) -> dict[str, ForecastResult]:
    daily = complete_days(hourly)
    # if the last observed day is incomplete, the first daily forecast point would be a part-observed day:
    # forecast one extra day and drop it so the daily forecast starts on the first day with no data at all
    partial_last_day = len(hourly) > 0 and hourly.index[-1].hour != 23
    d = forecast_series(daily, "daily", 7, cfg.daily_horizon + int(partial_last_day), 3, min_len=14, cfg=cfg)
    if partial_last_day and d.status == "ok" and len(d.forecast) > 1:
        d.forecast = d.forecast.iloc[1:].reset_index(drop=True)
    return {
        "hourly": forecast_series(hourly, "hourly", 24, cfg.hourly_horizon, 24, min_len=24 * 7, cfg=cfg),
        "daily": d,
    }


def _confidence(hourly, h, d, nxt, recent24, cfg) -> tuple[str, list[str]]:
    """Judge whether the forecast deserves to drive a risk call. Returns (High/Medium/Low, reasons)."""
    why = []
    lo_b, hi_b = cfg.outlook_runrate_band
    if recent24 > 0 and not (lo_b <= nxt / recent24 <= hi_b):
        why.append(f"the forecast ({nxt:,.0f}) is far from the actual volume of the last 24 hours ({recent24:,.0f})")
    if h.skill_vs_baseline is not None and h.skill_vs_baseline < cfg.outlook_min_skill_pct:
        why.append(f"the best hourly model beats the naive baseline by only {h.skill_vs_baseline:.0f}%")
    hi24 = float(h.forecast["hi"].iloc[:24].sum())
    if nxt > 0 and hi24 / nxt > cfg.outlook_interval_ratio:
        why.append("the 80% prediction interval is very wide compared with the forecast")
    if d is not None and d.status == "ok" and len(d.forecast):
        dn = float(d.forecast["yhat"].iloc[0])
        lo_a, hi_a = cfg.outlook_model_agree
        if dn > 0 and nxt > 0 and not (lo_a <= nxt / dn <= hi_a):
            why.append(f"the hourly forecast ({nxt:,.0f}/day) and daily forecast ({dn:,.0f}/day) disagree")
    if why:
        return "Low", why
    return ("High" if (h.skill_vs_baseline or 0) >= cfg.outlook_good_skill_pct else "Medium"), []


def risk_outlook(hourly: pd.Series, results: dict[str, ForecastResult], cfg: Config = DEFAULT) -> dict:
    """Plain-language risk level from the next-24h forecast vs the recent norm, with an honest confidence.
    When the forecast fails its own sanity checks the level is "Low confidence" and the message reports
    observed volumes instead of a trend, so a weak model never produces a confident headline."""
    h = results.get("hourly")
    if h is None or h.status != "ok" or len(hourly) < 24 * 7:
        return {"level": "Insufficient data", "ratio": None, "next24h": None, "baseline_daily": None,
                "confidence": None, "reasons": [],
                "message": "Not enough history to forecast; need at least 7 days of logs."}
    nxt = float(h.forecast["yhat"].iloc[:24].sum())
    daily_hist = complete_days(hourly)
    base = float(daily_hist.tail(7).mean())
    recent24 = float(hourly.tail(24).sum())
    p90 = float(daily_hist.quantile(0.9))
    ratio = nxt / base if base > 0 else float("inf")
    conf, why = _confidence(hourly, h, results.get("daily"), nxt, recent24, cfg)
    out = {"ratio": round(ratio, 2), "next24h": round(nxt), "baseline_daily": round(base),
           "last24h": round(recent24), "confidence": conf, "reasons": why}
    if conf == "Low":
        out["level"] = "Low confidence"
        out["headline"] = "Forecast confidence is low, so no trend is claimed"
        out["message"] = (f"The forecast is not reliable enough to call a trend: {'; '.join(why)}. "
                          f"The last 24 hours had {recent24:,.0f} failed logins and the previous 7-day average is {base:,.0f} per day. "
                          f"Risk outlook: Low confidence.")
        return out
    level = "Rising" if ratio >= 1.5 else "Elevated" if ratio >= 1.15 else "Falling" if ratio <= 0.85 else "Stable"
    if nxt >= p90 and level in ("Stable", "Falling"):
        level = "Elevated"
    out["level"] = level
    out["headline"] = f"Next 24 hours: {level.lower()} risk, {ratio:.1f}x the 7-day average"
    out["message"] = (f"Forecast for the next 24 hours is about {nxt:,.0f} failed logins, {ratio:.2f}x the average of the previous 7 days "
                      f"({base:,.0f} per day). Risk outlook: {level} (confidence: {conf}).")
    return out
