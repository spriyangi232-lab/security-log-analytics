import numpy as np
import pandas as pd

from sla import anomaly, forecast


def _series(days=21, seed=0):
    idx = pd.date_range("2026-01-01", periods=24 * days, freq="h")
    rng = np.random.default_rng(seed)
    base = 20 + 15 * np.sin(2 * np.pi * (idx.hour - 3) / 24)
    return pd.Series(rng.poisson(np.clip(base, 1, None)), index=idx, name="attempts").astype(float)


def test_forecast_shape_intervals_and_baseline_comparison():
    s = _series()
    res = forecast.run_forecasts(s)
    h = res["hourly"]
    assert h.status == "ok" and len(h.forecast) == 72
    assert (h.forecast["lo"] >= 0).all() and (h.forecast["lo"] <= h.forecast["yhat"]).all() and (h.forecast["yhat"] <= h.forecast["hi"]).all()
    assert "seasonal_naive" in set(h.metrics["model"])
    # on a clean seasonal signal a seasonal-aware model should at least match the baseline
    assert h.metrics.iloc[0]["MAE"] <= h.metrics.set_index("model").loc["seasonal_naive", "MAE"]


def test_short_history_is_refused_not_faked():
    res = forecast.run_forecasts(_series(days=2))
    assert res["hourly"].status.startswith("not enough history")
    assert forecast.risk_outlook(_series(days=2), res)["level"] == "Insufficient data"


def test_outlook_refuses_to_call_a_trend_when_models_disagree():
    s = _series(days=21)
    s.iloc[-24 * 3:] *= 4          # sudden ramp: hourly and daily models give very different answers
    res = forecast.run_forecasts(s)
    o = forecast.risk_outlook(s, res)
    assert o["level"] == "Low confidence" and o["confidence"] == "Low" and o["reasons"]
    assert "Risk outlook: Low confidence" in o["message"]


def _fake_results(hourly_per_h, daily_first, skill=40.0, hi_mult=1.3):
    idx = pd.date_range("2026-01-15", periods=72, freq="h")
    f = pd.DataFrame({"ts": idx, "yhat": hourly_per_h, "lo": hourly_per_h * 0.7, "hi": hourly_per_h * hi_mult})
    d = pd.DataFrame({"ts": pd.date_range("2026-01-15", periods=7, freq="D"), "yhat": daily_first, "lo": 0.0, "hi": 1.0})
    return {"hourly": forecast.ForecastResult("hourly", "ok", "ets", pd.DataFrame(), f, skill),
            "daily": forecast.ForecastResult("daily", "ok", "mean_profile", pd.DataFrame(), d, 20.0)}


def test_outlook_is_rising_when_forecast_is_trusted():
    s = pd.Series(20.0, index=pd.date_range("2026-01-01", periods=24 * 14, freq="h"))   # 480 per day
    o = forecast.risk_outlook(s, _fake_results(70.0, 1680.0))                          # forecast 1,680 per day
    assert o["level"] == "Rising" and o["confidence"] == "High" and o["reasons"] == []


def test_outlook_flags_forecast_far_below_recent_volume():
    s = pd.Series(100.0, index=pd.date_range("2026-01-01", periods=24 * 14, freq="h"))  # 2,400 per day
    o = forecast.risk_outlook(s, _fake_results(5.0, 120.0, skill=40.0))                  # forecast 120 per day
    assert o["level"] == "Low confidence" and any("last 24 hours" in r for r in o["reasons"])


def test_partial_edge_hours_are_not_modelled():
    from sla import kpis
    ts = pd.date_range("2026-01-01 06:55:00", "2026-01-03 17:20:00", freq="5min")
    ev = pd.DataFrame({"ts": ts, "weight": 1, "is_failed_attempt": True, "event_type": "failed_password",
                       "is_success": False, "ip_resolved": "203.0.113.5", "username": "root", "is_invalid_user": False})
    full = kpis.hourly_attempts(ev)
    whole = kpis.complete_hours(ev)
    assert full.index[0].hour == 6 and full.index[-1].hour == 17
    assert whole.index[0].hour == 7 and whole.index[-1].hour == 16


def test_daily_forecast_starts_on_first_day_with_no_data():
    s = _series(days=21)
    s = s.iloc[:-7]                                 # log ends mid-day (hour 17 of day 21)
    res = forecast.run_forecasts(s)
    assert res["daily"].status == "ok"
    assert res["daily"].forecast["ts"].iloc[0] == s.index[-1].normalize() + pd.Timedelta(days=1)
    assert len(res["daily"].forecast) == 7


def test_spike_detection_finds_injected_burst_only():
    s = _series(days=14)
    s.iloc[200] = 900
    sp = anomaly.detect_spikes(s)
    assert s.index[200] in set(sp["hour"]) and len(sp) <= 3
