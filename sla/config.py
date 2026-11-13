"""Engine tunables (window lengths, minimum counts, forecasting settings). What a rule MEANS
(technique, severity thresholds, actions, risk-score formula) lives in `rules.py`; the score
weights and tiers below are read from there so they cannot diverge."""
from dataclasses import dataclass, field

from .rules import RISK_TIERS, RISK_WEIGHTS

PRIVILEGED_USERS = frozenset({"root", "admin", "administrator", "oracle", "postgres", "ubuntu"})


@dataclass(frozen=True)
class Config:
    # --- parsing -------------------------------------------------------------
    default_year: int = 2015          # syslog lines carry no year; Loghub OpenSSH starts in December
    session_gap_minutes: int = 30     # same PID + gap below this = same SSH connection

    # --- detection rules -------------------------------------------------------
    episode_gap_minutes: int = 30     # attempts from one IP closer than this form one "episode"
    bf_window_minutes: int = 5        # sliding window used to measure attack intensity
    bf_min_attempts: int = 5          # >= this many failed attempts inside the window => brute force
    spray_min_users: int = 5          # distinct usernames inside one episode
    spray_max_attempts_per_user: float = 3.0
    distributed_min_ips: int = 10     # distinct IPs failing against one username within an hour
    distributed_max_attempts_per_ip: float = 15.0  # 'distributed' = many sources, each quiet (else it is just many brute-forcers)
    compromise_lookback_minutes: int = 60
    compromise_min_failures: int = 3  # failures from same IP before an accepted login
    recon_min_events: int = 3         # pre-auth probes (no ident / pre-auth close) in 10 minutes
    recon_window_minutes: int = 10

    # --- anomaly detection on hourly volume ---------------------------------
    anomaly_z: float = 5.0            # robust z-score threshold on log-scale residuals
    anomaly_min_count: int = 100      # ignore spikes below this absolute hourly volume
    anomaly_window_hours: int = 24 * 7

    # --- KPIs ------------------------------------------------------------------
    night_hours: tuple = (22, 23, 0, 1, 2, 3, 4, 5)   # 8 of 24 hours => 33.3% expected if uniform

    # --- risk score weights (sum to 1.0) ---------------------------------------
    w_volume: float = RISK_WEIGHTS["volume"]
    w_intensity: float = RISK_WEIGHTS["intensity"]
    w_breadth: float = RISK_WEIGHTS["breadth"]
    w_persistence: float = RISK_WEIGHTS["persistence"]
    w_privileged: float = RISK_WEIGHTS["privileged"]
    w_invalid: float = RISK_WEIGHTS["invalid"]
    tier_critical: float = RISK_TIERS["critical_from"]
    tier_high: float = RISK_TIERS["high_from"]
    tier_medium: float = RISK_TIERS["medium_from"]

    # --- control tests ---------------------------------------------------------
    lockout_policy_attempts: int = 5   # a control that works should stop an IP after about this many

    # --- forecasting -----------------------------------------------------------
    hourly_horizon: int = 72
    daily_horizon: int = 7
    backtest_folds: int = 3
    interval_coverage: float = 0.80
    # --- outlook confidence: when the forecast is not trustworthy the outlook says so ---------
    outlook_min_skill_pct: float = 10.0      # best model must beat the naive baseline by at least this much
    outlook_good_skill_pct: float = 25.0     # at or above this (and no other warning) confidence is High
    outlook_runrate_band: tuple = (0.25, 4.0)  # next-24h forecast / last-24h actual outside this band is suspect
    outlook_interval_ratio: float = 5.0      # 80% interval upper bound / point forecast above this is "very wide"
    outlook_model_agree: tuple = (1 / 3, 3.0)  # hourly vs daily next-day forecast ratio outside this band


DEFAULT = Config()
