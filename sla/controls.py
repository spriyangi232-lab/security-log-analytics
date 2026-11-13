"""Automated IT-control tests run against the log evidence. Each test returns PASS / WARN / FAIL with
the evidence behind it, mirroring how a control-effectiveness assessment is written up for a client."""
from __future__ import annotations

import re

import pandas as pd

from .config import DEFAULT, PRIVILEGED_USERS, Config
from .detection import failed_attempts

_RETRY_RE = re.compile(r"ignoring max retries; (\d+) > (\d+)")


def _row(cid, control, status, evidence, recommendation, reference):
    return {"control_id": cid, "control": control, "status": status, "evidence": evidence,
            "recommendation": recommendation, "reference": reference}


def run_control_tests(events: pd.DataFrame, incidents: pd.DataFrame, cfg: Config = DEFAULT) -> pd.DataFrame:
    fa = failed_attempts(events)
    total = int(fa["weight"].sum()) if len(fa) else 0
    rows = []

    n_ips = int(fa["ip"].nunique()) if len(fa) else 0
    status = "PASS" if total == 0 else "FAIL" if n_ips >= 10 else "WARN"
    rows.append(_row("C1", "Password authentication is not exposed to untrusted networks", status,
                     f"{total} failed password attempts from {n_ips} distinct external IPs",
                     "Disable password login (PasswordAuthentication no), require key-based auth or MFA, and restrict port 22 to a VPN or allow-list.",
                     "ISO/IEC 27001:2022 A.8.5; NIST CSF 2.0 PR.AA"))

    bf = incidents[incidents["rule"].isin(["SSH_BRUTE_FORCE", "PASSWORD_SPRAYING"])] if len(incidents) else incidents
    over = bf[bf["attempts"] > cfg.lockout_policy_attempts] if len(bf) else bf
    way_over = bf[bf["attempts"] > 10 * cfg.lockout_policy_attempts] if len(bf) else bf
    status = "FAIL" if len(way_over) else "WARN" if len(over) else "PASS"
    worst = int(bf["attempts"].max()) if len(bf) else 0
    rows.append(_row("C2", f"Account lockout / rate limiting stops guessing after about {cfg.lockout_policy_attempts} attempts", status,
                     f"{len(over)} of {len(bf)} attack episodes exceeded {cfg.lockout_policy_attempts} attempts; "
                     f"{len(way_over)} exceeded {10 * cfg.lockout_policy_attempts}; worst episode {worst} attempts",
                     "Deploy fail2ban or equivalent (ban after 5 failures / 10 min), lower MaxAuthTries, add network-level rate limiting.",
                     "ISO/IEC 27001:2022 A.8.5; CIS Control 5"))

    priv_att = int(fa.loc[fa["username"].fillna("").str.lower().isin(PRIVILEGED_USERS), "weight"].sum()) if len(fa) else 0
    root_ok = int(events[(events["is_success"]) & (events["username"].fillna("").str.lower() == "root")]["weight"].sum())
    status = "FAIL" if root_ok else "WARN" if priv_att else "PASS"
    rows.append(_row("C3", "Direct privileged (root/admin) SSH login is disabled", status,
                     f"{priv_att} attempts against privileged accounts; {root_ok} successful root logins",
                     "Set PermitRootLogin no; use named accounts with sudo and session logging.",
                     "ISO/IEC 27001:2022 A.8.2; NIST CSF 2.0 PR.AA"))

    n_comp = int((incidents["rule"] == "SUCCESS_AFTER_FAILURES").sum()) if len(incidents) else 0
    rows.append(_row("C4", "No successful login follows a run of failures from the same source",
                     "FAIL" if n_comp else "PASS",
                     f"{n_comp} successful login(s) preceded by >= {cfg.compromise_min_failures} failures within {cfg.compromise_lookback_minutes} min",
                     "Reset credentials and review session activity for the affected account(s); force MFA.",
                     "ISO/IEC 27001:2022 A.8.16; NIST CSF 2.0 RS.AN"))

    if len(incidents) and total:
        covered = int(incidents.loc[incidents["rule"].isin(["SSH_BRUTE_FORCE", "PASSWORD_SPRAYING", "DISTRIBUTED_ATTACK"]), "attempts"].sum())
        # distributed incidents overlap with per-IP incidents, so cap the ratio at 100%
        cov = min(100.0, 100 * covered / total)
    else:
        cov = 0.0 if total else 100.0
    rows.append(_row("C5", "Monitoring covers the bulk of malicious authentication activity",
                     "PASS" if cov >= 90 else "WARN" if cov >= 70 else "FAIL",
                     f"Detection rules cover {cov:.1f}% of failed attempts",
                     "Tune thresholds in config.py and forward alerts to the SIEM / ticketing queue.",
                     "ISO/IEC 27001:2022 A.8.15, A.8.16; NIST CSF 2.0 DE.CM"))

    mism = events[events["event_type"] == "PAM_MAX_RETRIES"]["raw"].str.extract(_RETRY_RE).dropna()
    if len(mism):
        a, b = int(mism.iloc[:, 0].astype(int).max()), int(mism.iloc[:, 1].astype(int).min())
        rows.append(_row("C6", "sshd MaxAuthTries is consistent with the PAM retry limit", "WARN",
                         f"{len(mism)} log entries show PAM ignoring its max-retries limit (sessions reached {a} tries against a limit of {b})",
                         "Align sshd MaxAuthTries with the PAM limit so that lockout policy is actually enforced.",
                         "ISO/IEC 27001:2022 A.8.9 Configuration management"))
    else:
        rows.append(_row("C6", "sshd MaxAuthTries is consistent with the PAM retry limit", "PASS",
                         "No PAM max-retries mismatches in the logs", "None.", "ISO/IEC 27001:2022 A.8.9"))
    return pd.DataFrame(rows)
