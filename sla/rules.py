"""The one place where rule semantics live.

Everything the UI explains to an analyst is defined here and nowhere else:
  * which detection rule maps to which MITRE ATT&CK technique,
  * the thresholds that decide a severity,
  * the recommended action for each rule,
  * the risk-score formula (components, weights, caps, tiers),
  * the priority and response target that follow from a severity.

Engine tunables that are not about meaning (window lengths, minimum counts to open an
episode) stay in `config.py`. The API serves this file read-only at GET /rules, so the
"How is this calculated?" text in the UI can never drift from the code that scores.
"""
from __future__ import annotations

# --------------------------------------------------------------------------- rules
RULES = {
    "SSH_BRUTE_FORCE": {
        "title": "SSH brute-force (password guessing)",
        "technique_id": "T1110.001", "technique": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "controls": "ISO/IEC 27001:2022 A.8.5 Secure authentication; NIST CSF 2.0 PR.AA",
        "plain": "One address hammered the server with password guesses far faster than any human could type.",
        "action": "Block the source IP; confirm no successful login from it; review lockout settings.",
    },
    "PASSWORD_SPRAYING": {
        "title": "Username enumeration / password spraying",
        "technique_id": "T1110.003", "technique": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "controls": "ISO/IEC 27001:2022 A.8.5, A.8.16; NIST CSF 2.0 DE.CM",
        "plain": "One address tried a few passwords against many different usernames, hunting for any account that works.",
        "action": "Block the source IP; check whether any targeted account exists and was accessed; enforce MFA or keys.",
    },
    "DISTRIBUTED_ATTACK": {
        "title": "Distributed attack on a single account",
        "technique_id": "T1110", "technique": "Brute Force (distributed)",
        "tactic": "Credential Access",
        "controls": "ISO/IEC 27001:2022 A.8.5, A.8.16; NIST CSF 2.0 DE.AE",
        "plain": "Many different addresses attacked the same account at once, which points to a botnet and defeats per-IP blocking.",
        "action": "Add account-level throttling; restrict SSH to VPN or allow-list; per-IP blocking alone is insufficient.",
    },
    "SUCCESS_AFTER_FAILURES": {
        "title": "Successful login after repeated failures (possible compromise)",
        "technique_id": "T1078", "technique": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "controls": "ISO/IEC 27001:2022 A.8.5, A.8.16; NIST CSF 2.0 RS.AN",
        "plain": "An address failed several times and then got in. Treat the account as possibly compromised until proven otherwise.",
        "action": "Treat as possible compromise: isolate account, force credential reset, review session activity and persistence.",
    },
    "RECON_SCAN": {
        "title": "Reconnaissance / port scanning",
        "technique_id": "T1595.001", "technique": "Active Scanning: Scanning IP Blocks",
        "tactic": "Reconnaissance",
        "controls": "ISO/IEC 27001:2022 A.8.16, A.8.20; NIST CSF 2.0 DE.CM",
        "plain": "An address connected repeatedly without attempting to log in, which is typical of scanning for open SSH services.",
        "action": "Monitor; block if repeated; confirm port 22 exposure is intended.",
    },
}
RECOMMENDED_ACTION = {k: v["action"] for k, v in RULES.items()}

# --------------------------------------------------------------------------- severity
SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

SEVERITY_RULES = {
    "SSH_BRUTE_FORCE": {
        "text": "Points: 2 if attempts >= 100, 1 if attempts >= 20; +1 if the peak 5-minute window >= 30 attempts; "
                "+1 if a privileged account was targeted. High at 4 or more points, Medium at 2 or 3, otherwise Low.",
        "attempts_2pts": 100, "attempts_1pt": 20, "peak_pts": 30, "high_at": 4, "medium_at": 2,
    },
    "PASSWORD_SPRAYING": {
        "text": "High if 20 or more usernames were tried or a privileged account was targeted, otherwise Medium.",
        "high_users": 20,
    },
    "DISTRIBUTED_ATTACK": {
        "text": "High if the account is privileged or 15 or more IPs took part, otherwise Medium.",
        "high_ips": 15,
    },
    "SUCCESS_AFTER_FAILURES": {"text": "Always Critical: a login succeeded after repeated failures.", "fixed": "Critical"},
    "RECON_SCAN": {"text": "Always Low: probing without login attempts.", "fixed": "Low"},
}
ATTACKER_SEVERITY_TEXT = ("An attacker IP takes the highest severity among the incidents raised against it. "
                          "An IP that raised no incident is shown as 'No incident'. Severity is separate from the risk score.")

# --------------------------------------------------------------------------- priority (separate from severity)
ITIL_PRIORITY = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4"}
RESPONSE_TARGET = {"P1": "Respond within 15 min", "P2": "Respond within 1 hour",
                   "P3": "Respond within 1 business day", "P4": "Review in weekly triage"}

# --------------------------------------------------------------------------- risk score
RISK_WEIGHTS = {"volume": 0.30, "intensity": 0.20, "breadth": 0.15, "persistence": 0.15, "privileged": 0.10, "invalid": 0.10}
RISK_PARAMS = {"volume_ref_attempts": 1000, "intensity_ref_window_attempts": 50, "breadth_ref_users": 20, "persistence_ref_hours": 24}
RISK_TIERS = {"medium_from": 35.0, "high_from": 60.0, "critical_from": 80.0}
COMPROMISE_SCORE_FLOOR = 90

RISK_COMPONENTS = [
    {"key": "volume", "label": "Volume",
     "formula": "min(1, log10(1 + attempts) / log10(1 + 1000))",
     "meaning": "How many failed attempts the IP made. Log scale, so 1,000 attempts reaches the cap."},
    {"key": "intensity", "label": "Intensity",
     "formula": "min(1, peak attempts in any 5-minute window / 50)",
     "meaning": "How fast the IP guessed at its fastest."},
    {"key": "breadth", "label": "Breadth",
     "formula": "min(1, distinct usernames tried / 20)",
     "meaning": "How many different accounts the IP tried."},
    {"key": "persistence", "label": "Persistence",
     "formula": "min(1, distinct active hours / 24)",
     "meaning": "How many different hours the IP was active."},
    {"key": "privileged", "label": "Privileged targets",
     "formula": "share of attempts aimed at root, admin and other privileged accounts",
     "meaning": "Attacks on powerful accounts count for more."},
    {"key": "invalid", "label": "Invalid usernames",
     "formula": "share of attempts using usernames that do not exist on the server",
     "meaning": "Guessing names is a sign of automated scanning."},
]
RISK_FORMULA_TEXT = ("Score = 100 x sum(weight x component), each component between 0 and 1. "
                     f"Weights: {', '.join(f'{k} {v:.2f}' for k, v in RISK_WEIGHTS.items())}. "
                     f"An IP with a successful login after repeated failures is raised to at least {COMPROMISE_SCORE_FLOOR}. "
                     f"Tiers: Medium from {RISK_TIERS['medium_from']:.0f}, High from {RISK_TIERS['high_from']:.0f}, "
                     f"Critical from {RISK_TIERS['critical_from']:.0f}.")

# --------------------------------------------------------------------------- data-quality rules
GAP_MIN_HOURS = 24   # a run of at least this many hours with no log lines is shown as a no-activity gap
ANOMALY_RULE = {
    "id": "HOURLY_VOLUME_SPIKE",
    "label": "Hourly attempts far above the same hour of the previous 7 days (robust z-score >= 5)",
}
