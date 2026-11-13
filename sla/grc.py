"""Governance, risk and compliance (GRC) and ITIL layer.

Turns the technical findings into the artefacts a cyber-risk team actually works with:
  * an audit-style control test matrix (objective, procedure, population, exceptions, result),
  * an access review (one row per account, with risk flags),
  * ITIL records: incident register with SLA due times, problem register, change requests.

Everything is derived from the log evidence. Where the logs cannot answer a question (for example
there were no successful logins to test) the control is marked "Not tested" instead of "Effective".
SLA targets are illustrative defaults and should be replaced with the client's agreed targets.
"""
from __future__ import annotations

import pandas as pd

from .config import DEFAULT, PRIVILEGED_USERS, Config
from .controls import run_control_tests
from .detection import failed_attempts
from .rules import ITIL_PRIORITY, RULES
from .rules import RECOMMENDED_ACTION as RULES_ACTION

BUSINESS_HOURS = range(7, 20)                      # 07:00-19:59 server time
# priority -> (response target minutes, resolution target minutes); illustrative defaults
SLA_MINUTES = {"P1": (15, 4 * 60), "P2": (60, 8 * 60), "P3": (8 * 60, 72 * 60), "P4": (7 * 24 * 60, 10 * 24 * 60)}
IMPACT_URGENCY = {"Critical": ("High", "High"), "High": ("High", "Medium"), "Medium": ("Medium", "Medium"), "Low": ("Low", "Low")}
RESULT_LABEL = {"PASS": "Effective", "WARN": "Partially effective", "FAIL": "Ineffective", "NOT TESTED": "Not tested"}
RECOMMENDED_ACTION = RULES_ACTION


def _result(status: str, population: int) -> str:
    return RESULT_LABEL["NOT TESTED" if population == 0 else status]


# --------------------------------------------------------------------------- access review
def access_review(events: pd.DataFrame, incidents: pd.DataFrame, cfg: Config = DEFAULT) -> pd.DataFrame:
    e = events[events["username"].notna()].copy()
    e["ip"] = e["ip_resolved"]
    fa = e[e["is_failed_attempt"]].copy()
    ok = e[e["is_success"]].copy()
    cols = ["username", "account_type", "exists_on_server", "failed_attempts", "successful_logins", "source_ips_success",
            "password_logins", "offhours_logins", "after_failures", "risk_rating", "review_flags"]
    if fa.empty and ok.empty:
        return pd.DataFrame(columns=cols)
    fa["valid_w"] = fa["weight"] * (~fa["is_invalid_user"])
    f = fa.groupby("username").agg(failed_attempts=("weight", "sum"), valid_w=("valid_w", "sum"))
    ok["off"] = (~ok["ts"].dt.hour.isin(BUSINESS_HOURS)) * ok["weight"]
    ok["pw"] = (ok["auth_method"] == "password") * ok["weight"]
    s = ok.groupby("username").agg(successful_logins=("weight", "sum"), source_ips_success=("ip", "nunique"),
                                   password_logins=("pw", "sum"), offhours_logins=("off", "sum"))
    a = f.join(s, how="outer").fillna(0).reset_index().rename(columns={"index": "username"})
    comp_users = set(incidents.loc[incidents["rule"] == "SUCCESS_AFTER_FAILURES", "username"].dropna()) if len(incidents) else set()
    a["account_type"] = a["username"].str.lower().map(lambda u: "Privileged" if u in PRIVILEGED_USERS else "Standard")
    a["exists_on_server"] = ((a["valid_w"] > 0) | (a["successful_logins"] > 0)).map({True: "Yes", False: "No (never valid)"})
    a["after_failures"] = a["username"].isin(comp_users).map({True: "Yes", False: "No"})

    def flags(r):
        out = []
        if r["successful_logins"] > 0 and r["account_type"] == "Privileged":
            out.append("Privileged account logged in remotely")
        if r["after_failures"] == "Yes":
            out.append("Login followed repeated failures")
        if r["source_ips_success"] >= 3:
            out.append(f"Used from {int(r['source_ips_success'])} source IPs")
        if r["offhours_logins"] > 0:
            out.append("Login outside 07:00-19:59")
        if r["password_logins"] > 0:
            out.append("Password (not key) authentication")
        if r["exists_on_server"] == "Yes" and r["failed_attempts"] >= 50:
            out.append("Existing account under sustained attack")
        return "; ".join(out) if out else "No exceptions"

    def rate(r):
        if r["successful_logins"] > 0 and (r["account_type"] == "Privileged" or r["after_failures"] == "Yes"):
            return "High"
        if (r["successful_logins"] > 0 and (r["offhours_logins"] > 0 or r["source_ips_success"] >= 3 or r["password_logins"] > 0)) \
                or (r["exists_on_server"] == "Yes" and r["failed_attempts"] >= 50):
            return "Medium"
        return "Low"

    a["review_flags"] = a.apply(flags, axis=1)
    a["risk_rating"] = a.apply(rate, axis=1)
    for c in ("failed_attempts", "successful_logins", "source_ips_success", "password_logins", "offhours_logins"):
        a[c] = a[c].astype(int)
    order = {"High": 0, "Medium": 1, "Low": 2}
    a = a.sort_values(by=["risk_rating", "failed_attempts"], key=lambda s: s.map(order) if s.name == "risk_rating" else -s)
    return a[cols].reset_index(drop=True)


# --------------------------------------------------------------------------- control matrix
def control_matrix(events: pd.DataFrame, incidents: pd.DataFrame, cfg: Config = DEFAULT) -> pd.DataFrame:
    base = run_control_tests(events, incidents, cfg).set_index("control_id")
    fa = failed_attempts(events)
    ok = events[events["is_success"]]
    n_fail = int(fa["weight"].sum()) if len(fa) else 0
    n_ok = int(ok["weight"].sum())
    attempts = n_fail + n_ok
    priv_att = int(fa.loc[fa["username"].fillna("").str.lower().isin(PRIVILEGED_USERS), "weight"].sum()) if len(fa) else 0
    priv_ok = int(ok.loc[ok["username"].fillna("").str.lower().isin(PRIVILEGED_USERS), "weight"].sum())
    pw_ok = int(ok.loc[ok["auth_method"] == "password", "weight"].sum())
    off_ok = int(ok.loc[~ok["ts"].dt.hour.isin(BUSINESS_HOURS), "weight"].sum())
    ok_users = ok.dropna(subset=["username"]).groupby("username")["ip_resolved"].nunique()
    inc = incidents if len(incidents) else pd.DataFrame(columns=["rule", "attempts"])
    bf = inc[inc["rule"].isin(["SSH_BRUTE_FORCE", "PASSWORD_SPRAYING"])]
    cov_rules = inc[inc["rule"].isin(["SSH_BRUTE_FORCE", "PASSWORD_SPRAYING", "DISTRIBUTED_ATTACK"])]
    uncovered = max(0, n_fail - int(cov_rules["attempts"].sum()))
    n_comp = int((inc["rule"] == "SUCCESS_AFTER_FAILURES").sum())
    fsessions = int(events.loc[events["is_failed_attempt"], "session_id"].nunique())
    mism = int((events["event_type"] == "PAM_MAX_RETRIES").sum())

    def graded(exc, pop, warn_below=0.5):
        if exc == 0:
            return "PASS"
        return "WARN" if exc / max(pop, 1) < warn_below else "FAIL"

    rows = [
        ("AC-01", "Access control", "Password authentication is not exposed to untrusted networks.",
         "Exposed password logins let attackers guess or reuse credentials at internet scale.",
         "Count authentication attempts by method and source; identify password attempts from external addresses.",
         "Authentication attempts (failed + successful)", attempts, n_fail + pw_ok, base.loc["C1", "status"], base.loc["C1", "evidence"],
         base.loc["C1", "recommendation"], "ISO/IEC 27001:2022 A.8.5; NIST CSF 2.0 PR.AA"),
        ("AC-02", "Access control", "Successful remote logins use strong authentication (keys or MFA), not passwords alone.",
         "A guessed password gives an attacker full access when no second factor or key is required.",
         "Take every successful login in the period and test the authentication method used.",
         "Successful logins", n_ok, pw_ok, graded(pw_ok, n_ok), f"{pw_ok} of {n_ok} successful logins used a password.",
         "Require public-key authentication or MFA for all remote logins.", "ISO/IEC 27001:2022 A.8.5; NIST CSF 2.0 PR.AA"),
        ("AC-03", "Access control", "Direct privileged (root/admin) SSH access is disabled.",
         "Compromise of a root or admin login gives complete control of the server.",
         "Count attempts and successes against privileged accounts.",
         "Authentication attempts (failed + successful)", attempts, priv_att + priv_ok, base.loc["C3", "status"], base.loc["C3", "evidence"],
         base.loc["C3", "recommendation"], "ISO/IEC 27001:2022 A.8.2; NIST CSF 2.0 PR.AA"),
        ("AC-04", "Access control", "Logins occur within expected working hours.",
         "Out-of-hours access can indicate misuse or a compromised credential.",
         "Test the timestamp of each successful login against 07:00-19:59 server time.",
         "Successful logins", n_ok, off_ok, "WARN" if off_ok else "PASS", f"{off_ok} of {n_ok} successful logins were outside 07:00-19:59.",
         "Confirm the logins with the account owner; alert on out-of-hours privileged access.", "ISO/IEC 27001:2022 A.8.16"),
        ("AC-05", "Access control", "Individual accounts are not used from many different source addresses.",
         "One account used from many networks suggests shared or stolen credentials.",
         "For each account with a successful login, count distinct source IPs.",
         "Accounts with successful logins", int(len(ok_users)), int((ok_users >= 3).sum()), "WARN" if (ok_users >= 3).any() else "PASS",
         f"{int((ok_users >= 3).sum())} of {len(ok_users)} accounts logged in from 3 or more source IPs.",
         "Review the accounts; remove sharing; bind access to known networks or a VPN.", "ISO/IEC 27001:2022 A.8.5"),
        ("SM-01", "Security monitoring", f"Lockout or rate limiting stops guessing after about {cfg.lockout_policy_attempts} attempts.",
         "Without lockout, attackers can try unlimited passwords.",
         "Measure attempts per attack episode against the lockout threshold.",
         "Brute-force and spraying episodes", int(len(bf)), int((bf["attempts"] > cfg.lockout_policy_attempts).sum()) if len(bf) else 0,
         base.loc["C2", "status"], base.loc["C2", "evidence"], base.loc["C2", "recommendation"], "ISO/IEC 27001:2022 A.8.5; CIS Control 5"),
        ("SM-02", "Security monitoring", "No successful login follows a run of failures from the same source.",
         "A success after many failures is the signature of a guessed password.",
         "Join each successful login to failed attempts from the same IP in the previous 60 minutes.",
         "Successful logins", n_ok, n_comp, base.loc["C4", "status"], base.loc["C4", "evidence"], base.loc["C4", "recommendation"],
         "ISO/IEC 27001:2022 A.8.16; NIST CSF 2.0 RS.AN"),
        ("SM-03", "Security monitoring", "Monitoring rules cover the bulk of malicious authentication activity.",
         "Activity outside detection coverage goes unnoticed by the SOC.",
         "Compare failed attempts inside detected incidents with all failed attempts.",
         "Failed attempts", n_fail, uncovered, base.loc["C5", "status"], base.loc["C5", "evidence"], base.loc["C5", "recommendation"],
         "ISO/IEC 27001:2022 A.8.15, A.8.16; NIST CSF 2.0 DE.CM"),
        ("CM-01", "Configuration management", "sshd MaxAuthTries is consistent with the PAM retry limit.",
         "Mismatched settings mean the intended lockout policy is not enforced.",
         "Search logs for PAM messages that it is ignoring its max-retries limit.",
         "Connections with failed attempts", fsessions, min(mism, fsessions), base.loc["C6", "status"], base.loc["C6", "evidence"],
         base.loc["C6", "recommendation"], "ISO/IEC 27001:2022 A.8.9"),
    ]
    out = []
    for cid, dom, obj, risk, proc, popd, pop, exc, status, evid, rec, ref in rows:
        if 0 < pop < 5:
            evid = f"{evid} Small population (n={pop}): treat as indicative and extend testing with a longer log period."
        out.append({"control_id": cid, "domain": dom, "control_objective": obj, "risk_addressed": risk, "test_procedure": proc,
                    "population_description": popd, "population": int(pop), "exceptions": int(exc),
                    "result": _result(status, int(pop)), "evidence": evid if pop else f"{popd}: none in the period, so this control cannot be tested.",
                    "recommendation": rec, "framework_reference": ref})
    return pd.DataFrame(out)


# --------------------------------------------------------------------------- ITIL records
def itil_registers(incidents: pd.DataFrame, matrix: pd.DataFrame, blocklist_size: int = 0, cfg: Config = DEFAULT):
    res = matrix.set_index("control_id")["result"]
    bad = lambda cid: cid in res.index and res[cid] in ("Ineffective", "Partially effective")
    inc = incidents.copy()

    # ---- problems (root causes behind groups of incidents)
    problems = []
    def add_problem(pid, title, cause, n, prio, workaround, fix):
        problems.append({"problem_id": pid, "title": title, "root_cause_hypothesis": cause, "linked_incidents": int(n), "highest_priority": prio,
                         "workaround": workaround, "permanent_fix": fix, "status": "Open - root cause analysis", "owner": "Problem manager (to assign)"})
    top_prio = lambda d: min(d["priority"], default="P4") if len(d) else "P4"
    if len(inc):
        inc["priority_rank"] = inc["priority"]
    g1 = inc[inc["rule"].isin(["SSH_BRUTE_FORCE", "PASSWORD_SPRAYING", "DISTRIBUTED_ATTACK"])] if len(inc) else inc
    if len(g1) and bad("AC-01"):
        add_problem("PRB-001", "Password SSH authentication is reachable from the internet",
                    "Port 22 accepts password logins from any address, so automated guessing is possible at any time.", len(g1), top_prio(g1),
                    "Ban offending IPs with fail2ban and apply the block list.", "Key-based authentication or MFA, with SSH restricted to a VPN or allow-list.")
    g2 = inc[inc["rule"].isin(["SSH_BRUTE_FORCE", "PASSWORD_SPRAYING"]) & (inc["attempts"] > cfg.lockout_policy_attempts)] if len(inc) else inc
    if len(g2) and bad("SM-01"):
        add_problem("PRB-002", "Lockout or rate limiting does not stop guessing", "No effective per-source limit is enforced, or limits are inconsistent (see CM-01).",
                    len(g2), top_prio(g2), "fail2ban: 5 failures in 5 minutes, 24 hour ban.", "Align sshd MaxAuthTries with PAM limits and add network-level rate limiting.")
    g3 = inc[inc["targets_privileged"].astype(bool)] if len(inc) else inc
    if len(g3) and bad("AC-03"):
        add_problem("PRB-003", "Privileged accounts (root/admin) are the main target", "Direct root/admin login is permitted over SSH.", len(g3), top_prio(g3),
                    "Monitor and block sources that target root or admin.", "PermitRootLogin no; named accounts with sudo.")
    g4 = inc[inc["rule"] == "SUCCESS_AFTER_FAILURES"] if len(inc) else inc
    if len(g4):
        add_problem("PRB-004", "Possible account compromise after repeated failures", "A source guessed a valid credential; the weakness that allowed it is not yet known.",
                    len(g4), "P1", "Reset the credential and isolate the session while investigating.", "Remove password authentication; review the account's activity and persistence.")
    if bad("CM-01"):
        add_problem("PRB-005", "sshd and PAM retry limits are inconsistent", "MaxAuthTries in sshd is higher than the PAM limit, so PAM logs that it is ignoring max retries.", 0, "P3",
                    "None required beyond monitoring.", "Align the two settings in a controlled change.")
    problems_df = pd.DataFrame(problems, columns=["problem_id", "title", "root_cause_hypothesis", "linked_incidents", "highest_priority", "workaround",
                                                  "permanent_fix", "status", "owner"])

    # ---- incident register
    link = {"SSH_BRUTE_FORCE": "PRB-001", "PASSWORD_SPRAYING": "PRB-001", "DISTRIBUTED_ATTACK": "PRB-001", "SUCCESS_AFTER_FAILURES": "PRB-004"}
    have = set(problems_df["problem_id"])
    if len(inc):
        det = pd.to_datetime(inc["end_ts"])
        resp = inc["priority"].map(lambda p: SLA_MINUTES[p][0]).astype(int)
        reso = inc["priority"].map(lambda p: SLA_MINUTES[p][1]).astype(int)
        reg = pd.DataFrame({
            "incident_id": inc["incident_id"], "category": "Security / Access", "subcategory": inc["title"], "priority": inc["priority"],
            "impact": inc["severity"].map(lambda s: IMPACT_URGENCY[s][0]), "urgency": inc["severity"].map(lambda s: IMPACT_URGENCY[s][1]),
            "severity": inc["severity"], "detected_at": det.dt.strftime("%Y-%m-%d %H:%M:%S"), "status": "New - awaiting triage",
            "assignment_group": "SOC L1 (Security Operations)",
            "response_due": (det + pd.to_timedelta(resp, unit="m")).dt.strftime("%Y-%m-%d %H:%M:%S"),
            "resolution_due": (det + pd.to_timedelta(reso, unit="m")).dt.strftime("%Y-%m-%d %H:%M:%S"),
            "source": inc["ip"].fillna("multiple IPs") + inc["username"].fillna("").map(lambda u: f" / {u}" if u else ""),
            "description": inc["evidence"], "mitre_technique": inc["technique_id"],
            "recommended_action": inc["rule"].map(RECOMMENDED_ACTION),
            "linked_problem": inc["rule"].map(link).map(lambda p: p if p in have else "")})
    else:
        reg = pd.DataFrame(columns=["incident_id", "category", "subcategory", "priority", "impact", "urgency", "severity", "detected_at", "status",
                                    "assignment_group", "response_due", "resolution_due", "source", "description", "mitre_technique", "recommended_action", "linked_problem"])

    # ---- change requests (proposed fixes)
    has_crit = bool(len(inc) and (inc["severity"] == "Critical").any())
    changes = [
        ("CHG-001", "Deploy fail2ban for sshd (5 failures / 5 min, 24h ban)", "Standard", "Low", "Stop fail2ban service and remove the jail.", "PRB-002"),
        ("CHG-002", "Set PermitRootLogin no and verify a sudo-enabled admin account first", "Normal", "Medium", "Restore sshd_config backup and reload sshd.", "PRB-003"),
        ("CHG-003", "Disable password authentication; require public keys or MFA", "Normal", "High", "Restore sshd_config backup; keep a console session open during the change.", "PRB-001"),
        ("CHG-004", f"Apply IP block list ({blocklist_size} High/Critical source IPs)", "Emergency" if has_crit else "Standard", "Low", "Remove the firewall rules added.", "PRB-001"),
        ("CHG-005", "Align sshd MaxAuthTries with the PAM retry limit", "Standard", "Low", "Restore previous sshd_config.", "PRB-005"),
        ("CHG-006", "Restrict SSH access to VPN or an allow-listed address range", "Normal", "High", "Re-open the previous firewall rule from the console.", "PRB-001"),
    ]
    ch = pd.DataFrame([{"change_id": c, "description": d, "change_type": t, "risk": r, "rollback_plan": rb, "linked_problem": p if p in have else "",
                        "approval": "", "status": "Proposed - awaiting CAB approval"} for c, d, t, r, rb, p in changes])
    return reg, problems_df, ch
