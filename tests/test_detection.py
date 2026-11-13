from datetime import datetime, timedelta

from conftest import events_from
from sla import controls, detection, risk


def _line(t, pid, msg):
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S} h sshd[{pid}]: {msg}"


def _fail(t, pid, ip, user="root", valid=True):
    return _line(t, pid, f"Failed password for {'' if valid else 'invalid user '}{user} from {ip} port 22 ssh2")


T0 = datetime(2026, 1, 5, 10, 0, 0)


def test_brute_force_detected_and_quiet_ip_ignored():
    lines = [_fail(T0 + timedelta(seconds=5 * i), 1, "1.1.1.1") for i in range(12)]
    lines += [_fail(T0, 2, "2.2.2.2")]
    inc = detection.run_all(events_from(lines))
    assert list(inc["rule"]) == ["SSH_BRUTE_FORCE"] and inc.loc[0, "ip"] == "1.1.1.1" and inc.loc[0, "attempts"] == 12


def test_password_spraying_detected():
    lines = [_fail(T0 + timedelta(seconds=2 * i), 1, "3.3.3.3", user=f"u{i}", valid=False) for i in range(10)]
    inc = detection.run_all(events_from(lines))
    assert "PASSWORD_SPRAYING" in set(inc["rule"])


def test_distributed_attack_needs_many_quiet_ips():
    lines = [_fail(T0 + timedelta(minutes=i), 100 + i, f"10.0.0.{i}", user="root") for i in range(12)]
    inc = detection.run_all(events_from(lines))
    assert "DISTRIBUTED_ATTACK" in set(inc["rule"])


def test_success_after_failures_is_critical_and_forces_critical_risk():
    lines = [_fail(T0 + timedelta(seconds=10 * i), 5, "4.4.4.4", user="admin") for i in range(4)]
    lines.append(_line(T0 + timedelta(minutes=2), 5, "Accepted password for admin from 4.4.4.4 port 22 ssh2"))
    ev = events_from(lines)
    inc = detection.run_all(ev)
    crit = inc[inc["rule"] == "SUCCESS_AFTER_FAILURES"]
    assert len(crit) == 1 and crit.iloc[0]["severity"] == "Critical"
    prof = risk.ip_profile(ev, inc)
    row = prof[prof["ip"] == "4.4.4.4"].iloc[0]
    assert row["risk_tier"] == "Critical" and row["risk_score"] >= 90
    ctl = controls.run_control_tests(ev, inc).set_index("control_id")
    assert ctl.loc["C4", "status"] == "FAIL"


def test_legit_login_without_failures_is_not_flagged():
    ev = events_from([_line(T0, 9, "Accepted publickey for deploy from 5.5.5.5 port 22 ssh2")])
    assert detection.run_all(ev).empty


def test_risk_scores_bounded_and_explainable():
    lines = [_fail(T0 + timedelta(seconds=i), 1, "1.1.1.1") for i in range(300)]
    ev = events_from(lines)
    prof = risk.ip_profile(ev, detection.run_all(ev))
    assert 0 <= prof.loc[0, "risk_score"] <= 100
    comps = sum(prof.loc[0, c] for c in prof.columns if c.startswith("c_"))
    assert abs(comps - prof.loc[0, "risk_score"]) < 0.6
