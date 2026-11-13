from conftest import events_from
from sla.parser import classify, parse_file


def test_failed_password_valid_and_invalid_user():
    a = classify("Failed password for root from 1.2.3.4 port 22 ssh2")
    assert (a["event_type"], a["username"], a["ip"], a["is_invalid_user"]) == ("FAILED_LOGIN", "root", "1.2.3.4", False)
    b = classify("Failed password for invalid user  0101 from 5.6.7.8 port 99 ssh2")
    assert b["is_invalid_user"] and b["username"] == "0101"


def test_accepted_and_other_event_types():
    assert classify("Accepted publickey for deploy from 9.9.9.9 port 1 ssh2")["event_type"] == "ACCEPTED"
    assert classify("Did not receive identification string from 1.1.1.1")["event_type"] == "NO_IDENT"
    assert classify("pam_unix(sshd:auth): check pass; user unknown")["event_type"] == "PAM_UNKNOWN_USER"
    assert classify("totally unknown message")["event_type"] == "OTHER"


def test_pam_failure_extracts_ip_from_rhost():
    r = classify("pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.2.3.4  user=root")
    assert r["ip"] == "1.2.3.4" and r["username"] == "root"


def test_only_failed_login_counts_as_attempt_no_double_counting():
    lines = [
        "Dec 10 06:55:46 LabSZ sshd[1]: Invalid user bob from 1.1.1.1",
        "Dec 10 06:55:46 LabSZ sshd[1]: pam_unix(sshd:auth): check pass; user unknown",
        "Dec 10 06:55:47 LabSZ sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=1.1.1.1 ",
        "Dec 10 06:55:48 LabSZ sshd[1]: Failed password for invalid user bob from 1.1.1.1 port 5 ssh2",
    ]
    ev = events_from(lines)
    assert int(ev["is_failed_attempt"].sum()) == 1


def test_repeat_lines_expand_weight():
    ev = events_from(["Dec 10 06:55:46 LabSZ sshd[1]: message repeated 5 times: [ Failed password for root from 1.1.1.1 port 5 ssh2]"])
    assert ev.loc[0, "weight"] == 5 and ev.loc[0, "is_failed_attempt"]


def test_session_reconstruction_fills_missing_ip():
    lines = [
        "Dec 10 06:55:46 LabSZ sshd[7]: Invalid user bob from 3.3.3.3",
        "Dec 10 06:55:47 LabSZ sshd[7]: pam_unix(sshd:auth): check pass; user unknown",
    ]
    ev = events_from(lines)
    assert ev["ip_resolved"].tolist() == ["3.3.3.3", "3.3.3.3"]


def test_year_rolls_over_dec_to_jan():
    ev = events_from(["Dec 31 23:59:59 LabSZ sshd[1]: Did not receive identification string from 1.1.1.1",
                      "Jan  1 00:00:05 LabSZ sshd[2]: Did not receive identification string from 1.1.1.1"], year=2015)
    assert [t.year for t in ev["ts"]] == [2015, 2016]


def test_real_sample_parses_fully(sample_log):
    ev = parse_file(sample_log)
    assert len(ev) == 2000
    assert ev["ip_resolved"].notna().mean() > 0.99
    assert (ev["event_type"] == "OTHER").mean() < 0.01
