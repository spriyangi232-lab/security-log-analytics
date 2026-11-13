"""Overview numbers must agree with the pipeline's own KPIs, and must be honest about gaps and unparsed lines."""
import json
import sqlite3

import pandas as pd
import pytest

from sla import overview as ov
from sla.parser import parse_lines
from sla.pipeline import run
from sla.synthetic import generate


@pytest.fixture(scope="module")
def ds(tmp_path_factory):
    d = tmp_path_factory.mktemp("ov")
    log = d / "s.log"
    log.write_text("\n".join(generate()) + "\nthis is not a syslog line\n")
    res = run(str(log), str(d / "s.db"), str(d / "out"), year=2026, verbose=False)
    return sqlite3.connect(d / "s.db"), res["kpis"]


def test_parser_counts_unmatched():
    st = {}
    rows = list(parse_lines(["", "garbage", "Jan  1 00:00:01 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"], 2026, st))
    assert st == {"lines_total": 2, "lines_unmatched": 1} and len(rows) == 1


def test_all_range_matches_kpis(ds):
    conn, k = ds
    cells = {c["key"]: c for c in ov.overview(conn, "all")["cells"]}
    assert cells["failed_attempts"]["value"] == k["failed_attempts"]
    assert cells["unique_ips"]["value"] == k["unique_attacker_ips"]
    assert cells["high_critical"]["value"] == k["incidents_critical_high"]
    assert cells["failed_attempts"]["change_pct"] is None      # no previous period for "all"


def test_trust_reports_unparsed_line(ds):
    conn, _ = ds
    t = ov.trust(conn)
    assert t["lines_unmatched"] == 1 and t["unparsed_pct"] > 0


def test_severity_bars_sum_to_total(ds):
    conn, _ = ds
    o = ov.overview(conn, "7d")
    assert sum(r["attempts"] for r in o["by_severity"]["rows"]) == o["cells"][0]["value"]


def test_attackers_sorted_and_filtered(ds):
    conn, _ = ds
    a = ov.attackers(conn, "all", limit=500)
    att = [r["attempts"] for r in a["rows"]]
    assert att == sorted(att, reverse=True) and a["rows"][0]["rank"] == 1
    hi = ov.attackers(conn, "all", severity="High")
    assert all(r["severity"] == "High" for r in hi["rows"])


def test_gap_detection():
    ts = pd.to_datetime(["2026-01-01 00:10", "2026-01-01 05:00", "2026-01-03 06:00"])
    ev = pd.DataFrame({"ts": ts})
    g = ov.log_gaps(ev, min_hours=24)
    assert len(g) == 1 and g.iloc[0]["hours"] == 48


def test_change_suppressed_when_previous_period_has_gap(tmp_path):
    conn = sqlite3.connect(":memory:")
    # minimal dataset: a 20-day log with a 3-day gap inside the previous week
    meta = {"period_start": "2026-01-01 00:00:00", "period_end": "2026-01-20 00:00:00", "filename": "t.log", "lines_total": "10",
            "lines_unmatched": "0", "lines_other": "0", "unparsed_pct": "0", "run_at": "2026-01-20 00:00:00", "year": "2026"}
    pd.DataFrame({"key": list(meta), "value": list(meta.values())}).to_sql("dataset_meta", conn, index=False)
    pd.DataFrame({"start_ts": ["2026-01-08 00:00:00"], "end_ts": ["2026-01-11 00:00:00"], "hours": [72]}).to_sql("log_gaps", conn, index=False)
    ev = pd.DataFrame({"ts": ["2026-01-19 00:00:00", "2026-01-15 00:00:00"], "ip_resolved": ["1.1.1.1"] * 2, "username": ["a"] * 2,
                       "weight": [1, 1], "is_failed_attempt": [1, 1]})
    ev.to_sql("events", conn, index=False)
    pd.DataFrame({"incident_id": [], "severity": [], "start_ts": []}).to_sql("incidents", conn, index=False)
    pd.DataFrame({"hour": [], "attempts": []}).to_sql("hourly_attempts", conn, index=False)
    pd.DataFrame({"start_ts": [], "end_ts": []}).to_sql("anomaly_spans", conn, index=False)
    pd.DataFrame({"ip": [], "severity": []}).to_sql("attackers", conn, index=False)
    pd.DataFrame({"result": ["Effective"]}).to_sql("control_matrix", conn, index=False)
    o = ov.overview(conn, "7d")
    assert all(c["change_pct"] is None for c in o["cells"]) and "no log lines" in o["change_note"]
