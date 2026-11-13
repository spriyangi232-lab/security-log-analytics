from datetime import datetime, timedelta

import pandas as pd
from openpyxl import load_workbook
from docx import Document
from pptx import Presentation

from conftest import events_from
from sla import deliverables, detection, grc, pipeline

T0 = datetime(2026, 1, 5, 10, 0, 0)


def _line(t, pid, msg):
    return f"{t:%b} {t.day:>2} {t:%H:%M:%S} h sshd[{pid}]: {msg}"


def _compromise_events():
    lines = [_line(T0 + timedelta(seconds=10 * i), 5, "Failed password for admin from 4.4.4.4 port 22 ssh2") for i in range(8)]
    lines.append(_line(T0 + timedelta(minutes=3), 5, "Accepted password for admin from 4.4.4.4 port 22 ssh2"))
    return events_from(lines, year=2026)


def test_no_population_means_not_tested_never_effective():
    ev = events_from([_line(T0, 1, "Failed password for root from 1.1.1.1 port 22 ssh2")], year=2026)
    m = grc.control_matrix(ev, detection.run_all(ev)).set_index("control_id")
    assert m.loc["SM-02", "result"] == "Not tested" and m.loc["AC-02", "result"] == "Not tested"
    assert len(m) == 9


def test_compromise_fails_controls_and_creates_p1_problem():
    ev = _compromise_events()
    inc = detection.run_all(ev)
    m = grc.control_matrix(ev, inc).set_index("control_id")
    assert m.loc["SM-02", "result"] == "Ineffective" and m.loc["AC-02", "result"] != "Effective"
    reg, prob, chg = grc.itil_registers(inc, m.reset_index(), 1)
    assert "PRB-004" in set(prob["problem_id"])
    p1 = reg[reg["priority"] == "P1"].iloc[0]
    assert pd.Timestamp(p1["response_due"]) - pd.Timestamp(p1["detected_at"]) == pd.Timedelta(minutes=15)
    assert pd.Timestamp(p1["resolution_due"]) - pd.Timestamp(p1["detected_at"]) == pd.Timedelta(hours=4)
    assert chg.loc[chg["change_id"] == "CHG-004", "change_type"].iloc[0] == "Emergency"


def test_access_review_flags_privileged_login_after_failures():
    ev = _compromise_events()
    a = grc.access_review(ev, detection.run_all(ev))
    row = a[a["username"] == "admin"].iloc[0]
    assert row["risk_rating"] == "High" and "Privileged account logged in remotely" in row["review_flags"]


def test_deliverables_open_and_workbook_has_live_formulas(tmp_path, sample_log):
    pipeline.run(str(sample_log), str(tmp_path / "t.db"), str(tmp_path / "rep"), verbose=False)
    d = tmp_path / "rep" / "deliverables"
    wb = load_workbook(d / "control_workpaper.xlsx")
    assert wb.sheetnames[0] == "Summary" and "Control Matrix" in wb.sheetnames
    assert str(wb["Summary"]["B13"].value).startswith("=COUNTIF")          # results are formulas, not pasted numbers
    assert str(wb["Control Matrix"]["I5"].value).startswith("=IF(")
    doc = Document(d / "client_assessment_report.docx")
    assert any("Executive summary" in p.text for p in doc.paragraphs)
    assert len(Presentation(d / "executive_summary.pptx").slides) == 6
    assert "P1" in (d / "incident_response_runbook.md").read_text()
