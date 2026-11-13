"""Client-style deliverables built from the pipeline results:
  * Excel workpaper (control matrix, access review, ITIL registers, summary with live formulas)
  * Word assessment report with findings in condition / criteria / effect / recommendation form
  * PowerPoint summary deck
  * Markdown incident-response runbook
Everything is generated from computed results, so it cannot drift from the data."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pandas as pd
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from openpyxl import Workbook
from openpyxl.formatting.rule import CellIsRule
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor as PRGB
from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_LEGEND_POSITION
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Emu, Inches as PIn, Pt as PPt

from .reports import executive_summary, ip_phrase

NAVY, TEAL, INK, MUTED = "14213D", "0E7C86", "1F2933", "5F6B7A"
RESULT_COLOR = {"Ineffective": "C0392B", "Partially effective": "D98E04", "Effective": "2E8B57", "Not tested": "7B8794"}
RESULT_FILL = {"Ineffective": "F8D7D3", "Partially effective": "FCE8C3", "Effective": "D5EEDD", "Not tested": "E4E7EB"}
SAMPLE_NOTE = "Sample assessment prepared on public Loghub OpenSSH data. Not client data."


# ============================================================================= helpers
def overall_rating(matrix: pd.DataFrame, incidents: pd.DataFrame) -> str:
    crit = len(incidents) and (incidents["severity"] == "Critical").any()
    if crit or (matrix["result"] == "Ineffective").any():
        return "High"
    return "Medium" if (matrix["result"] == "Partially effective").any() else "Low"


def _tested(matrix):
    return matrix[matrix["result"] != "Not tested"]


def headline(matrix: pd.DataFrame) -> str:
    t = _tested(matrix)
    n_bad = int((t["result"] == "Ineffective").sum())
    return f"{n_bad} of {len(t)} tested controls are ineffective against SSH password attacks" if n_bad else f"{len(t)} controls tested, none ineffective"


def _recs(res: dict, matrix: pd.DataFrame, blocklist_n: int) -> dict[str, list[str]]:
    inc = res["incidents"]
    bad = set(matrix.loc[matrix["result"].isin(["Ineffective", "Partially effective"]), "control_id"])
    imm, short, gov = [], [], []
    if len(inc) and (inc["rule"] == "SUCCESS_AFTER_FAILURES").any():
        who = ", ".join(sorted(set(inc.loc[inc["rule"] == "SUCCESS_AFTER_FAILURES", "username"].dropna().astype(str))))
        imm.append(f"Investigate and reset credentials for {who}")
    if blocklist_n:
        imm.append(f"Apply the block list ({blocklist_n} High/Critical IPs) after a shared-address check")
    imm.append("Alert on 5 failed logins in 5 minutes from one IP")
    if "SM-01" in bad:
        short.append("Deploy fail2ban: 5 failures in 5 minutes, 24 hour ban")
    if "AC-03" in bad:
        short.append("Disable direct root login; use named accounts with sudo")
    if "AC-01" in bad or "AC-02" in bad:
        short.append("Require keys or MFA; disable password login")
    if "CM-01" in bad:
        short.append("Align sshd MaxAuthTries with the PAM limit")
    gov += ["Raise changes CHG-001 to CHG-006 for approval", "Send alerts to the SIEM and ticketing queue", "Re-run this assessment after the fixes to evidence improvement"]
    return {"Immediate": imm, "Short term": short or ["No further technical changes required"], "Governance": gov}


# ============================================================================= Excel
def _style_table(ws, df, header_row, widths, fill="14213D"):
    thin = Side(style="thin", color="D0D5DB")
    for j, col in enumerate(df.columns, 1):
        c = ws.cell(row=header_row, column=j, value=col.replace("_", " ").title())
        c.font, c.fill = Font(name="Arial", size=10, bold=True, color="FFFFFF"), PatternFill("solid", fgColor=fill)
        c.alignment, c.border = Alignment(wrap_text=True, vertical="center"), Border(bottom=thin)
        ws.column_dimensions[get_column_letter(j)].width = widths.get(col, 16)
    for i, row in enumerate(df.itertuples(index=False), header_row + 1):
        for j, v in enumerate(row, 1):
            c = ws.cell(row=i, column=j, value=None if pd.isna(v) else v)
            c.font, c.alignment, c.border = Font(name="Arial", size=10), Alignment(wrap_text=True, vertical="top"), Border(bottom=thin)
    ws.freeze_panes = ws.cell(row=header_row + 1, column=1)
    if len(df):
        ws.auto_filter.ref = f"A{header_row}:{get_column_letter(len(df.columns))}{header_row + len(df)}"


def _title(ws, text, sub):
    ws["A1"], ws["A2"] = text, sub
    ws["A1"].font, ws["A2"].font = Font(name="Arial", size=14, bold=True, color=NAVY), Font(name="Arial", size=9, italic=True, color=MUTED)


def _result_cf(ws, rng):
    for label, fill in RESULT_FILL.items():
        ws.conditional_formatting.add(rng, CellIsRule(operator="equal", formula=[f'"{label}"'], fill=PatternFill("solid", bgColor=fill, fgColor=fill)))


def build_workbook(path: Path, res: dict, matrix, access, reg, problems, changes, source: str) -> None:
    wb = Workbook()
    k = res["kpis"]
    # ---- Control Matrix
    cm = wb.active
    cm.title = "Control Matrix"
    _title(cm, "Control test matrix", "Automated tests on log evidence. Yellow cells are for the reviewer to complete. Exception rate is a formula.")
    show = matrix.copy()
    show["exception_rate"] = None
    show["tested_by"] = "Automated log analytics"
    for c in ("reviewer_sign_off", "management_response", "target_date"):
        show[c] = None
    show = show[["control_id", "domain", "control_objective", "risk_addressed", "test_procedure", "population_description", "population", "exceptions",
                 "exception_rate", "result", "evidence", "recommendation", "framework_reference", "tested_by", "reviewer_sign_off", "management_response", "target_date"]]
    widths = {"control_id": 9, "domain": 16, "control_objective": 38, "risk_addressed": 34, "test_procedure": 38, "population_description": 24, "population": 11,
              "exceptions": 11, "exception_rate": 11, "result": 17, "evidence": 44, "recommendation": 44, "framework_reference": 28, "tested_by": 18,
              "reviewer_sign_off": 16, "management_response": 28, "target_date": 13}
    h = 4
    _style_table(cm, show, h, widths)
    first, last = h + 1, h + len(show)
    yellow = PatternFill("solid", fgColor="FFF3B0")
    for r in range(first, last + 1):
        cm.cell(row=r, column=9, value=f'=IF(G{r}=0,"n/a",H{r}/G{r})').number_format = "0.0%"
        for col in (7, 8):
            cm.cell(row=r, column=col).number_format = "#,##0"
        for col in (15, 16, 17):
            cm.cell(row=r, column=col).fill = yellow
        cm.row_dimensions[r].height = 92
    _result_cf(cm, f"J{first}:J{last}")

    # ---- Access Review
    ar = wb.create_sheet("Access Review")
    _title(ar, "Access review", "One row per account seen in the logs. Rating: High = privileged login or login after failures; Medium = weak or unusual access, or sustained attack on a real account.")
    _style_table(ar, access, 4, {"username": 16, "account_type": 13, "exists_on_server": 16, "failed_attempts": 12, "successful_logins": 12, "source_ips_success": 12,
                                 "password_logins": 12, "offhours_logins": 12, "after_failures": 12, "risk_rating": 11, "review_flags": 60})
    for lab, fill in (("High", "F8D7D3"), ("Medium", "FCE8C3"), ("Low", "D5EEDD")):
        ar.conditional_formatting.add(f"J5:J{4 + max(len(access), 1)}", CellIsRule(operator="equal", formula=[f'"{lab}"'], fill=PatternFill("solid", bgColor=fill, fgColor=fill)))

    # ---- ITIL registers
    ir = wb.create_sheet("Incident Register")
    _title(ir, "ITIL incident register", "SLA due times use illustrative targets (P1 15 min / 4 h, P2 1 h / 8 h, P3 8 h / 72 h, P4 7 d / 10 d). Status is 'New' because no analyst has triaged these yet.")
    ireg = reg.head(5000)
    _style_table(ir, ireg, 4, {"incident_id": 12, "category": 16, "subcategory": 34, "priority": 9, "impact": 9, "urgency": 9, "severity": 10, "detected_at": 18, "status": 20,
                               "assignment_group": 24, "response_due": 18, "resolution_due": 18, "source": 26, "description": 56, "mitre_technique": 11,
                               "recommended_action": 56, "linked_problem": 12})
    pr = wb.create_sheet("Problem Register")
    _title(pr, "ITIL problem register", "Root causes behind groups of incidents. Root cause is a hypothesis until confirmed by a configuration review.")
    _style_table(pr, problems, 4, {"problem_id": 10, "title": 38, "root_cause_hypothesis": 50, "linked_incidents": 11, "highest_priority": 11, "workaround": 38, "permanent_fix": 44,
                                   "status": 22, "owner": 22})
    for r in range(5, 5 + len(problems)):
        pr.row_dimensions[r].height = 62
    ch = wb.create_sheet("Change Requests")
    _title(ch, "Proposed change requests", "Raised from the problem register. Approval column is for the change advisory board.")
    _style_table(ch, changes, 4, {"change_id": 10, "description": 54, "change_type": 12, "risk": 9, "rollback_plan": 48, "linked_problem": 12, "approval": 16, "status": 30})
    for r in range(5, 5 + len(changes)):
        ch.row_dimensions[r].height = 44
        ch.cell(row=r, column=7).fill = yellow

    # ---- Top attackers
    ta = wb.create_sheet("Top Attackers")
    _title(ta, "Top 50 attacking IPs by risk score", "Score components (c_*) are points contributed to the 0-100 score.")
    cols = [c for c in res["ip_risk"].columns if c not in ("first_seen", "last_seen")] + ["first_seen", "last_seen"]
    t = res["ip_risk"].head(50)[cols].copy()
    for c in ("first_seen", "last_seen"):
        t[c] = pd.to_datetime(t[c]).dt.strftime("%Y-%m-%d %H:%M")
    _style_table(ta, t, 4, {"ip": 18, "risk_tier": 11})

    # ---- Notes
    nt = wb.create_sheet("Notes")
    _title(nt, "Method, assumptions and sign-off", "")
    notes = [
        "Data: " + source + ". Public Loghub OpenSSH logs; not client data.",
        "Attempts: only 'Failed password' lines count as failed attempts; repeated-message lines are expanded.",
        "Tests are automated from log evidence. A control with no population (for example no successful logins) is marked Not tested, never Effective.",
        "Result scale: Effective / Partially effective / Ineffective / Not tested.",
        "SLA targets and the working-hours window (07:00-19:59) are illustrative defaults; replace with the client's agreed values.",
        "Thresholds for detection rules are in sla/config.py.",
        "", "Prepared by: Priyangi Singh Chouhan", "Reviewed by: ____________________    Date: ____________",
    ]
    for i, n in enumerate(notes, 3):
        nt.cell(row=i, column=1, value=n).font = Font(name="Arial", size=10)
    nt.column_dimensions["A"].width = 120

    # ---- Summary (first sheet, live formulas)
    sm = wb.create_sheet("Summary", 0)
    _title(sm, "Cyber risk assessment: SSH access monitoring and controls", SAMPLE_NOTE)
    label = Font(name="Arial", size=10, bold=True)
    body = Font(name="Arial", size=10)
    facts = [("Source", source), ("Period", f"{k['period_start'][:16]} to {k['period_end'][:16]}"), ("Log events analysed", k["log_events"]),
             ("Failed login attempts", k["failed_attempts"]), ("Unique attacker IPs", k["unique_attacker_ips"]), ("Overall rating", overall_rating(matrix, res["incidents"]))]
    for i, (a, b) in enumerate(facts, 4):
        sm.cell(row=i, column=1, value=a).font = label
        c = sm.cell(row=i, column=2, value=b)
        c.font, c.alignment = body, Alignment(horizontal="left")
        if isinstance(b, int):
            c.number_format = "#,##0"
    r0 = 11
    sm.cell(row=r0, column=1, value="Control test results").font = Font(name="Arial", size=11, bold=True, color=NAVY)
    for j, hname in enumerate(("Result", "Controls", "Share of controls"), 1):
        c = sm.cell(row=r0 + 1, column=j, value=hname)
        c.font, c.fill = Font(name="Arial", size=10, bold=True, color="FFFFFF"), PatternFill("solid", fgColor=NAVY)
    cm_rng = f"'Control Matrix'!$J${first}:$J${last}"
    for i, lab in enumerate(("Ineffective", "Partially effective", "Effective", "Not tested"), r0 + 2):
        sm.cell(row=i, column=1, value=lab).font = body
        sm.cell(row=i, column=2, value=f'=COUNTIF({cm_rng},A{i})').font = body
        c = sm.cell(row=i, column=3, value=f"=IF($B${r0 + 6}=0,0,B{i}/$B${r0 + 6})")
        c.number_format, c.font = "0%", body
    sm.cell(row=r0 + 6, column=1, value="Total controls").font = label
    sm.cell(row=r0 + 6, column=2, value=f"=SUM(B{r0 + 2}:B{r0 + 5})").font = label
    sm.cell(row=r0 + 7, column=1, value="Share effective (of tested)").font = label
    c = sm.cell(row=r0 + 7, column=2, value=f"=IF(B{r0 + 6}-B{r0 + 5}=0,\"n/a\",B{r0 + 4}/(B{r0 + 6}-B{r0 + 5}))")
    c.number_format, c.font = "0%", label
    _result_cf(sm, f"A{r0 + 2}:A{r0 + 5}")

    r1 = r0 + 10
    sm.cell(row=r1, column=1, value="Incidents by ITIL priority").font = Font(name="Arial", size=11, bold=True, color=NAVY)
    for j, hname in enumerate(("Priority", "Incidents", "Response target"), 1):
        c = sm.cell(row=r1 + 1, column=j, value=hname)
        c.font, c.fill = Font(name="Arial", size=10, bold=True, color="FFFFFF"), PatternFill("solid", fgColor=NAVY)
    pr_rng = f"'Incident Register'!$D$5:$D${4 + max(len(ireg), 1)}"
    targets = {"P1": "15 minutes", "P2": "1 hour", "P3": "8 hours", "P4": "7 days"}
    for i, p in enumerate(("P1", "P2", "P3", "P4"), r1 + 2):
        sm.cell(row=i, column=1, value=p).font = body
        sm.cell(row=i, column=2, value=f"=COUNTIF({pr_rng},A{i})").font = body
        sm.cell(row=i, column=3, value=targets[p]).font = body
    sm.cell(row=r1 + 6, column=1, value="Total incidents").font = label
    sm.cell(row=r1 + 6, column=2, value=f"=SUM(B{r1 + 2}:B{r1 + 5})").font = label

    r2 = r1 + 9
    sm.cell(row=r2, column=1, value="Accounts by review rating").font = Font(name="Arial", size=11, bold=True, color=NAVY)
    ar_rng = f"'Access Review'!$J$5:$J${4 + max(len(access), 1)}"
    for i, p in enumerate(("High", "Medium", "Low"), r2 + 1):
        sm.cell(row=i, column=1, value=p).font = body
        sm.cell(row=i, column=2, value=f"=COUNTIF({ar_rng},A{i})").font = body
    sm.column_dimensions["A"].width = 32
    sm.column_dimensions["B"].width = 34
    sm.column_dimensions["C"].width = 20
    wb.save(path)


# ============================================================================= Word
def _shade(cell, hex_):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear"), shd.set(qn("w:color"), "auto"), shd.set(qn("w:fill"), hex_)
    tcPr.append(shd)


def _no_split(row):
    trPr = row._tr.get_or_add_trPr()
    trPr.append(OxmlElement("w:cantSplit"))


def _set_font_name(style):
    rpr = style.element.get_or_add_rPr()
    rf = rpr.find(qn("w:rFonts"))
    if rf is None:
        rf = OxmlElement("w:rFonts")
        rpr.append(rf)
    for a in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
        if rf.get(qn(a)) is not None:
            del rf.attrib[qn(a)]
    for a in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
        rf.set(qn(a), "Arial")


def _font(run, size=10.5, bold=False, color=INK, italic=False):
    run.font.name, run.font.size, run.font.bold, run.font.italic = "Arial", Pt(size), bold, italic
    run.font.color.rgb = RGBColor.from_string(color)
    run._element.rPr.rFonts.set(qn("w:eastAsia"), "Arial")


def _table(doc, header, rows, widths, result_col=None, font=9):
    t = doc.add_table(rows=1, cols=len(header))
    t.style, t.alignment, t.autofit = "Table Grid", WD_TABLE_ALIGNMENT.CENTER, False
    for j, h in enumerate(header):
        c = t.rows[0].cells[j]
        c.width = Inches(widths[j])
        _shade(c, NAVY)
        p = c.paragraphs[0]
        _font(p.add_run(h), font, True, "FFFFFF")
    for j, w in enumerate(widths):
        t.columns[j].width = Inches(w)
    for row in rows:
        r_ = t.add_row()
        _no_split(r_)
        cells = r_.cells
        for j, v in enumerate(row):
            cells[j].width = Inches(widths[j])
            p = cells[j].paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            _font(p.add_run(str(v)), font, bold=(j == result_col), color=RESULT_COLOR.get(str(v), INK) if j == result_col else INK)
            if j == result_col and str(v) in RESULT_FILL:
                _shade(cells[j], RESULT_FILL[str(v)])
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


def _field(paragraph, instr):
    r = paragraph.add_run()
    for kind, txt in (("begin", None), (None, instr), ("end", None)):
        if kind:
            el = OxmlElement("w:fldChar")
            el.set(qn("w:fldCharType"), kind)
        else:
            el = OxmlElement("w:instrText")
            el.set(qn("xml:space"), "preserve")
            el.text = txt
        r._r.append(el)
    _font(r, 8, color=MUTED)


def build_report_docx(path: Path, res: dict, matrix, reg, problems, source: str, blocklist_n: int) -> None:
    k, inc = res["kpis"], res["incidents"]
    doc = Document()
    sec = doc.sections[0]
    sec.left_margin = sec.right_margin = Inches(0.9)
    sec.top_margin = sec.bottom_margin = Inches(0.9)
    for name, size, col in (("Normal", 10.5, INK), ("Heading 1", 15, NAVY), ("Heading 2", 12, TEAL)):
        s = doc.styles[name]
        s.font.name, s.font.size, s.font.bold = "Arial", Pt(size), name != "Normal"
        s.font.color.rgb = RGBColor.from_string(col)
        _set_font_name(s)
        if name != "Normal":
            s.paragraph_format.space_before, s.paragraph_format.space_after, s.paragraph_format.keep_with_next = Pt(14 if name == "Heading 1" else 10), Pt(4), True
    fp = sec.footer.paragraphs[0]
    _font(fp.add_run(SAMPLE_NOTE + "    Page "), 8, color=MUTED)
    _field(fp, "PAGE")

    rating = overall_rating(matrix, inc)
    p = doc.add_paragraph()
    _font(p.add_run("Cyber Risk Assessment"), 24, True, NAVY)
    p = doc.add_paragraph()
    _font(p.add_run("SSH access monitoring and controls"), 14, False, TEAL)
    meta = [("Prepared by", "Priyangi Singh Chouhan"), ("Date", datetime.now().strftime("%d %B %Y")), ("Data source", source),
            ("Period covered", f"{k['period_start'][:16]} to {k['period_end'][:16]}"), ("Status", "Draft for review"), ("Overall risk rating", rating)]
    t = doc.add_table(rows=0, cols=2)
    t.style, t.autofit = "Table Grid", False
    t.columns[0].width, t.columns[1].width = Inches(1.8), Inches(4.9)
    for a, b in meta:
        cells = t.add_row().cells
        cells[0].width, cells[1].width = Inches(1.8), Inches(4.9)
        _shade(cells[0], "EEF1F5")
        _font(cells[0].paragraphs[0].add_run(a), 10, True)
        _font(cells[1].paragraphs[0].add_run(b), 10, bold=(a == "Overall risk rating"), color={"High": "C0392B", "Medium": "D98E04", "Low": "2E8B57"}.get(b, INK))
    p = doc.add_paragraph()
    _font(p.add_run(SAMPLE_NOTE), 9, italic=True, color=MUTED)

    doc.add_heading("1. Executive summary", 1)
    doc.add_paragraph(executive_summary(k, inc, res["outlook"]).replace("**", ""))
    t_ = _tested(matrix)
    doc.add_paragraph(f"Of {len(matrix)} controls, {len(t_)} could be tested from the available evidence: "
                      f"{int((t_['result'] == 'Ineffective').sum())} ineffective, {int((t_['result'] == 'Partially effective').sum())} partially effective and "
                      f"{int((t_['result'] == 'Effective').sum())} effective. {len(matrix) - len(t_)} could not be tested because the logs contain no relevant events.")

    doc.add_heading("2. Scope and approach", 1)
    for b in ("Scope: authentication activity on one SSH server, from the sshd logs supplied.",
              "Approach: log events were parsed and loaded into a SQL database; five detection rules mapped to MITRE ATT&CK raised incidents; nine control tests were run against ISO/IEC 27001:2022 and NIST CSF 2.0 references.",
              "Counting: only failed-password lines count as attempts, so one login attempt is never counted several times.",
              "Out of scope: network devices, application logs and any system other than this SSH server."):
        doc.add_paragraph(b, style="List Bullet")

    doc.add_heading("3. Results at a glance", 1)
    _table(doc, ["ID", "Control objective", "Exceptions / population", "Result"],
           [(r.control_id, r.control_objective, f"{r.exceptions:,} / {r.population:,}", r.result) for r in matrix.itertuples()], [0.6, 3.7, 1.3, 1.2], result_col=3)

    doc.add_heading("4. Detailed findings", 1)
    bad = matrix[matrix["result"].isin(["Ineffective", "Partially effective"])].copy()
    bad["o"] = bad["result"].map({"Ineffective": 0, "Partially effective": 1})
    for n, r in enumerate(bad.sort_values("o").itertuples(), 1):
        doc.add_heading(f"F-{n:02d}  {r.control_id}: {r.control_objective}", 2)
        _table(doc, ["Element", "Detail"], [("Rating", "High" if r.result == "Ineffective" else "Medium"), ("Condition (what we found)", r.evidence),
                                           ("Criteria (what should be true)", f"{r.control_objective} Reference: {r.framework_reference}."), ("Risk (why it matters)", r.risk_addressed),
                                           ("Recommendation", r.recommendation)], [1.8, 4.9], font=9)
    if bad.empty:
        doc.add_paragraph("No exceptions were identified.")

    doc.add_heading("5. Incident summary", 1)
    if len(inc):
        counts = inc.groupby("priority").size().reindex(["P1", "P2", "P3", "P4"], fill_value=0)
        doc.add_paragraph(f"{len(inc):,} incidents were raised: " + ", ".join(f"{p} {int(c):,}" for p, c in counts.items()) + ". Top incidents by priority:")
        top = reg.head(6)
        _table(doc, ["ID", "Priority", "Type", "Source", "Detail"], [(r.incident_id, r.priority, r.subcategory, r.source, r.description) for r in top.itertuples()], [0.8, 0.6, 1.5, 1.3, 2.5], font=8)
    else:
        doc.add_paragraph("No incidents were raised.")

    doc.add_heading("6. Recommendations and roadmap", 1)
    rec = _recs(res, matrix, blocklist_n)
    when = {"Immediate": "Within days", "Short term": "Within 30 days", "Governance": "Within 60 days"}
    _table(doc, ["Horizon", "Action", "Timing"], [(h, a, when[h]) for h, items in rec.items() for a in items], [1.2, 4.2, 1.3], font=9)
    if len(problems):
        doc.add_paragraph("Underlying problems are tracked as PRB records and the fixes as CHG records in the accompanying Excel workpaper.")

    doc.add_heading("7. Outlook", 1)
    doc.add_paragraph(res["outlook"]["message"] if res["outlook"].get("ratio") is not None else
                      "A forecast could not be produced because the logs cover under 7 days. Run the assessment on a longer period for a risk outlook.")
    doc.add_heading("8. Limitations", 1)
    for b in ("Findings come from one log source; they describe observed behaviour, not the server's full configuration.",
              "An IP address is not a person; review the block list for shared addresses before enforcing it.",
              "Thresholds and SLA targets are illustrative defaults and should be agreed with the client.",
              "Forecasts describe likely volume from past behaviour and cannot anticipate a new campaign."):
        doc.add_paragraph(b, style="List Bullet")
    doc.add_heading("Appendix A. Management response", 1)
    _table(doc, ["Finding", "Management response", "Owner", "Target date"], [(f"F-{i:02d}", "", "", "") for i in range(1, max(len(bad), 1) + 1)], [0.8, 3.3, 1.4, 1.2])
    doc.save(path)


# ============================================================================= PowerPoint
def _rgb(h):
    return PRGB.from_string(h)


def _bullet(p):
    from lxml import etree
    pPr = p._p.get_or_add_pPr()
    pPr.set("marL", "285750"), pPr.set("indent", "-285750")
    etree.SubElement(pPr, qn_a("buChar"), char="\u2022")


def qn_a(tag):
    return "{http://schemas.openxmlformats.org/drawingml/2006/main}" + tag


def _tb(slide, x, y, w, h, text, size=16, bold=False, color=INK, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, font="Arial", space_after=0, bullets=False):
    box = slide.shapes.add_textbox(PIn(x), PIn(y), PIn(w), PIn(h))
    tf = box.text_frame
    tf.word_wrap, tf.vertical_anchor = True, anchor
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    lines = text if isinstance(text, list) else [text]
    for i, ln in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        p.space_after = PPt(space_after)
        if bullets:
            _bullet(p)
        r = p.add_run()
        r.text = ln
        r.font.name, r.font.size, r.font.bold = font, PPt(size), bold
        r.font.color.rgb = _rgb(color)
    return box


def _bg(slide, hex_):
    f = slide.background.fill
    f.solid()
    f.fore_color.rgb = _rgb(hex_)


def _style_chart(chart, size=12):
    chart.font.size, chart.font.name = PPt(size), "Arial"
    chart.font.color.rgb = _rgb(MUTED)


def build_deck(path: Path, res: dict, matrix, source: str, blocklist_n: int) -> None:
    k, inc = res["kpis"], res["incidents"]
    prs = Presentation()
    prs.slide_width, prs.slide_height = PIn(13.333), PIn(7.5)
    blank = prs.slide_layouts[6]
    rating = overall_rating(matrix, inc)

    def content_slide(title, notes):
        s = prs.slides.add_slide(blank)
        _bg(s, "FFFFFF")
        _tb(s, 0.6, 0.45, 12.1, 1.0, title, 30, True, NAVY, anchor=MSO_ANCHOR.TOP)
        _tb(s, 0.6, 7.0, 9, 0.3, SAMPLE_NOTE, 10, color=MUTED)
        s.notes_slide.notes_text_frame.text = notes
        return s

    # 1 title
    s = prs.slides.add_slide(blank)
    _bg(s, NAVY)
    _tb(s, 0.9, 2.2, 11.5, 1.6, "SSH access monitoring: cyber risk assessment", 42, True, "FFFFFF")
    _tb(s, 0.9, 4.0, 11.5, 0.5, "What the server logs show, which controls fail, and what to fix first", 20, color="BFD3E6")
    _tb(s, 0.9, 6.3, 11.5, 0.8, [f"Priyangi Singh Chouhan   |   {datetime.now():%d %B %Y}", SAMPLE_NOTE], 12, color="9FB3C8")
    s.notes_slide.notes_text_frame.text = "Introduce the purpose: turn raw SSH logs into a client-ready view of attacks, control gaps and priorities."

    # 2 key findings
    s = content_slide(headline(matrix), "State the overall rating first, then the three numbers. These come straight from the pipeline output.")
    stats = [(f"{k['failed_attempts']:,}", "failed login attempts"), (f"{k['unique_attacker_ips']:,}", "distinct attacker IPs"),
             (f"{k['incidents_critical_high']:,}", "High or Critical incidents")]
    for i, (num, lab) in enumerate(stats):
        x = 0.6 + i * 4.1
        card = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, PIn(x), PIn(1.9), PIn(3.8), PIn(1.9))
        card.fill.solid(), card.line.fill.background()
        card.fill.fore_color.rgb = _rgb("EEF3F8")
        card.adjustments[0] = 0.08
        _tb(s, x + 0.3, 2.1, 3.3, 1.0, num, 44, True, NAVY)
        _tb(s, x + 0.3, 3.2, 3.3, 0.4, lab, 16, color=MUTED)
    col = {"High": "C0392B", "Medium": "D98E04", "Low": "2E8B57"}[rating]
    _tb(s, 0.6, 4.3, 3.3, 0.4, "Overall risk rating", 16, color=MUTED)
    _tb(s, 0.6, 4.75, 3.3, 0.9, rating, 40, True, col)
    top_ip = k.get("top10_ip_share_pct")
    pts = [f"{k['ips_for_50pct']} IP{'s' if k['ips_for_50pct'] != 1 else ''} produce{'' if k['ips_for_50pct'] != 1 else 's'} half of all attempts, so targeted blocking works." if k.get("ips_for_50pct") else "",
           f"root and admin take {k['root_admin_share_pct']}% of guesses." if "root_admin_share_pct" in k else "",
           "A login succeeded after repeated failures: investigate now." if len(inc) and (inc["rule"] == "SUCCESS_AFTER_FAILURES").any() else "No login followed a run of failures."]
    _tb(s, 4.3, 4.3, 8.4, 2.6, [p for p in pts if p], 20, color=INK, space_after=12, bullets=True)

    # 3 attackers
    top = res["ip_risk"].sort_values("attempts", ascending=False).head(8)
    s = content_slide(f"{ip_phrase(k['ips_for_50pct'])} for half of all failed attempts" if k.get("ips_for_50pct") else "Attack volume by source IP",
                      "Show concentration: a few sources dominate, which is why blocking and rate limiting are effective.")
    cd = CategoryChartData()
    cd.categories = list(top["ip"][::-1])
    cd.add_series("Failed attempts", [int(v) for v in top["attempts"][::-1]])
    gf = s.shapes.add_chart(XL_CHART_TYPE.BAR_CLUSTERED, PIn(0.6), PIn(1.6), PIn(8.2), PIn(5.2), cd)
    ch = gf.chart
    _style_chart(ch)
    ch.has_legend, ch.has_title = False, False
    pl = ch.plots[0]
    pl.gap_width, pl.has_data_labels = 60, True
    pl.data_labels.font.size, pl.data_labels.position = PPt(12), XL_LABEL_POSITION.OUTSIDE_END
    pl.series[0].format.fill.solid()
    pl.series[0].format.fill.fore_color.rgb = _rgb(TEAL)
    ch.value_axis.has_major_gridlines, ch.value_axis.visible = False, False
    ch.category_axis.format.line.fill.background()
    _tb(s, 9.3, 1.8, 3.5, 4.8, [f"Top 10 IPs: {k['top10_ip_share_pct']}% of attempts", "", f"Median attacker makes {k['median_attempts_per_ip']:.0f} attempts, so a long tail of one-off probes sits under a few persistent sources.", "",
                                f"{k['invalid_user_share_pct']}% of guesses use usernames that do not exist, which marks automated attacks."], 18, color=INK)

    # 4 controls
    cnt = matrix["result"].value_counts()
    s = content_slide(f"Control results: {cnt.get('Ineffective', 0)} ineffective, {cnt.get('Partially effective', 0)} partial, {cnt.get('Effective', 0)} effective"
                      + (f", {cnt.get('Not tested', 0)} not tested" if cnt.get("Not tested", 0) else ""), "Walk the table top to bottom. Red rows are the priority for remediation.")
    rows = len(matrix) + 1
    tbl = s.shapes.add_table(rows, 4, PIn(0.6), PIn(1.55), PIn(12.1), PIn(0.46 * rows)).table
    for j, w in enumerate((0.9, 7.3, 2.0, 1.9)):
        tbl.columns[j].width = PIn(w)
    for j, hname in enumerate(("ID", "Control objective", "Exceptions / population", "Result")):
        c = tbl.cell(0, j)
        c.text = hname
        c.fill.solid()
        c.fill.fore_color.rgb = _rgb(NAVY)
        r = c.text_frame.paragraphs[0].runs[0]
        r.font.size, r.font.bold, r.font.name, r.font.color.rgb = PPt(13), True, "Arial", _rgb("FFFFFF")
    for i, rw in enumerate(matrix.itertuples(), 1):
        vals = (rw.control_id, rw.control_objective, f"{rw.exceptions:,} / {rw.population:,}", rw.result)
        for j, v in enumerate(vals):
            c = tbl.cell(i, j)
            c.text = str(v)
            c.fill.solid()
            c.fill.fore_color.rgb = _rgb(RESULT_FILL[rw.result] if j == 3 else "FFFFFF")
            c.margin_top = c.margin_bottom = PIn(0.03)
            r = c.text_frame.paragraphs[0].runs[0]
            r.font.size, r.font.name, r.font.bold = PPt(12), "Arial", j == 3
            r.font.color.rgb = _rgb(RESULT_COLOR[rw.result] if j == 3 else INK)

    # 5 pattern or forecast
    fd = res["forecast"].get("daily")
    if fd is not None and fd.status == "ok":
        s = content_slide(res["outlook"].get("headline") or "Forecast of failed attempts", "Observed daily volume, then the 7-day forecast with its backtested model.")
        from .forecast import complete_days
        from .kpis import hourly_attempts
        hist = complete_days(hourly_attempts(res["events"])).tail(14)
        cd = CategoryChartData()
        cd.categories = [d.strftime("%d %b") for d in hist.index] + [d.strftime("%d %b") for d in fd.forecast["ts"]]
        cd.add_series("Observed", [int(v) for v in hist.values] + [None] * len(fd.forecast))
        cd.add_series("Forecast", [None] * len(hist) + [float(v) for v in fd.forecast["yhat"]])
        gf = s.shapes.add_chart(XL_CHART_TYPE.COLUMN_CLUSTERED, PIn(0.6), PIn(1.6), PIn(12.1), PIn(5.2), cd)
        ch = gf.chart
        _style_chart(ch)
        ch.has_legend, ch.has_title = True, False
        ch.legend.position, ch.legend.include_in_layout = XL_LEGEND_POSITION.TOP, False
        ch.plots[0].overlap, ch.plots[0].gap_width = 100, 40
        for ser, colr in zip(ch.plots[0].series, ("14213D", TEAL)):
            ser.format.fill.solid(), setattr(ser.format.fill.fore_color, "rgb", _rgb(colr))
        ch.value_axis.major_gridlines.format.line.color.rgb = _rgb("E1E5EA")
    else:
        hod = k.get("attempts_by_hour_of_day", {})
        s = content_slide("When attempts arrive, by hour of day (server time)", "The log is too short for a forecast; this view shows the timing pattern instead.")
        cd = CategoryChartData()
        cd.categories = [f"{int(h):02d}" for h in range(24)]
        cd.add_series("Failed attempts", [int(hod.get(str(h), hod.get(h, 0))) for h in range(24)])
        gf = s.shapes.add_chart(XL_CHART_TYPE.COLUMN_CLUSTERED, PIn(0.6), PIn(1.6), PIn(12.1), PIn(4.9), cd)
        ch = gf.chart
        _style_chart(ch)
        ch.has_legend = ch.has_title = False
        ch.plots[0].gap_width = 50
        ch.plots[0].series[0].format.fill.solid(), setattr(ch.plots[0].series[0].format.fill.fore_color, "rgb", _rgb(TEAL))
        ch.value_axis.major_gridlines.format.line.color.rgb = _rgb("E1E5EA")
        _tb(s, 0.6, 6.55, 12, 0.35, "A forecast needs at least 7 days of logs; this extract is shorter.", 13, color=MUTED)

    # 6 recommendations
    s = content_slide("What to fix first", "Immediate actions contain risk now; short-term changes remove the cause; governance keeps it fixed.")
    rec = _recs(res, matrix, blocklist_n)
    head_col = {"Immediate": "C0392B", "Short term": "D98E04", "Governance": TEAL}
    for i, (hname, items) in enumerate(rec.items()):
        x = 0.6 + i * 4.1
        card = s.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, PIn(x), PIn(1.7), PIn(3.9), PIn(4.9))
        card.fill.solid(), card.line.fill.background()
        card.fill.fore_color.rgb = _rgb("F3F6F9")
        card.adjustments[0] = 0.04
        _tb(s, x + 0.3, 1.95, 3.3, 0.5, hname, 20, True, head_col[hname])
        _tb(s, x + 0.3, 2.7, 3.35, 3.8, items[:4], 16, color=INK, space_after=14, bullets=True)
    prs.save(path)


# ============================================================================= runbook
RUNBOOK = """# SSH incident response runbook

Use with the incident register. Times are targets from the priority table (illustrative; agree the real values with the client).

| Priority | Meaning | Respond within |
|---|---|---|
| P1 | Possible compromise (login succeeded after repeated failures) | 15 minutes |
| P2 | High-volume or privileged-account attack | 1 hour |
| P3 | Brute force or spraying with no sign of access | 1 business day |
| P4 | Scanning or low volume | Weekly triage |

## 1. Triage (all priorities)
1. Open the incident; note the source IP, account, time window and the evidence line.
2. Confirm it is real: does the IP belong to a known user, VPN or scanner you operate? If yes, close as false positive and add it to the allow-list.
3. Check whether any login succeeded from that IP: `sudo grep "Accepted" /var/log/auth.log | grep <ip>` (path varies by distribution).
4. Set the status to In progress and record the time (this starts the resolution clock).

## 2. P1: possible compromise
1. Contain: lock the account `sudo passwd -l <user>`, end its sessions `sudo pkill -KILL -u <user>`, and block the IP `sudo ufw deny from <ip>`.
2. Preserve evidence before changing anything else: copy `/var/log/auth.log*` and `last -i` output to a safe location.
3. Investigate: what did the account run after the login? Check shell history, new users, new SSH keys in `~/.ssh/authorized_keys`, cron jobs and listening ports `ss -tulpn`.
4. Eradicate: remove any persistence found; force a new credential `sudo chage -d 0 <user>`; prefer keys or MFA.
5. Escalate to the incident manager and inform the account owner. Record every action with a timestamp.

## 3. P2 and P3: brute force, spraying, distributed attack
1. Block the source: `sudo fail2ban-client set sshd banip <ip>` or a firewall rule.
2. Check targeted accounts: did any existing account receive many attempts? Review the Access Review sheet.
3. For a distributed attack on one account, add account-level throttling and consider restricting SSH to a VPN or allow-list.
4. Link the incident to its problem record (for example PRB-001) and raise or update the change request.

## 4. P4: reconnaissance
1. Monitor; block if the same source returns.
2. Confirm port 22 is meant to be reachable from the internet.

## 5. Close and learn
1. Confirm the fix held: no new incidents from the same source for 24 hours.
2. Update the incident (cause, action, time to resolve) and close it.
3. If the same cause keeps producing incidents, make sure a problem record and a change request exist.
4. Re-run the assessment after changes to evidence the improvement.
"""


# ============================================================================= entry point
def build_all(res: dict, out_dir: str | Path, source: str, cfg=None) -> dict:
    from .config import DEFAULT
    from . import grc
    cfg = cfg or DEFAULT
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    matrix = grc.control_matrix(res["events"], res["incidents"], cfg)
    access = grc.access_review(res["events"], res["incidents"], cfg)
    n_block = int(res["ip_risk"]["risk_tier"].isin(["Critical", "High"]).sum()) if len(res["ip_risk"]) else 0
    reg, problems, changes = grc.itil_registers(res["incidents"], matrix, n_block, cfg)
    build_workbook(out / "control_workpaper.xlsx", res, matrix, access, reg, problems, changes, source)
    build_report_docx(out / "client_assessment_report.docx", res, matrix, reg, problems, source, n_block)
    build_deck(out / "executive_summary.pptx", res, matrix, source, n_block)
    (out / "incident_response_runbook.md").write_text(RUNBOOK, encoding="utf-8")
    return {"control_matrix": matrix, "access_review": access, "itil_incidents": reg, "itil_problems": problems, "itil_changes": changes}
