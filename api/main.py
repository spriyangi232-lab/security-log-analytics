"""Read-only API over the analytics pipeline output. All numbers come from sla.overview; nothing is computed in the UI.
Datasets are SQLite files in SLA_DATA_DIR (default data/datasets) that contain a `dataset_meta` table."""
from __future__ import annotations

import csv
import io
import os
import sqlite3
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from sla import overview as ov
from . import jobs
from .schemas import JobOut, AccountPage, AttackerDetail, AttackerEvents, AttackerPage, ControlsOut, ForecastOut, IncidentPage, Overview, ReportsOut
from sla.rules import ANOMALY_RULE, ATTACKER_SEVERITY_TEXT, GAP_MIN_HOURS, RISK_COMPONENTS, RISK_FORMULA_TEXT, RISK_WEIGHTS, RULES, SEVERITY_RULES

Range = Literal["24h", "7d", "all"]
Severity = Literal["Critical", "High", "Medium", "Low", "No incident"]


class Problem(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    detail: str | None = None


app = FastAPI(title="Security Log Analytics API", version="1.0.0",
              description="Read-only API. Errors use application/problem+json.",
              responses={404: {"model": Problem}, 422: {"model": Problem}})


def data_dir() -> Path:
    return Path(os.environ.get("SLA_DATA_DIR", "data/datasets"))


def _has_meta(p: Path) -> bool:
    try:
        c = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
        try:
            return c.execute("SELECT 1 FROM sqlite_master WHERE name='dataset_meta'").fetchone() is not None
        finally:
            c.close()
    except sqlite3.Error:
        return False


def _conn(dataset_id: str) -> sqlite3.Connection:
    p = data_dir() / f"{Path(dataset_id).name}.db"
    if not p.exists() or not _has_meta(p):
        raise HTTPException(404, f"Dataset '{dataset_id}' was not found.")
    return sqlite3.connect(f"file:{p}?mode=ro", uri=True)


@app.exception_handler(HTTPException)
async def _http(_: Request, exc: HTTPException):
    return JSONResponse({"title": "Request failed", "status": exc.status_code, "detail": str(exc.detail)},
                        status_code=exc.status_code, media_type="application/problem+json")


@app.exception_handler(ValueError)
async def _val(_: Request, exc: ValueError):
    return JSONResponse({"title": "Invalid request", "status": 422, "detail": str(exc)}, status_code=422,
                        media_type="application/problem+json")


class DatasetSummary(BaseModel):
    id: str
    filename: str
    period_start: str
    period_end: str
    lines_total: int
    uploaded_at: str


@app.get("/api/v1/datasets", response_model=list[DatasetSummary], tags=["datasets"])
def list_datasets():
    out = []
    for p in sorted(data_dir().glob("*.db")) if data_dir().exists() else []:
        if p.name.startswith(".") or not _has_meta(p):
            continue
        c = _conn(p.stem)
        try:
            m = ov.meta(c)
        finally:
            c.close()
        out.append(DatasetSummary(id=p.stem, filename=m["filename"], period_start=m["period_start"],
                                  period_end=m["period_end"], lines_total=int(m["lines_total"]), uploaded_at=m["run_at"]))
    return out


@app.get("/api/v1/datasets/{dataset_id}/overview", tags=["overview"], response_model=Overview)
def get_overview(dataset_id: str, range: Range = "7d"):
    c = _conn(dataset_id)
    try:
        return ov.overview(c, range)
    finally:
        c.close()


@app.get("/api/v1/datasets/{dataset_id}/attackers", tags=["attackers"], response_model=AttackerPage)
def get_attackers(dataset_id: str, range: Range = "7d",
                  sort: Literal["rank", "ip", "attempts", "first_seen", "last_seen", "accounts", "severity"] = "attempts",
                  dir: Literal["asc", "desc"] = "desc", q: str | None = None, severity: Severity | None = None,
                  limit: int = Query(25, ge=1, le=500), offset: int = Query(0, ge=0)):
    c = _conn(dataset_id)
    try:
        return ov.attackers(c, range, sort, dir, q, severity, limit, offset)
    finally:
        c.close()


@app.get("/api/v1/datasets/{dataset_id}/attackers/{ip}", tags=["attackers"], response_model=AttackerDetail)
def get_attacker(dataset_id: str, ip: str):
    c = _conn(dataset_id)
    try:
        d = ov.attacker_detail(c, ip)
    finally:
        c.close()
    if d is None:
        raise HTTPException(404, f"No attacker with IP {ip} in this dataset.")
    return d


@app.get("/api/v1/datasets/{dataset_id}/attackers/{ip}/events", tags=["attackers"], response_model=AttackerEvents)
def get_attacker_events(dataset_id: str, ip: str, limit: int = Query(50, ge=1, le=500)):
    c = _conn(dataset_id)
    try:
        return ov.attacker_events(c, ip, limit)
    finally:
        c.close()


@app.get("/api/v1/datasets/{dataset_id}/exports/attackers.csv", tags=["exports"])
def export_attackers(dataset_id: str, range: Range = "7d", severity: Severity | None = None) -> Response:
    c = _conn(dataset_id)
    try:
        d = ov.attackers(c, range, severity=severity, limit=100000)
    finally:
        c.close()
    cols = ["rank", "ip", "attempts", "first_seen", "last_seen", "accounts", "severity", "techniques", "action"]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(cols)
    for r in d["rows"]:
        w.writerow([";".join(r[k]) if k == "techniques" else r[k] for k in cols])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="attackers_{dataset_id}_{range}.csv"'})


@app.get("/api/v1/rules", tags=["rules"])
def get_rules() -> dict:
    """Every rule, threshold and formula behind a number on screen (the 'How is this calculated?' source)."""
    return {"detection": [{"id": k, "title": v["title"], "technique_id": v["technique_id"], "technique": v["technique"],
                           "tactic": v["tactic"], "plain": v["plain"], "action": v["action"],
                           "severity_rule": SEVERITY_RULES[k]["text"] if k in SEVERITY_RULES else None}
                          for k, v in RULES.items()],
            "attacker_severity": ATTACKER_SEVERITY_TEXT, "risk_formula": RISK_FORMULA_TEXT,
            "risk_components": RISK_COMPONENTS, "risk_weights": RISK_WEIGHTS, "anomaly_rule": ANOMALY_RULE, "gap_rule_hours": GAP_MIN_HOURS}


@app.get("/api/v1/datasets/{dataset_id}/accounts", tags=["accounts"], response_model=AccountPage)
def get_accounts(dataset_id: str, range: Range = "7d",
                 sort: Literal["username", "attempts", "source_ips", "share_pct", "last_seen", "successful_logins"] = "attempts",
                 dir: Literal["asc", "desc"] = "desc", q: str | None = None,
                 limit: int = Query(25, ge=1, le=500), offset: int = Query(0, ge=0)):
    c = _conn(dataset_id)
    try:
        return ov.accounts(c, range, sort, dir, q, limit, offset)
    finally:
        c.close()


@app.get("/api/v1/datasets/{dataset_id}/incidents", tags=["incidents"], response_model=IncidentPage)
def get_incidents(dataset_id: str, range: Range = "7d", rule: str | None = None, severity: Severity | None = None,
                  q: str | None = None, sort: Literal["start_ts", "incident_id", "severity", "attempts", "ip"] = "start_ts",
                  dir: Literal["asc", "desc"] = "desc", limit: int = Query(25, ge=1, le=500), offset: int = Query(0, ge=0)):
    c = _conn(dataset_id)
    try:
        return ov.incidents(c, range, rule, severity, q, sort, dir, limit, offset)
    finally:
        c.close()


@app.get("/api/v1/datasets/{dataset_id}/controls", tags=["controls"], response_model=ControlsOut)
def get_controls(dataset_id: str):
    c = _conn(dataset_id)
    try:
        return ov.controls(c)
    finally:
        c.close()


@app.get("/api/v1/datasets/{dataset_id}/forecast", tags=["forecast"], response_model=ForecastOut)
def get_forecast(dataset_id: str):
    c = _conn(dataset_id)
    try:
        return ov.forecast(c)
    finally:
        c.close()


@app.get("/api/v1/datasets/{dataset_id}/reports", tags=["reports"], response_model=ReportsOut)
def get_reports(dataset_id: str):
    c = _conn(dataset_id)
    try:
        return ov.reports(c, dataset_id)
    finally:
        c.close()


@app.get("/api/v1/datasets/{dataset_id}/reports/download", tags=["reports"])
def download_report(dataset_id: str, file: str):
    """Only files in the report catalogue can be downloaded."""
    if file not in {r[0] for r in ov.REPORT_FILES}:
        raise HTTPException(404, "Unknown report file.")
    c = _conn(dataset_id)
    try:
        d = ov.reports_dir(ov.meta(c), dataset_id)
    finally:
        c.close()
    p = d / file if d else None
    if p is None or not p.exists():
        raise HTTPException(404, "This report file is not available for the dataset.")
    return FileResponse(p, filename=p.name)


def reports_root() -> Path:
    return Path(os.environ.get("SLA_REPORTS_DIR", "data/reports"))


@app.post("/api/v1/datasets", tags=["datasets"], response_model=JobOut, status_code=202)
async def upload_dataset(file: UploadFile = File(...), year: int = Form(...), name: str | None = Form(None)):
    """Upload an OpenSSH syslog file. Analysis runs in the background; poll /jobs/{job_id}."""
    fname = Path(file.filename or "upload.log").name
    if Path(fname).suffix.lower() not in jobs.ALLOWED_SUFFIXES:
        raise HTTPException(422, "Only .log and .txt files are accepted.")
    if not 1990 <= year <= 2100:
        raise HTTPException(422, "Year must be between 1990 and 2100.")
    data_dir().mkdir(parents=True, exist_ok=True)
    dataset_id = jobs.unique_id(data_dir(), jobs.slug(name or fname))
    tmp = data_dir() / f".upload-{dataset_id}.log"
    size = 0
    with open(tmp, "wb") as out:
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > jobs.MAX_UPLOAD_BYTES:
                out.close()
                tmp.unlink(missing_ok=True)
                raise HTTPException(413, f"File is larger than the {jobs.MAX_UPLOAD_BYTES // 1048576} MB limit.")
            out.write(chunk)
    if size == 0:
        tmp.unlink(missing_ok=True)
        raise HTTPException(422, "The file is empty.")
    job_id = jobs.start(tmp, fname, year, dataset_id, data_dir(), reports_root())
    return jobs.get(job_id)


@app.get("/api/v1/jobs/{job_id}", tags=["datasets"], response_model=JobOut)
def get_job(job_id: str):
    j = jobs.get(job_id)
    if j is None:
        raise HTTPException(404, "Unknown job.")
    return j
