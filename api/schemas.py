"""Response models: the contract the frontend types are generated from."""
from __future__ import annotations

from pydantic import BaseModel


class Gap(BaseModel):
    start_ts: str
    end_ts: str
    hours: int


class Trust(BaseModel):
    filename: str
    period_start: str
    period_end: str
    lines_total: int
    lines_unmatched: int
    lines_other: int
    unparsed_pct: float
    last_upload: str
    year_assumed: int
    gaps: list[Gap]


class Cell(BaseModel):
    key: str
    label: str
    value: int
    of: int | None = None
    previous: int | None = None
    change_pct: float | None = None
    spark: list[int] | None = None


class Window(BaseModel):
    start: str
    end: str


class GapSpan(BaseModel):
    start: str
    end: str
    hours: int


class Anomaly(BaseModel):
    start_ts: str
    end_ts: str
    peak_attempts: int
    hours: int
    rule_id: str
    rule: str


class AnomalyRule(BaseModel):
    id: str
    label: str


class TimeSeries(BaseModel):
    points: list[tuple[str, int | None]]
    gaps: list[GapSpan]
    anomalies: list[Anomaly]
    anomaly_rule: AnomalyRule
    caption: str


class SeverityRow(BaseModel):
    severity: str
    attempts: int


class BySeverity(BaseModel):
    rows: list[SeverityRow]
    caption: str
    rule: str


class Overview(BaseModel):
    range: str
    window: Window
    previous_window: Window | None
    change_note: str
    trust: Trust
    cells: list[Cell]
    timeseries: TimeSeries
    by_severity: BySeverity


class AttackerRow(BaseModel):
    rank: int
    ip: str
    attempts: int
    first_seen: str
    last_seen: str
    accounts: int
    severity: str
    techniques: list[str]
    action: str | None = None
    top_incident_id: str | None = None
    reason: str | None = None
    risk_score: float | None = None
    risk_tier: str | None = None
    spark14: list[int]


class AttackerPage(BaseModel):
    range: str
    total: int
    limit: int
    offset: int
    rows: list[AttackerRow]
    caption: str


class Component(BaseModel):
    key: str
    label: str
    formula: str
    meaning: str
    weight: float
    points: float


class Risk(BaseModel):
    score: float
    tier: str
    components: list[Component]
    formula: str
    compromise_flag: bool


class IncidentRow(BaseModel):
    incident_id: str
    rule: str
    title: str
    technique_id: str
    severity: str
    priority: str
    start_ts: str
    end_ts: str
    attempts: int
    evidence: str


class AttackerDetail(BaseModel):
    ip: str
    severity: str
    reason: str
    action: str
    techniques: list[str]
    risk: Risk
    incidents: list[IncidentRow]
    first_seen: str
    last_seen: str


class LogLine(BaseModel):
    ts: str
    raw: str


class AttackerEvents(BaseModel):
    ip: str
    total: int
    shown: int
    lines: list[LogLine]


class AccountRow(BaseModel):
    username: str
    attempts: int
    source_ips: int
    share_pct: float
    privileged: bool
    exists: bool
    successful_logins: int
    last_seen: str


class AccountTop(BaseModel):
    username: str
    attempts: int


class AccountPage(BaseModel):
    range: str
    total: int
    limit: int
    offset: int
    rows: list[AccountRow]
    top: list[AccountTop]
    caption: str


class IncidentFull(BaseModel):
    incident_id: str
    rule: str
    title: str
    technique_id: str
    severity: str
    priority: str
    ip: str | None = None
    username: str | None = None
    start_ts: str
    end_ts: str
    attempts: int
    distinct_users: int | None = None
    distinct_ips: int | None = None
    peak_window_attempts: int | None = None
    evidence: str
    response_target: str


class SeverityCount(BaseModel):
    severity: str
    count: int


class RuleRef(BaseModel):
    id: str
    title: str


class IncidentPage(BaseModel):
    range: str
    total: int
    limit: int
    offset: int
    rows: list[IncidentFull]
    by_severity: list[SeverityCount]
    rules: list[RuleRef]
    caption: str


class ControlRow(BaseModel):
    control_id: str
    domain: str
    control_objective: str
    risk_addressed: str
    test_procedure: str
    population_description: str
    population: int
    exceptions: int
    result: str
    evidence: str
    recommendation: str
    framework_reference: str


class ResultCount(BaseModel):
    result: str
    count: int


class ControlsOut(BaseModel):
    rows: list[ControlRow]
    summary: list[ResultCount]
    caption: str


class Outlook(BaseModel):
    level: str
    headline: str
    message: str
    confidence: str
    reasons: list[str]
    last24h: int
    next24h: int
    baseline_daily: int
    ratio: float


class Models(BaseModel):
    hourly: str | None = None
    daily: str | None = None


class FPoint(BaseModel):
    actual: list[tuple[str, int | None]]
    forecast: list[tuple[str, float, float, float]]


class BacktestRow(BaseModel):
    model: str
    MAE: float
    RMSE: float
    bias: float
    folds: int
    skill_vs_naive_pct: float


class Backtest(BaseModel):
    hourly: list[BacktestRow]
    daily: list[BacktestRow]


class ForecastOut(BaseModel):
    outlook: Outlook
    models: Models
    hourly: FPoint
    daily: FPoint
    backtest: Backtest
    confidence_rules: list[str]
    caption: str


class ReportRow(BaseModel):
    file: str
    title: str
    description: str
    audience: str
    size_bytes: int | None = None
    available: bool


class ReportsOut(BaseModel):
    rows: list[ReportRow]
    caption: str


class JobOut(BaseModel):
    job_id: str
    dataset_id: str
    filename: str
    status: str
    steps: list[str]
    error: str | None = None
