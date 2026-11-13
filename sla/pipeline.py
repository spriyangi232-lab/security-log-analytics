"""End-to-end pipeline: parse -> store -> detect -> score -> KPIs -> forecast -> report."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import pandas as pd

from . import anomaly, controls as ctl, db, deliverables, detection, forecast, kpis as kp, overview, reports, risk
from .config import DEFAULT
from .parser import parse_file


def run(log: str, db_path: str = "data/processed/security.db", out_dir: str = "reports", year: int = DEFAULT.default_year,
        cfg=DEFAULT, verbose: bool = True, progress=None) -> dict:
    t0 = time.time()

    def step(msg):
        if progress:
            progress(msg)
        if verbose:
            print(f"[{time.time() - t0:6.1f}s] {msg}", flush=True)

    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    parse_stats: dict = {}
    events = parse_file(log, year=year, config=cfg, stats=parse_stats)
    if events.empty:
        raise SystemExit("No sshd lines could be parsed from the log. Is it an OpenSSH syslog file?")
    step(f"parsed {len(events):,} events ({events['ts'].min()} to {events['ts'].max()})")

    conn = db.connect(db_path)
    db.write_events(conn, events)
    step(f"loaded events into SQLite: {db_path}")

    incidents = detection.run_all(events, cfg)
    step(f"detection: {len(incidents)} incidents ({incidents['severity'].value_counts().to_dict() if len(incidents) else {}})")
    ip_risk = risk.ip_profile(events, incidents, cfg)
    hourly = kp.hourly_attempts(events)
    k = kp.compute_kpis(events, ip_risk, incidents, cfg)
    spikes = anomaly.detect_spikes(hourly, cfg)
    controls_df = ctl.run_control_tests(events, incidents, cfg)
    hourly_fc = kp.complete_hours(events)          # forecasts use whole hours only
    results = forecast.run_forecasts(hourly_fc, cfg)
    outlook = forecast.risk_outlook(hourly_fc, results, cfg)
    step(f"forecast: hourly={results['hourly'].status}, daily={results['daily'].status}; outlook={outlook['level']}")

    db.write_table(conn, "incidents", incidents, ["start_ts", "end_ts"])
    db.write_table(conn, "ip_risk", ip_risk, ["first_seen", "last_seen"])
    db.write_table(conn, "hourly_attempts", hourly.rename_axis("hour").reset_index().assign(hour=lambda d: d["hour"].dt.strftime("%Y-%m-%d %H:%M:%S")))
    db.write_table(conn, "spikes", spikes, ["hour"])
    db.write_table(conn, "controls", controls_df)
    for name, df in overview.build_tables(events, incidents, ip_risk, spikes, parse_stats, Path(log).name, year, str(Path(out_dir).resolve())).items():
        db.write_table(conn, name, df)
    for name, r in results.items():
        if r.status == "ok":
            db.write_table(conn, f"forecast_{name}", r.forecast, ["ts"])
            db.write_table(conn, f"forecast_{name}_metrics", r.metrics)
    k["outlook"] = outlook
    k["forecast_model_hourly"] = results["hourly"].model
    k["forecast_model_daily"] = results["daily"].model
    db.write_kpis(conn, k)
    conn.close()

    out = Path(out_dir)
    report = reports.build_report(k, incidents, ip_risk, controls_df, results, outlook, spikes, cfg, source=Path(log).name)
    (out / "incident_report.md").write_text(report, encoding="utf-8")
    (out / "blocklist.txt").write_text(reports.blocklist(ip_risk), encoding="utf-8")
    (out / "fail2ban_jail.local").write_text(reports.FAIL2BAN, encoding="utf-8")
    incidents.to_csv(out / "incidents.csv", index=False)
    ip_risk.to_csv(out / "ip_risk.csv", index=False)
    controls_df.to_csv(out / "control_tests.csv", index=False)
    (out / "kpis.json").write_text(json.dumps(k, indent=2, default=lambda o: o.item() if hasattr(o, "item") else str(o)), encoding="utf-8")
    for name, r in results.items():
        if r.status == "ok":
            r.forecast.to_csv(out / f"forecast_{name}.csv", index=False)
            r.metrics.to_csv(out / f"forecast_{name}_backtest.csv", index=False)
    step(f"wrote report and artefacts to {out_dir}/")
    result = {"events": events, "incidents": incidents, "ip_risk": ip_risk, "kpis": k, "controls": controls_df,
              "forecast": results, "outlook": outlook, "spikes": spikes}
    tables = deliverables.build_all(result, out / "deliverables", Path(log).name, cfg)
    conn = db.connect(db_path)
    for name, df in tables.items():
        db.write_table(conn, name, df)
    conn.close()
    step(f"wrote client deliverables (xlsx, docx, pptx, runbook) to {out_dir}/deliverables/")
    result.update(tables)
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(prog="sla", description="Security Log Analytics pipeline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run", help="analyse an OpenSSH syslog file")
    r.add_argument("--log", required=True)
    r.add_argument("--year", type=int, default=DEFAULT.default_year, help="syslog has no year; default 2015 (Loghub OpenSSH)")
    r.add_argument("--db", default="data/processed/security.db")
    r.add_argument("--out", default="reports")
    d = sub.add_parser("demo", help="generate a SYNTHETIC 30-day log and analyse it (for demos/tests only)")
    d.add_argument("--db", default="data/processed/demo.db")
    d.add_argument("--out", default="reports/demo")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        run(a.log, a.db, a.out, a.year)
    else:
        from .synthetic import generate
        Path("data/raw").mkdir(parents=True, exist_ok=True)
        path = "data/raw/synthetic_30d.log"
        Path(path).write_text("\n".join(generate()) + "\n")
        print("NOTE: demo uses SYNTHETIC data (RFC 5737 IPs). Do not quote its numbers as real findings.")
        run(path, a.db, a.out, year=2026)


if __name__ == "__main__":
    main()
