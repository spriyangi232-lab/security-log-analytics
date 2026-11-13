import json
import sqlite3
from pathlib import Path

from sla import db, pipeline, synthetic


def test_pipeline_on_real_sample(tmp_path, sample_log):
    out = pipeline.run(str(sample_log), str(tmp_path / "t.db"), str(tmp_path / "rep"), verbose=False)
    assert out["kpis"]["failed_attempts"] > 500
    rep = (tmp_path / "rep" / "incident_report.md").read_text()
    assert "Executive summary" in rep
    assert "Forecast not produced" in rep            # 4 hours of logs must not produce a fake forecast
    k = json.loads((tmp_path / "rep" / "kpis.json").read_text())
    assert k["unique_attacker_ips"] == out["kpis"]["unique_attacker_ips"]


def test_sql_matches_pandas_counts(tmp_path, sample_log):
    out = pipeline.run(str(sample_log), str(tmp_path / "t.db"), str(tmp_path / "rep"), verbose=False)
    conn = db.connect(tmp_path / "t.db")
    top = db.query(conn, "top_attacker_ips", limit=5)
    assert top["attempts"].sum() <= out["kpis"]["failed_attempts"]
    total_sql = conn.execute("SELECT SUM(weight) FROM events WHERE is_failed_attempt=1").fetchone()[0]
    assert total_sql == out["kpis"]["failed_attempts"]
    assert set(db.load_queries()) >= {"top_attacker_ips", "failed_by_hour_of_day", "success_after_failures"}


def test_synthetic_30_days_end_to_end_with_forecast(tmp_path):
    log = tmp_path / "syn.log"
    log.write_text("\n".join(synthetic.generate(days=21)) + "\n")
    out = pipeline.run(str(log), str(tmp_path / "s.db"), str(tmp_path / "rep"), year=2026, verbose=False)
    assert out["forecast"]["hourly"].status == "ok" and out["forecast"]["daily"].status == "ok"
    assert (out["incidents"]["rule"] == "SUCCESS_AFTER_FAILURES").sum() == 1
    ips = set(out["events"]["ip_resolved"].dropna())
    assert all(ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")) for ip in ips)   # synthetic uses documentation ranges only
