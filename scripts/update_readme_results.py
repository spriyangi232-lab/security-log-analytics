"""Fill the RESULTS block in README.md from reports/kpis.json so the README always quotes
numbers the pipeline actually produced.   Usage: python scripts/update_readme_results.py [reports/kpis.json]"""
import json
import re
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
kp = json.loads(Path(sys.argv[1] if len(sys.argv) > 1 else root / "reports" / "kpis.json").read_text())
import pandas as pd
hours = (pd.Timestamp(kp["period_end"]) - pd.Timestamp(kp["period_start"])).total_seconds() / 3600
night = f"{kp['night_share_pct']}%  ({kp['night_lift']}x)" if hours >= 72 else "n/a (log shorter than 72 hours)"
fm = f"{kp.get('forecast_model_hourly')} / {kp.get('forecast_model_daily')}" if kp.get("forecast_model_hourly") else "n/a (needs 7+ days of logs)"
top = ", ".join(f"`{u}` ({n:,})" for u, n in list(kp["top_usernames"].items())[:3])
rows = [
    ("Log events analysed", f"{kp['log_events']:,}"),
    ("Period", f"{kp['period_start'][:10]} to {kp['period_end'][:10]}"),
    ("Failed login attempts", f"{kp['failed_attempts']:,}"),
    ("Unique attacker IPs", f"{kp['unique_attacker_ips']:,}"),
    ("IPs behind 50% / 80% of attempts", f"{kp['ips_for_50pct']} / {kp['ips_for_80pct']}"),
    ("Top-10 IP share of attempts", f"{kp['top10_ip_share_pct']}%"),
    ("root + admin share of attempts", f"{kp['root_admin_share_pct']}%"),
    ("Attempts on non-existent usernames", f"{kp['invalid_user_share_pct']}%"),
    ("Most targeted usernames", top),
    ("Share of attempts 22:00-05:59 (33% expected if uniform)", night),
    ("Incidents detected (High+Critical)", f"{kp['incidents_total']:,} ({kp['incidents_critical_high']:,})"),
    ("Forecast model (hourly / daily)", fm),
    ("Risk outlook", kp["outlook"]["level"] + (f" (confidence: {kp['outlook']['confidence']})" if kp["outlook"].get("confidence") and kp["outlook"]["level"] != "Low confidence" else "")),
]
block = "| Metric | Value |\n|---|---|\n" + "\n".join(f"| {a} | {b} |" for a, b in rows)
readme = root / "README.md"
text = readme.read_text()
new = re.sub(r"(<!-- RESULTS:START -->).*?(<!-- RESULTS:END -->)", lambda m: f"{m.group(1)}\n{block}\n{m.group(2)}", text, flags=re.S)
readme.write_text(new)
print("README results block updated")
