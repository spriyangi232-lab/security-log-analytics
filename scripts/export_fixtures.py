"""Export real pipeline output as static fixtures for the read-only web demo (VITE_FIXTURES=1).

Tables (attackers, accounts, incidents) are exported in full for each range, so the demo can search, filter,
sort and page in the browser exactly like the API does. Every attacker gets its detail panel and its first
50 raw log lines.

Usage: SLA_DATA_DIR=data/datasets SLA_REPORTS_DIR=data/reports python scripts/export_fixtures.py <dataset-id>
"""
import json
import shutil
import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from api.main import app, data_dir, reports_root  # noqa: E402
from api.schemas import AccountPage, AttackerPage, IncidentPage  # noqa: E402
from sla import db, overview as ov  # noqa: E402

ds = sys.argv[1]
out = ROOT / "web" / "public" / "fixtures"
if out.exists():
    shutil.rmtree(out)
out.mkdir(parents=True)
c = TestClient(app)
ALL = 1_000_000


def write(name, obj):
    (out / f"{name}.json").write_text(json.dumps(obj, separators=(",", ":"), default=str), encoding="utf-8")
    return obj


def save(name, url):
    r = c.get(url)
    r.raise_for_status()
    return write(name, r.json())


save("datasets", "/api/v1/datasets")
save("rules", "/api/v1/rules")
save("controls", f"/api/v1/datasets/{ds}/controls")
save("forecast", f"/api/v1/datasets/{ds}/forecast")
reports = save("reports", f"/api/v1/datasets/{ds}/reports")

conn = db.connect(str(data_dir() / f"{ds}.db"))
ips = set()
for rng in ("24h", "7d", "all"):
    save(f"overview_{rng}", f"/api/v1/datasets/{ds}/overview?range={rng}")
    # Pass through the API's response schemas so the files carry exactly the fields the API returns.
    a = write(f"attackers_{rng}", AttackerPage.model_validate(ov.attackers(conn, rng, limit=ALL)).model_dump(mode="json"))
    ips.update(r["ip"] for r in a["rows"])
    write(f"accounts_{rng}", AccountPage.model_validate(ov.accounts(conn, rng, limit=ALL)).model_dump(mode="json"))
    # natural table order (incident_id), so the browser's stable sort breaks ties exactly like the API
    write(f"incidents_{rng}", IncidentPage.model_validate(
        ov.incidents(conn, rng, sort="incident_id", direction="asc", limit=ALL)).model_dump(mode="json"))
for ip in sorted(ips):
    save(f"attacker_{ip}", f"/api/v1/datasets/{ds}/attackers/{ip}")
    save(f"events_{ip}", f"/api/v1/datasets/{ds}/attackers/{ip}/events?limit=50")

# report files, downloadable from the static site
for row in reports["rows"]:
    if row["available"]:
        dst = out / "reports" / row["file"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(reports_root() / ds / row["file"], dst)
print(f"fixtures written to {out} ({len(ips)} attackers)")
