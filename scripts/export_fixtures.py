"""Export small excerpts of real pipeline output as UI fixtures (VITE_FIXTURES=1 npm run dev).
Excerpt only: top 5 attackers, 50 raw lines each. Usage: SLA_DATA_DIR=... python scripts/export_fixtures.py <dataset-id>"""
import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.main import app  # noqa: E402

ds = sys.argv[1]
out = Path(__file__).resolve().parents[1] / "web" / "public" / "fixtures"
out.mkdir(parents=True, exist_ok=True)
c = TestClient(app)


def save(name, url):
    r = c.get(url)
    r.raise_for_status()
    (out / f"{name}.json").write_text(json.dumps(r.json()))
    return r.json()


save("datasets", "/api/v1/datasets")
save("rules", "/api/v1/rules")
for rng in ("24h", "7d", "all"):
    save(f"overview_{rng}", f"/api/v1/datasets/{ds}/overview?range={rng}")
    page = save(f"attackers_{rng}", f"/api/v1/datasets/{ds}/attackers?range={rng}&limit=10")
    for row in page["rows"][:5]:
        save(f"attacker_{row['ip']}", f"/api/v1/datasets/{ds}/attackers/{row['ip']}")
        save(f"events_{row['ip']}", f"/api/v1/datasets/{ds}/attackers/{row['ip']}/events?limit=50")
print("fixtures written to", out)
