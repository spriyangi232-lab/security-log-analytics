import pytest
from fastapi.testclient import TestClient

from sla.pipeline import run
from sla.synthetic import generate


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("api")
    log = d / "s.log"
    log.write_text("\n".join(generate()) + "\n")
    (d / "ds").mkdir()
    run(str(log), str(d / "ds" / "demo.db"), str(d / "out"), year=2026, verbose=False)
    import os
    os.environ["SLA_DATA_DIR"] = str(d / "ds")
    from api.main import app
    return TestClient(app)


def test_datasets_and_overview(client):
    ds = client.get("/api/v1/datasets").json()
    assert ds[0]["id"] == "demo"
    o = client.get("/api/v1/datasets/demo/overview?range=all").json()
    assert [c["key"] for c in o["cells"]][:2] == ["failed_attempts", "unique_ips"]


def test_attackers_detail_events_csv(client):
    page = client.get("/api/v1/datasets/demo/attackers?range=all&limit=3").json()
    ip = page["rows"][0]["ip"]
    assert client.get(f"/api/v1/datasets/demo/attackers/{ip}").json()["risk"]["components"]
    assert client.get(f"/api/v1/datasets/demo/attackers/{ip}/events?limit=2").json()["shown"] == 2
    assert client.get("/api/v1/datasets/demo/exports/attackers.csv?range=all").text.startswith("rank,ip")


def test_errors_are_problem_json(client):
    r = client.get("/api/v1/datasets/nope/overview")
    assert r.status_code == 404 and r.headers["content-type"].startswith("application/problem+json")
    assert client.get("/api/v1/datasets/demo/overview?range=3d").status_code == 422


def test_accounts_incidents_controls(client):
    a = client.get("/api/v1/datasets/demo/accounts?range=all&limit=5").json()
    assert a["rows"] and a["rows"][0]["attempts"] >= a["rows"][-1]["attempts"]
    i = client.get("/api/v1/datasets/demo/incidents?range=all&limit=5").json()
    assert i["total"] == sum(s["count"] for s in i["by_severity"]) and i["rows"][0]["response_target"]
    c = client.get("/api/v1/datasets/demo/controls").json()
    assert sum(s["count"] for s in c["summary"]) == len(c["rows"])


def test_forecast_and_reports(client):
    f = client.get("/api/v1/datasets/demo/forecast").json()
    assert f["outlook"]["level"] and f["daily"]["actual"] and len(f["confidence_rules"]) == 4
    r = client.get("/api/v1/datasets/demo/reports").json()
    assert any(x["available"] for x in r["rows"])
    assert client.get("/api/v1/datasets/demo/reports/download?file=../../etc/passwd").status_code == 404
    assert client.get("/api/v1/datasets/demo/reports/download?file=incidents.csv").status_code == 200


def test_upload_runs_and_rejects_bad_files(client, tmp_path):
    import time
    from sla.synthetic import generate
    import os
    os.environ["SLA_REPORTS_DIR"] = str(tmp_path / "rep")
    r = client.post("/api/v1/datasets", files={"file": ("my upload.log", "\n".join(generate()).encode())}, data={"year": "2026"})
    assert r.status_code == 202
    job = r.json()
    for _ in range(120):
        job = client.get(f"/api/v1/jobs/{job['job_id']}").json()
        if job["status"] in ("done", "failed"):
            break
        time.sleep(1)
    assert job["status"] == "done", job
    ids = [d["id"] for d in client.get("/api/v1/datasets").json()]
    assert job["dataset_id"] in ids
    assert client.get(f"/api/v1/datasets/{job['dataset_id']}/overview?range=all").status_code == 200
    assert client.post("/api/v1/datasets", files={"file": ("x.exe", b"abc")}, data={"year": "2026"}).status_code == 422
    bad = client.post("/api/v1/datasets", files={"file": ("junk.log", b"hello world\nnot a log\n")}, data={"year": "2026"}).json()
    for _ in range(60):
        bad = client.get(f"/api/v1/jobs/{bad['job_id']}").json()
        if bad["status"] in ("done", "failed"):
            break
        time.sleep(0.5)
    assert bad["status"] == "failed" and "OpenSSH" in bad["error"]
    assert bad["dataset_id"] not in [d["id"] for d in client.get("/api/v1/datasets").json()]


def test_forecast_page_survives_short_log(client, tmp_path):
    import os, sqlite3
    from sla import overview as ov
    from sla.pipeline import run
    short = tmp_path / "short.log"
    from sla.synthetic import generate
    short.write_text("\n".join(generate()[:3000]) + "\n")
    run(str(short), str(tmp_path / "short.db"), str(tmp_path / "o"), year=2026, verbose=False)
    f = ov.forecast(sqlite3.connect(tmp_path / "short.db"))
    assert f["outlook"]["level"] in ("Insufficient data", "Low confidence") or f["hourly"]["forecast"] == []
