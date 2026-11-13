"""Upload and analysis jobs. One worker runs analyses one at a time; job state is kept in memory."""
from __future__ import annotations

import os
import re
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sla.pipeline import run

MAX_UPLOAD_BYTES = int(os.environ.get("SLA_MAX_UPLOAD_MB", "300")) * 1024 * 1024
ALLOWED_SUFFIXES = {".log", ".txt"}
_pool = ThreadPoolExecutor(max_workers=1)
_jobs: dict[str, dict] = {}
_lock = threading.Lock()


def slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", Path(name).stem.lower()).strip("-")
    return s[:48] or "dataset"


def unique_id(data_dir: Path, base: str) -> str:
    cand, i = base, 2
    with _lock:
        taken = {j["dataset_id"] for j in _jobs.values()}
        while (data_dir / f"{cand}.db").exists() or cand in taken:
            cand, i = f"{base}-{i}", i + 1
    return cand


def _set(job_id: str, **kw) -> None:
    with _lock:
        _jobs[job_id].update(kw)


def start(upload_path: Path, filename: str, year: int, dataset_id: str, data_dir: Path, reports_dir: Path) -> str:
    job_id = uuid.uuid4().hex[:12]
    with _lock:
        _jobs[job_id] = {"job_id": job_id, "dataset_id": dataset_id, "filename": filename, "status": "queued",
                         "steps": [], "error": None, "started": time.time()}

    def work():
        _set(job_id, status="running")
        db_tmp = data_dir / f".{dataset_id}.partial.db"
        try:
            data_dir.mkdir(parents=True, exist_ok=True)
            run(str(upload_path), str(db_tmp), str(reports_dir / dataset_id), year=year, verbose=False,
                progress=lambda m: _jobs[job_id]["steps"].append(re.sub(r"\s*/[\w./-]+", "", m)))
            # recorded filename should be the user's, not the temp upload name
            import sqlite3
            c = sqlite3.connect(db_tmp)
            c.execute("UPDATE dataset_meta SET value = ? WHERE key = 'filename'", (filename,))
            c.commit()
            c.close()
            os.replace(db_tmp, data_dir / f"{dataset_id}.db")      # appears in the dataset list only when complete
            _set(job_id, status="done")
        except SystemExit:
            _set(job_id, status="failed", error="No OpenSSH (sshd) log lines were found in this file. "
                 "This version reads OpenSSH syslog files only. Check the file type, or choose a different year if the dates look wrong.")
        except Exception as e:  # noqa: BLE001
            _set(job_id, status="failed", error=f"The analysis stopped with an error: {type(e).__name__}: {e}")
        finally:
            for p in (upload_path, db_tmp):
                try:
                    p.unlink()
                except OSError:
                    pass

    _pool.submit(work)
    return job_id


def get(job_id: str) -> dict | None:
    with _lock:
        j = _jobs.get(job_id)
        return dict(j, steps=list(j["steps"])) if j else None
