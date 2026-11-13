import os

import pytest

from sla import pipeline

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest


def test_dashboard_renders_without_exceptions(tmp_path, sample_log, monkeypatch):
    dbp = tmp_path / "d.db"
    pipeline.run(str(sample_log), str(dbp), str(tmp_path / "rep"), verbose=False)
    monkeypatch.setenv("SLA_DB", str(dbp))
    at = AppTest.from_file(os.path.join(os.path.dirname(__file__), "..", "app", "dashboard.py"), default_timeout=60).run()
    assert not at.exception
    assert len(at.metric) == 6 and len(at.tabs) == 8
