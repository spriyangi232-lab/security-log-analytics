"""SQLite storage layer: schema, indexes, bulk load, and named-query runner."""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

import pandas as pd

SQL_FILE = Path(__file__).resolve().parent.parent / "sql" / "queries.sql"

SCHEMA = """
DROP TABLE IF EXISTS events;
CREATE TABLE events (
    id INTEGER PRIMARY KEY, ts TEXT NOT NULL, day TEXT, hour TEXT, hod INTEGER, dow INTEGER,
    host TEXT, pid INTEGER, session_id TEXT, event_type TEXT NOT NULL,
    ip TEXT, ip_resolved TEXT, username TEXT, port INTEGER, auth_method TEXT,
    is_invalid_user INTEGER, weight INTEGER, is_failed_attempt INTEGER, is_success INTEGER, raw TEXT
);
"""
INDEXES = [
    "CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts)",
    "CREATE INDEX IF NOT EXISTS ix_events_ip ON events(ip_resolved)",
    "CREATE INDEX IF NOT EXISTS ix_events_user ON events(username)",
    "CREATE INDEX IF NOT EXISTS ix_events_type ON events(event_type)",
    "CREATE INDEX IF NOT EXISTS ix_events_failed ON events(is_failed_attempt, ts)",
]


def connect(path: str | Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def _ts(df: pd.DataFrame, cols) -> pd.DataFrame:
    df = df.copy()
    for c in cols:
        if c in df:
            df[c] = pd.to_datetime(df[c]).dt.strftime("%Y-%m-%d %H:%M:%S")
    return df


def write_events(conn: sqlite3.Connection, events: pd.DataFrame) -> None:
    conn.executescript(SCHEMA)
    e = events.copy()
    e["day"] = e["ts"].dt.strftime("%Y-%m-%d")
    e["hour"] = e["ts"].dt.strftime("%Y-%m-%d %H:00:00")
    e["hod"] = e["ts"].dt.hour
    e["dow"] = e["ts"].dt.dayofweek
    e["ts"] = e["ts"].dt.strftime("%Y-%m-%d %H:%M:%S")
    for c in ("is_invalid_user", "is_failed_attempt", "is_success"):
        e[c] = e[c].astype(int)
    cols = ["ts", "day", "hour", "hod", "dow", "host", "pid", "session_id", "event_type", "ip", "ip_resolved",
            "username", "port", "auth_method", "is_invalid_user", "weight", "is_failed_attempt", "is_success", "raw"]
    e[cols].to_sql("events", conn, if_exists="append", index=False, chunksize=50_000)
    for stmt in INDEXES:
        conn.execute(stmt)
    conn.commit()


def write_table(conn: sqlite3.Connection, name: str, df: pd.DataFrame, ts_cols=()) -> None:
    _ts(df, ts_cols).to_sql(name, conn, if_exists="replace", index=False)
    conn.commit()


def write_kpis(conn: sqlite3.Connection, kpis: dict) -> None:
    conn.execute("CREATE TABLE IF NOT EXISTS kpis (key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("DELETE FROM kpis")
    conn.executemany("INSERT INTO kpis VALUES (?, ?)", [(k, json.dumps(v, default=lambda o: o.item())) for k, v in kpis.items()])
    conn.commit()


def read_kpis(conn: sqlite3.Connection) -> dict:
    return {r["key"]: json.loads(r["value"]) for r in conn.execute("SELECT key, value FROM kpis")}


def load_queries(path: Path = SQL_FILE) -> dict[str, str]:
    text = path.read_text(encoding="utf-8")
    parts = re.split(r"^-- name:\s*(\w+)\s*$", text, flags=re.M)
    return {parts[i]: parts[i + 1].strip() for i in range(1, len(parts), 2)}


def query(conn: sqlite3.Connection, name: str, **params) -> pd.DataFrame:
    sql = load_queries()[name]
    needed = set(re.findall(r":(\w+)", sql))
    defaults = {"limit": 10, "min_failures": 3}
    bind = {k: params.get(k, defaults.get(k)) for k in needed}
    return pd.read_sql_query(sql, conn, params=bind)
