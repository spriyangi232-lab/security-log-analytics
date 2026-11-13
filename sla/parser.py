"""Parse OpenSSH (sshd) syslog lines into a structured events table.

Design notes
------------
* One log line -> one event row, classified into an event_type taxonomy.
* A single failed login produces several log lines (Invalid user, input_userauth_request,
  pam_unix failure, Failed password). Only ``Failed password/publickey/keyboard-interactive``
  lines are flagged ``is_failed_attempt`` so attempts are never double counted.
* ``message repeated N times: [...]`` lines are expanded through ``weight`` (N).
* sshd forks one process per connection, so rows that carry no IP (pam_unix, "Too many
  authentication failures") are attributed to the IP seen on the same PID within the same
  session window (``ip_resolved``).
* Syslog has no year: it is supplied by the caller and rolled forward on a Dec -> Jan wrap.
"""
from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator

import pandas as pd

from .config import DEFAULT, Config

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
LINE_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<msg>.*?)\s*$"
)
REPEAT_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[\s*(?P<inner>.*?)\s*\]$")

# (event_type, regex) - evaluated in order, first match wins.
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("FAILED_LOGIN", re.compile(
        rf"^Failed (?P<method>password|publickey|keyboard-interactive/pam) for "
        rf"(?P<invalid>invalid user )?(?P<user>.+?) from {IP} port (?P<port>\d+)")),
    ("FAILED_NONE", re.compile(
        rf"^Failed none for (?P<invalid>invalid user )?(?P<user>.+?) from {IP} port (?P<port>\d+)")),
    ("ACCEPTED", re.compile(
        rf"^Accepted (?P<method>\S+) for (?P<user>\S+) from {IP} port (?P<port>\d+)")),
    ("INVALID_USER", re.compile(rf"^Invalid user (?P<user>.*?) from {IP}")),
    ("INVALID_USER_PREAUTH", re.compile(r"^input_userauth_request: invalid user (?P<user>.*?) \[preauth\]")),
    ("PAM_MORE_FAILURES", re.compile(
        r"^PAM (?P<n>\d+) more authentication failures?;.*?rhost=(?P<rhost>\S*)(?:\s+user=(?P<user>\S+))?")),
    ("PAM_AUTH_FAILURE", re.compile(
        r"^pam_unix\(sshd:auth\): authentication failure;.*?rhost=(?P<rhost>\S*)(?:\s+user=(?P<user>\S+))?")),
    ("PAM_UNKNOWN_USER", re.compile(r"^pam_unix\(sshd:auth\): check pass; user unknown")),
    ("PAM_MAX_RETRIES", re.compile(r"^PAM service\(sshd\) ignoring max retries; (?P<n>\d+) > (?P<limit>\d+)")),
    ("RDNS_MISMATCH", re.compile(
        r"^reverse mapping checking getaddrinfo for (?P<rhost>\S+) \[(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\] failed")),
    ("TOO_MANY_FAILURES", re.compile(r"^(?:error: )?(?:PAM: )?Disconnecting: Too many authentication failures for (?P<user>.+?)(?: \[preauth\])?$")),
    ("NO_IDENT", re.compile(rf"^Did not receive identification string from {IP}")),
    ("DISCONNECT", re.compile(rf"^(?:error: )?Received disconnect from {IP}: (?P<code>\d+):")),
    ("CONN_CLOSED_PREAUTH", re.compile(rf"^Connection closed by {IP} \[preauth\]")),
    ("SESSION_OPENED", re.compile(r"^pam_unix\(sshd:session\): session opened for user (?P<user>\S+)")),
    ("SESSION_CLOSED", re.compile(r"^pam_unix\(sshd:session\): session closed for user (?P<user>\S+)")),
]
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

COLUMNS = ["ts", "host", "pid", "event_type", "ip", "username", "port", "auth_method",
           "is_invalid_user", "weight", "is_failed_attempt", "is_success", "raw"]


def classify(msg: str) -> dict:
    """Classify one sshd message body. Returns fields (possibly only event_type=OTHER)."""
    for name, rx in PATTERNS:
        m = rx.match(msg)
        if not m:
            continue
        g = m.groupdict()
        out = {"event_type": name}
        ip = g.get("ip")
        rhost = g.get("rhost")
        if not ip and rhost and IPV4_RE.match(rhost):
            ip = rhost
        out["ip"] = ip
        user = g.get("user")
        out["username"] = user.strip() if user and user.strip() else None
        out["port"] = int(g["port"]) if g.get("port") else None
        out["auth_method"] = (g.get("method") or "").split("/")[0] or None
        out["is_invalid_user"] = bool(g.get("invalid")) or name in ("INVALID_USER", "INVALID_USER_PREAUTH")
        out["weight"] = int(g["n"]) if name == "PAM_MORE_FAILURES" and g.get("n") else 1
        return out
    return {"event_type": "OTHER"}


def parse_lines(lines: Iterable[str], year: int = DEFAULT.default_year, stats: dict | None = None) -> Iterator[dict]:
    """Yield one dict per recognised sshd syslog line. If `stats` is given it receives honest counters:
    lines_total (non-empty lines read) and lines_unmatched (lines that are not sshd syslog lines, or whose
    date cannot be read). Nothing is dropped silently."""
    prev_month = None
    cur_year = year
    st = stats if stats is not None else {}
    st.setdefault("lines_total", 0)
    st.setdefault("lines_unmatched", 0)
    for line in lines:
        line = line.rstrip("\r\n")
        if not line.strip():
            continue
        st["lines_total"] += 1
        m = LINE_RE.match(line)
        if not m:
            st["lines_unmatched"] += 1
            continue
        mon = MONTHS.get(m["mon"])
        if mon is None:
            st["lines_unmatched"] += 1
            continue
        if prev_month is not None and prev_month - mon > 6:   # Dec -> Jan wrap
            cur_year += 1
        prev_month = mon
        try:
            h, mi, s = (int(x) for x in m["time"].split(":"))
            ts = datetime(cur_year, mon, int(m["day"]), h, mi, s)
        except ValueError:
            st["lines_unmatched"] += 1
            continue
        msg = m["msg"]
        weight = 1
        rep = REPEAT_RE.match(msg)
        if rep:
            weight = int(rep["n"])
            msg = rep["inner"]
        ev = classify(msg)
        ev["weight"] = max(ev.get("weight", 1), 1) * weight if rep else ev.get("weight", 1)
        ev.update(ts=ts, host=m["host"], pid=int(m["pid"]), raw=line)
        yield ev


def parse_file(path: str | Path, year: int = DEFAULT.default_year, config: Config = DEFAULT, stats: dict | None = None) -> pd.DataFrame:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        rows = list(parse_lines(fh, year=year, stats=stats))
    return build_frame(rows, config)


def build_frame(rows: list[dict], config: Config = DEFAULT) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    if df.empty:
        return pd.DataFrame(columns=COLUMNS + ["session_id", "ip_resolved"])
    for c in ("ip", "username", "port", "auth_method"):
        if c not in df:
            df[c] = None
    df["is_invalid_user"] = df["is_invalid_user"].fillna(False).astype(bool)
    df["weight"] = df["weight"].fillna(1).astype(int)
    df = df.sort_values(["ts", "pid"], kind="stable").reset_index(drop=True)
    df["is_failed_attempt"] = df["event_type"].eq("FAILED_LOGIN")
    df["is_success"] = df["event_type"].eq("ACCEPTED")
    df = _attach_sessions(df, config)
    return df[COLUMNS + ["session_id", "ip_resolved"]]


def _attach_sessions(df: pd.DataFrame, config: Config) -> pd.DataFrame:
    """Reconstruct SSH connections: same PID and no gap > session_gap => one session. Then
    propagate the IP seen anywhere in the session to rows that lack one, and the username to
    the PAM / disconnect rows that never name the user themselves."""
    df = df.sort_values(["pid", "ts"], kind="stable")
    gap = df.groupby("pid")["ts"].diff() > pd.Timedelta(minutes=config.session_gap_minutes)
    df["session_id"] = df["pid"].astype(str) + "-" + gap.groupby(df["pid"]).cumsum().astype(int).astype(str)
    grp = df.groupby("session_id")
    df["ip_resolved"] = grp["ip"].ffill()
    df["ip_resolved"] = df.groupby("session_id")["ip_resolved"].bfill()
    needs_user = df["event_type"].isin(["PAM_UNKNOWN_USER", "PAM_AUTH_FAILURE", "PAM_MORE_FAILURES"])
    filled = grp["username"].ffill()
    filled = filled.where(filled.notna(), df.groupby("session_id")["username"].bfill())
    df["username"] = df["username"].where(~needs_user | df["username"].notna(), filled)
    return df.sort_values(["ts", "pid"], kind="stable").reset_index(drop=True)
