"""SYNTHETIC log generator, for tests and for demonstrating the pipeline at scale.

It writes sshd syslog lines in exactly the Loghub OpenSSH format, using only RFC 5737
documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) so no real host is ever
implicated. It exists because the public sample is only a few hours long; forecasting needs weeks.
Never quote findings from synthetic data as real results.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta

import numpy as np

USERS_COMMON = ["root"] * 14 + ["admin"] * 3 + ["oracle", "test", "user", "ubuntu", "postgres", "ftp", "git", "pi",
                                                 "support", "guest", "mysql", "nagios", "tomcat", "jenkins"]
NIGHT_BIAS = np.array([4, 4, 4, 3, 3, 3, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 3, 4, 4], float)


def _ips(rng, n):
    nets = ["192.0.2", "198.51.100", "203.0.113"]
    pool = [f"{n_}.{i}" for n_ in nets for i in range(1, 255)]
    return list(rng.choice(pool, size=n, replace=False))


def generate(days: int = 30, start: datetime = datetime(2026, 9, 1), seed: int = 7, trend_last_days: int = 7):
    rng = np.random.default_rng(seed)
    rows: list[tuple[datetime, int, str]] = []
    pid = [20000]

    def emit_conn(t, ip, user, n_attempts, valid=False, success=False):
        pid[0] += int(rng.integers(1, 9))
        p, port = pid[0], int(rng.integers(30000, 65000))
        lines = []
        if not valid:
            lines += [f"Invalid user {user} from {ip}", f"input_userauth_request: invalid user {user} [preauth]",
                      "pam_unix(sshd:auth): check pass; user unknown"]
        for i in range(n_attempts):
            lines.append(f"pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}")
            lines.append(f"Failed password for {'' if valid else 'invalid user '}{user} from {ip} port {port} ssh2")
        if success:
            lines += [f"Accepted password for {user} from {ip} port {port} ssh2",
                      f"pam_unix(sshd:session): session opened for user {user} by (uid=0)"]
        else:
            lines.append(f"Received disconnect from {ip}: 11: Bye Bye [preauth]")
        for ln in lines:
            t = t + timedelta(seconds=float(rng.uniform(0.1, 2.0)))
            rows.append((t, p, ln))
        return t

    persistent = _ips(rng, 28)
    one_off = _ips(rng, 160)
    sprayers = persistent[:4]
    for d in range(days):
        day0 = start + timedelta(days=d)
        trend = 1 + (1.2 * max(0, d - (days - trend_last_days)) / trend_last_days)   # ramp-up at the end
        weekly = 0.75 if day0.weekday() >= 5 else 1.0
        for ip in persistent:
            if rng.random() > 0.55:
                continue
            hour = int(rng.choice(24, p=NIGHT_BIAS / NIGHT_BIAS.sum()))
            t = day0 + timedelta(hours=hour, minutes=int(rng.integers(0, 50)))
            for _ in range(int(rng.poisson(30 * trend * weekly)) + 1):
                user = str(rng.choice(USERS_COMMON))
                t = emit_conn(t + timedelta(seconds=float(rng.uniform(2, 15))), ip, user, int(rng.integers(1, 7)), valid=user in ("root",) and rng.random() < 0.9)
        for ip in rng.choice(one_off, size=int(rng.integers(3, 10)), replace=False):
            t = day0 + timedelta(hours=int(rng.integers(0, 24)), minutes=int(rng.integers(0, 60)))
            emit_conn(t, ip, str(rng.choice(USERS_COMMON)), int(rng.integers(1, 4)))
            if rng.random() < 0.3:   # pre-auth scan probes
                for _ in range(4):
                    t += timedelta(seconds=20)
                    pid[0] += 1
                    rows.append((t, pid[0], f"Did not receive identification string from {ip}"))
        if d % 6 == 2:               # password-spraying episode
            ip, t = sprayers[d % 4], day0 + timedelta(hours=int(rng.integers(0, 24)))
            for u in rng.choice([f"user{i}" for i in range(80)] + ["admin", "test", "oracle"], size=35, replace=False):
                t = emit_conn(t + timedelta(seconds=3), ip, str(u), 2)
        legit_ip = "198.51.100.250"
        if day0.weekday() < 5:
            t = day0 + timedelta(hours=9, minutes=int(rng.integers(0, 120)))
            pid[0] += 3
            rows.append((t, pid[0], f"Accepted publickey for deploy from {legit_ip} port 50123 ssh2"))
    # distributed attack on root: 40 IPs x 4 attempts inside 2 hours
    t0 = start + timedelta(days=max(days - 12, 1), hours=3)
    for ip in _ips(rng, 40):
        emit_conn(t0 + timedelta(minutes=float(rng.uniform(0, 120))), ip, "root", 4, valid=True)
    # compromise: brute force then a successful login
    t = start + timedelta(days=max(days - 5, 1), hours=14)
    for _ in range(4):
        t = emit_conn(t + timedelta(seconds=10), "203.0.113.200", "admin", 3, valid=True)
    emit_conn(t + timedelta(seconds=15), "203.0.113.200", "admin", 0, valid=True, success=True)

    rows.sort(key=lambda r: (r[0], r[1]))
    return [f"{t:%b} {t.day:>2} {t:%H:%M:%S} LabSZ sshd[{p}]: {msg}" for t, p, msg in rows]


def main():
    ap = argparse.ArgumentParser(description="Generate a SYNTHETIC sshd log (RFC 5737 IPs only).")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--out", default="data/raw/synthetic_30d.log")
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    lines = generate(days=a.days, seed=a.seed)
    with open(a.out, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines):,} synthetic lines to {a.out}")


if __name__ == "__main__":
    main()
