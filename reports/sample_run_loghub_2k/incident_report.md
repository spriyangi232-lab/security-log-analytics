# SSH Security Log Analysis: Incident Report
_Source: OpenSSH_2k.log | Period: 2015-12-10 06:55:46 to 2015-12-10 11:04:45 | Generated: 2026-11-13 07:43_

## 1. Executive summary
Over 4.1 hours of SSH logs (2,000 events) the server received 528 failed password attempts from 23 distinct IP addresses, against 1 successful login(s). Activity is highly concentrated: 1 IP address accounts for half of all attempts and 4 for 80%, so targeted blocking is effective. Attackers overwhelmingly guess privileged usernames: root and admin make up 79.9% of attempts. No login succeeded after a run of failures, so there is no evidence of a compromised account in this period. 5 incident(s) are rated High.

## 2. Key findings
1. **Concentration.** The top 10 IPs generate 94.3% of all failed attempts; the median attacking IP makes only 5, so a few persistent sources sit on top of a long tail of one-off probes.
2. **Targeted accounts.** Most-guessed usernames: `root` (378), `admin` (44), `oracle` (6).
3. **Account enumeration.** 25.6% of attempts target usernames that do not exist on the server, which is the signature of automated dictionary attacks rather than users mistyping.
4. **Timing.** Only 4.1 hours of logs are available, which is too short to make a reliable time-of-day statement. Peak hour: 2015-12-10 10:00:00 with 171 attempts.
5. **Detections.** SSH brute-force (password guessing): 8; Username enumeration / password spraying: 4; Reconnaissance / port scanning: 2.

## 3. Priority incidents (top 10)
| incident_id | priority | title | technique_id | source | window | attempts | response |
|---|---|---|---|---|---|---|---|
| INC-00001 | P2 | SSH brute-force (password guessing) | T1110.001 | 183.62.140.253 / root | 12-10 10:54 to 11:04 | 286 | Respond within 1 hour |
| INC-00002 | P2 | Username enumeration / password spraying | T1110.003 | 187.141.143.180 | 12-10 09:12 to 09:20 | 80 | Respond within 1 hour |
| INC-00003 | P2 | Username enumeration / password spraying | T1110.003 | 103.99.0.122 | 12-10 09:11 to 09:12 | 30 | Respond within 1 hour |
| INC-00004 | P2 | Username enumeration / password spraying | T1110.003 | 5.188.10.180 | 12-10 08:24 to 08:26 | 18 | Respond within 1 hour |
| INC-00005 | P2 | Username enumeration / password spraying | T1110.003 | 103.99.0.122 | 12-10 11:03 to 11:04 | 16 | Respond within 1 hour |
| INC-00006 | P3 | SSH brute-force (password guessing) | T1110.001 | 112.95.230.3 / root | 12-10 07:27 to 07:28 | 26 | Respond within 1 business day |
| INC-00007 | P4 | SSH brute-force (password guessing) | T1110.001 | 185.190.58.151 / admin | 12-10 09:07 to 09:12 | 17 | Review in weekly triage |
| INC-00008 | P4 | Reconnaissance / port scanning | T1595.001 | 5.188.10.180 | 12-10 08:24 to 08:26 | 12 | Review in weekly triage |
| INC-00009 | P4 | Reconnaissance / port scanning | T1595.001 | 185.190.58.151 | 12-10 09:07 to 09:13 | 8 | Review in weekly triage |
| INC-00010 | P4 | SSH brute-force (password guessing) | T1110.001 | 123.235.32.19 / root | 12-10 07:32 to 07:34 | 7 | Review in weekly triage |

## 4. Top attackers by risk score
| ip | attempts | distinct_users | peak_window_attempts | risk_score | risk_tier |
|---|---|---|---|---|---|
| 187.141.143.180 | 80 | 28 | 57 | 64.8 | High |
| 183.62.140.253 | 286 | 10 | 147 | 63.4 | High |
| 103.99.0.122 | 46 | 19 | 30 | 55.3 | Medium |
| 5.188.10.180 | 18 | 7 | 18 | 41.4 | Medium |
| 185.190.58.151 | 17 | 3 | 16 | 40.6 | Medium |
| 112.95.230.3 | 26 | 3 | 26 | 37.6 | Medium |
| 119.4.203.64 | 6 | 1 | 6 | 32.2 | Low |
| 123.235.32.19 | 7 | 1 | 7 | 23.2 | Low |
| 52.80.34.196 | 5 | 3 | 1 | 22.9 | Low |
| 106.5.5.195 | 6 | 1 | 6 | 22.2 | Low |

_Risk score (0-100) = weighted volume, burst intensity, username breadth, persistence, privileged-account targeting and invalid-user share. Component points per IP are in `ip_risk.csv`._

## 5. IT control assessment
| control_id | control | status | evidence |
|---|---|---|---|
| C1 | Password authentication is not exposed to untrusted networks | FAIL | 528 failed password attempts from 23 distinct external IPs |
| C2 | Account lockout / rate limiting stops guessing after about 5 attempts | FAIL | 11 of 12 attack episodes exceeded 5 attempts; 2 exceeded 50; worst episode 286 attempts |
| C3 | Direct privileged (root/admin) SSH login is disabled | WARN | 431 attempts against privileged accounts; 0 successful root logins |
| C4 | No successful login follows a run of failures from the same source | PASS | 0 successful login(s) preceded by >= 3 failures within 60 min |
| C5 | Monitoring covers the bulk of malicious authentication activity | PASS | Detection rules cover 95.3% of failed attempts |
| C6 | sshd MaxAuthTries is consistent with the PAM retry limit | WARN | 7 log entries show PAM ignoring its max-retries limit (sessions reached 6 tries against a limit of 3) |

## 6. Forecast and risk outlook
Forecast not produced: not enough history (6 hourly points, need 168). A reliable forecast needs at least 7 days of logs.

## 7. Recommendations
**Immediate**
- Block the 2 High/Critical-risk IPs in `blocklist.txt`; together they produced 69% of failed attempts. Verify none is a shared/NAT address before enforcing.

**Short term**
- Alert after 5 failed logins from one IP in 5 minutes and ban automatically (see `fail2ban_jail.local`).
- Disable direct root login (`PermitRootLogin no`) and use named accounts with sudo; root/admin are the dominant targets.
- Move to key-based authentication or MFA and disable password login (`PasswordAuthentication no`); this removes the attack surface these attempts are aimed at.

**Governance**
- Remediate failed control test(s) C1, C2 and re-run this assessment to evidence the improvement.
- Forward these alerts to the SIEM / ticketing queue and review thresholds monthly against the false-positive rate.

## 8. Method, assumptions and limitations
- A failed attempt is one `Failed password` line (repeat-compressed lines expanded); PAM and pre-auth lines are never double counted.
- Syslog has no year; the year is a parameter and rolls over on a December to January wrap.
- Rules and thresholds are in `sla/config.py`; they are heuristics tuned for SSH on a single host, not universal constants.
- IP address does not equal person: NAT, proxies and botnets mean blocking should be reviewed before enforcement.
- Forecasts describe likely volume given past behaviour; they cannot predict a new campaign starting.
