# SSH Security Log Analysis: Incident Report
_Source: SSH.log | Period: 2015-12-10 06:55:46 to 2016-01-07 17:22:01 | Generated: 2026-11-13 21:24_

## 1. Executive summary
Over 28.4 days of SSH logs (655,147 events) the server received 344,631 failed password attempts from 1,008 distinct IP addresses, against 182 successful login(s). Activity is highly concentrated: 4 IP addresses account for half of all attempts and 13 for 80%, so targeted blocking is effective. Attackers overwhelmingly guess privileged usernames: root and admin make up 96.3% of attempts. **1 incident(s) indicate a possible account compromise (a login succeeded after repeated failures) and need immediate review.** 295 incident(s) are rated High. The forecast is not reliable enough to call a trend: the hourly forecast (889/day) and daily forecast (13,132/day) disagree. The last 24 hours had 3,073 failed logins and the previous 7-day average is 36,333 per day. Risk outlook: Low confidence.

## 2. Key findings
1. **Concentration.** The top 10 IPs generate 74.9% of all failed attempts; the median attacking IP makes only 6, so a few persistent sources sit on top of a long tail of one-off probes.
2. **Targeted accounts.** Most-guessed usernames: `root` (323,827), `admin` (8,073), `test` (543).
3. **Account enumeration.** 5.8% of attempts target usernames that do not exist on the server, which is the signature of automated dictionary attacks rather than users mistyping.
4. **Timing.** 36.1% of attempts fall between 22:00 and 05:59 (server time), versus 33.3% expected if activity were uniform (1.08x). Peak hour: 2016-01-04 04:00:00 with 5,638 attempts.
5. **Detections.** SSH brute-force (password guessing): 1057; Username enumeration / password spraying: 208; Reconnaissance / port scanning: 40; Successful login after repeated failures (possible compromise): 1.

## 3. Priority incidents (top 10)
| incident_id | priority | title | technique_id | source | window | attempts | response |
|---|---|---|---|---|---|---|---|
| INC-00001 | P1 | Successful login after repeated failures (possible compromise) | T1078 | 123.255.103.142 / curi | 12-20 17:24 to 17:26 | 5 | Respond within 15 min |
| INC-00002 | P2 | SSH brute-force (password guessing) | T1110.001 | 59.63.188.30 / root | 01-03 10:07 to 12:22 | 86294 | Respond within 1 hour |
| INC-00003 | P2 | SSH brute-force (password guessing) | T1110.001 | 58.242.83.25 / root | 01-01 08:48 to 17:13 | 43147 | Respond within 1 hour |
| INC-00004 | P2 | SSH brute-force (password guessing) | T1110.001 | 218.65.30.30 / root | 01-01 14:23 to 11:12 | 25102 | Respond within 1 hour |
| INC-00005 | P2 | SSH brute-force (password guessing) | T1110.001 | 218.87.109.156 / root | 01-03 15:01 to 12:17 | 21377 | Respond within 1 hour |
| INC-00006 | P2 | SSH brute-force (password guessing) | T1110.001 | 182.100.67.120 / root | 01-01 20:32 to 11:31 | 18513 | Respond within 1 hour |
| INC-00007 | P2 | SSH brute-force (password guessing) | T1110.001 | 183.63.110.206 / root | 01-02 19:15 to 10:08 | 17340 | Respond within 1 hour |
| INC-00008 | P2 | SSH brute-force (password guessing) | T1110.001 | 139.219.191.138 / root | 12-30 04:23 to 11:33 | 10852 | Respond within 1 hour |
| INC-00009 | P2 | SSH brute-force (password guessing) | T1110.001 | 183.62.140.253 / root | 12-10 10:54 to 17:19 | 10852 | Respond within 1 hour |
| INC-00010 | P2 | SSH brute-force (password guessing) | T1110.001 | 182.100.67.52 / root | 01-04 03:43 to 11:32 | 8992 | Respond within 1 hour |

## 4. Top attackers by risk score
| ip | attempts | distinct_users | peak_window_attempts | risk_score | risk_tier |
|---|---|---|---|---|---|
| 123.255.103.142 | 8 | 1 | 5 | 90.0 | Critical |
| 185.165.29.57 | 417 | 20 | 64 | 83.1 | Critical |
| 103.99.0.122 | 930 | 19 | 30 | 82.3 | Critical |
| 5.188.10.180 | 716 | 16 | 29 | 81.9 | Critical |
| 119.7.221.129 | 1650 | 113 | 129 | 81.5 | Critical |
| 181.214.87.4 | 381 | 18 | 29 | 81.1 | Critical |
| 5.188.10.182 | 618 | 16 | 29 | 80.6 | Critical |
| 183.62.140.253 | 10852 | 51 | 151 | 80.0 | Critical |
| 139.219.191.138 | 10852 | 51 | 133 | 80.0 | Critical |
| 5.188.10.156 | 497 | 16 | 29 | 79.5 | High |

_Risk score (0-100) = weighted volume, burst intensity, username breadth, persistence, privileged-account targeting and invalid-user share. Component points per IP are in `ip_risk.csv`._

## 5. IT control assessment
| control_id | control | status | evidence |
|---|---|---|---|
| C1 | Password authentication is not exposed to untrusted networks | FAIL | 344631 failed password attempts from 1008 distinct external IPs |
| C2 | Account lockout / rate limiting stops guessing after about 5 attempts | FAIL | 1221 of 1265 attack episodes exceeded 5 attempts; 157 exceeded 50; worst episode 86294 attempts |
| C3 | Direct privileged (root/admin) SSH login is disabled | WARN | 332784 attempts against privileged accounts; 0 successful root logins |
| C4 | No successful login follows a run of failures from the same source | FAIL | 1 successful login(s) preceded by >= 3 failures within 60 min |
| C5 | Monitoring covers the bulk of malicious authentication activity | PASS | Detection rules cover 99.2% of failed attempts |
| C6 | sshd MaxAuthTries is consistent with the PAM retry limit | WARN | 37963 log entries show PAM ignoring its max-retries limit (sessions reached 6 tries against a limit of 3) |

## 6. Forecast and risk outlook
The forecast is not reliable enough to call a trend: the hourly forecast (889/day) and daily forecast (13,132/day) disagree. The last 24 hours had 3,073 failed logins and the previous 7-day average is 36,333 per day. Risk outlook: Low confidence.

Hourly model: **ets** (backtest MAE 776.5 attempts/hour; +33.1% vs a seasonal-naive baseline). Intervals are 80% empirical backtest intervals.

Next 7 days (daily model: **mean_profile**, +9.9% vs naive):

| date | forecast | low | high |
|---|---|---|---|
| 2016-01-08 | 13132 | 10116 | 71507 |
| 2016-01-09 | 19965 | 16950 | 78340 |
| 2016-01-10 | 17272 | 14256 | 75647 |
| 2016-01-11 | 26298 | 23282 | 84673 |
| 2016-01-12 | 7419 | 4403 | 65794 |
| 2016-01-13 | 5753 | 2737 | 64128 |
| 2016-01-14 | 7034 | 4018 | 65409 |

## 7. Recommendations
**Immediate**
- Investigate and reset credentials for account(s) curi; review their sessions since the first failed attempt.
- Block the 84 High/Critical-risk IPs in `blocklist.txt`; together they produced 96% of failed attempts. Verify none is a shared/NAT address before enforcing.

**Short term**
- Alert after 5 failed logins from one IP in 5 minutes and ban automatically (see `fail2ban_jail.local`).
- Disable direct root login (`PermitRootLogin no`) and use named accounts with sudo; root/admin are the dominant targets.
- Move to key-based authentication or MFA and disable password login (`PasswordAuthentication no`); this removes the attack surface these attempts are aimed at.

**Governance**
- Remediate failed control test(s) C1, C2, C4 and re-run this assessment to evidence the improvement.
- Forward these alerts to the SIEM / ticketing queue and review thresholds monthly against the false-positive rate.

## 8. Method, assumptions and limitations
- A failed attempt is one `Failed password` line (repeat-compressed lines expanded); PAM and pre-auth lines are never double counted.
- Syslog has no year; the year is a parameter and rolls over on a December to January wrap.
- Rules and thresholds are in `sla/config.py`; they are heuristics tuned for SSH on a single host, not universal constants.
- IP address does not equal person: NAT, proxies and botnets mean blocking should be reviewed before enforcement.
- Forecasts describe likely volume given past behaviour; they cannot predict a new campaign starting.
