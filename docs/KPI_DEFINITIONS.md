# KPI definitions

Every number on the dashboard and in the report is defined here, so it can be reproduced and defended.

| KPI | Definition |
|---|---|
| Failed attempt | One `Failed password` / `publickey` / `keyboard-interactive` log line. Lines compressed as `message repeated N times` count N. PAM, invalid-user and pre-auth lines are not counted (they describe the same attempt). |
| Failed-login rate | failed attempts / (failed attempts + successful logins). On an attacked server it is close to 100%, so it is reported but not used as the headline. |
| Unique attacker IPs | Distinct source IPs with at least one failed attempt. The source IP is taken from the line itself, or from the same SSH connection (same PID within 30 minutes) when the line has none. |
| Attempts per hour | Failed attempts divided by the hours between the first and last log line. Peak hour is the busiest clock hour. |
| Top-10 IP share | Share of all failed attempts made by the ten busiest IPs. `ips_for_50pct` / `ips_for_80pct` is the smallest number of IPs covering that share, which tells you how effective blocking would be. |
| root + admin share | Share of failed attempts whose username is `root` or `admin`. |
| Invalid-user share | Share of failed attempts for usernames that do not exist on the server. High values indicate automated dictionary attacks. |
| Night share and lift | Share of attempts between 22:00 and 05:59 server time, and that share divided by 33.3% (the share expected if activity were uniform across hours). Only reported when the logs span at least 72 hours. |
| Attack episode | Consecutive attempts from one IP with no gap above 30 minutes. |
| Peak window attempts | Maximum attempts from one IP inside any 5-minute sliding window. |
| Incident | One detection rule firing on one episode (or one account, for the distributed rule). Has severity, ITIL priority (Critical P1, High P2, Medium P3, Low P4), MITRE ATT&CK technique and a human-readable evidence string. |
| Risk score | 0-100: 30% volume (log-scaled), 20% burst intensity, 15% username breadth, 15% persistence (active hours), 10% privileged-account share, 10% invalid-user share. Tiers: Critical 80+, High 60+, Medium 35+, Low below. A success-after-failures finding forces at least 90. |
| Spike | Hourly volume at least 5 robust standard deviations above the median of the same hour of day over the previous 7 days (log scale), and at least 100 attempts. |
| Detection coverage | Failed attempts that fall inside a brute-force, spraying or distributed incident divided by all failed attempts. |
| Forecast skill | 1 - (model MAE / seasonal-naive MAE) on a rolling-origin backtest. Positive means the model beats the baseline. |
| Risk outlook | Forecast for the next 24 hours divided by the average daily volume of the previous 7 complete days. 1.5x or more = Rising, 1.15x or more = Elevated, 0.85x or less = Falling, otherwise Stable. Shown only when the forecast passes its confidence checks; otherwise the outlook is **Low confidence**. |
| Outlook confidence | Low if any check fails: the best hourly model beats the naive baseline by under 10%; the next-24h forecast is below 0.25x or above 4x the actual last 24 hours; the 80% interval upper bound is over 5x the forecast; or the hourly and daily forecasts differ by more than 3x. High if none fail and the skill is 25% or more, otherwise Medium. Thresholds are in `sla/config.py`. |
