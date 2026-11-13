-- Named, parameterised queries used by the pipeline, the dashboard and the report.
-- Format:  "-- name: <id>" starts a query; ":param" are bound parameters.
-- "Failed attempt" always means events.is_failed_attempt = 1 (Failed password lines only) so
-- that the several log lines one login attempt produces are never counted twice.

-- name: top_attacker_ips
-- Top attacking IPs with their share of all attempts and the cumulative share (Pareto view).
SELECT ip_resolved AS ip,
       SUM(weight)                                                        AS attempts,
       ROUND(100.0 * SUM(weight) / SUM(SUM(weight)) OVER (), 2)           AS share_pct,
       ROUND(100.0 * SUM(SUM(weight)) OVER (ORDER BY SUM(weight) DESC
             ROWS UNBOUNDED PRECEDING) / SUM(SUM(weight)) OVER (), 2)     AS cumulative_pct,
       COUNT(DISTINCT username)                                           AS distinct_users,
       MIN(ts) AS first_seen, MAX(ts) AS last_seen
FROM events
WHERE is_failed_attempt = 1 AND ip_resolved IS NOT NULL
GROUP BY ip_resolved
ORDER BY attempts DESC
LIMIT :limit;

-- name: failed_by_hour_of_day
SELECT hod AS hour_of_day, SUM(weight) AS attempts,
       ROUND(100.0 * SUM(weight) / SUM(SUM(weight)) OVER (), 2) AS share_pct
FROM events WHERE is_failed_attempt = 1
GROUP BY hod ORDER BY hod;

-- name: failed_by_day
-- Daily volume with a 3-day moving average (window function).
SELECT day, attempts,
       ROUND(AVG(attempts) OVER (ORDER BY day ROWS BETWEEN 2 PRECEDING AND CURRENT ROW), 1) AS moving_avg_3d
FROM (SELECT date(ts) AS day, SUM(weight) AS attempts FROM events WHERE is_failed_attempt = 1 GROUP BY date(ts))
ORDER BY day;

-- name: top_usernames
SELECT username, SUM(weight) AS attempts, COUNT(DISTINCT ip_resolved) AS distinct_ips,
       ROUND(100.0 * SUM(weight) / SUM(SUM(weight)) OVER (), 2) AS share_pct
FROM events WHERE is_failed_attempt = 1 AND username IS NOT NULL
GROUP BY username ORDER BY attempts DESC LIMIT :limit;

-- name: busiest_minutes
-- Attack bursts: minutes with the most failed attempts (shows automated tooling).
SELECT strftime('%Y-%m-%d %H:%M', ts) AS minute, SUM(weight) AS attempts, COUNT(DISTINCT ip_resolved) AS ips
FROM events WHERE is_failed_attempt = 1
GROUP BY minute ORDER BY attempts DESC LIMIT :limit;

-- name: success_after_failures
-- Self-join: successful logins preceded by failures from the same IP in the previous 60 minutes.
SELECT a.ts AS login_ts, a.ip_resolved AS ip, a.username, a.auth_method,
       SUM(f.weight) AS prior_failures
FROM events a
JOIN events f ON f.ip_resolved = a.ip_resolved AND f.is_failed_attempt = 1
             AND f.ts <= a.ts AND f.ts >= datetime(a.ts, '-60 minutes')
WHERE a.is_success = 1
GROUP BY a.id HAVING prior_failures >= :min_failures
ORDER BY prior_failures DESC;

-- name: heatmap_hour_by_day
SELECT date(ts) AS day, hod AS hour_of_day, SUM(weight) AS attempts
FROM events WHERE is_failed_attempt = 1 GROUP BY day, hod;

-- name: incidents_by_rule
SELECT rule, severity, COUNT(*) AS incidents, SUM(attempts) AS attempts
FROM incidents GROUP BY rule, severity ORDER BY incidents DESC;

-- name: ips_with_multiple_incidents
SELECT ip, COUNT(*) AS incidents, GROUP_CONCAT(DISTINCT rule) AS rules, SUM(attempts) AS attempts
FROM incidents WHERE ip IS NOT NULL GROUP BY ip HAVING incidents > 1 ORDER BY incidents DESC LIMIT :limit;
