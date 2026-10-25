
WITH failed_logins AS (
    SELECT
        user_id,
        ip_address,
        COUNT(*) AS failed_attempts,
        MAX(event_time) AS last_failed_login
    FROM raw_security_logs
    WHERE event_type = 'LOGIN'
      AND status = 'FAILED'
    GROUP BY user_id, ip_address
    HAVING COUNT(*) >= 3
),
successful_logins AS (
    SELECT
        f.user_id,
        f.failed_attempts,
        MIN(s.event_time) AS successful_login_time
    FROM failed_logins f
    JOIN raw_security_logs s
      ON s.user_id = f.user_id
     AND s.event_type = 'LOGIN'
     AND s.status = 'SUCCESS'
     AND s.event_time > f.last_failed_login
    GROUP BY f.user_id, f.failed_attempts
),
large_access AS (
    SELECT
        s.user_id,
        s.failed_attempts,
        s.successful_login_time,
        COUNT(*) AS large_access_events,
        SUM(r.data_volume_mb) AS total_data_mb
    FROM successful_logins s
    JOIN raw_security_logs r
      ON r.user_id = s.user_id
     AND r.event_type = 'FILE_ACCESS'
     AND r.status = 'SUCCESS'
     AND r.event_time > s.successful_login_time
    WHERE r.data_volume_mb >= 500
    GROUP BY
        s.user_id,
        s.failed_attempts,
        s.successful_login_time
)
INSERT INTO incident_alerts (
    user_id,
    failed_attempts,
    successful_login_time,
    large_access_events,
    total_data_mb,
    investigation_priority
)
SELECT
    user_id,
    failed_attempts,
    successful_login_time,
    large_access_events,
    total_data_mb,
    CASE
        WHEN total_data_mb >= 1000 THEN 'HIGH PRIORITY'
        WHEN total_data_mb >= 500 THEN 'MEDIUM PRIORITY'
        ELSE 'REVIEW'
    END
FROM large_access
ON CONFLICT (user_id, successful_login_time)
DO NOTHING;
