
WITH failed_logins AS (
    SELECT
        user_id,
        ip_address,
        COUNT(*) AS failed_attempts,
        MIN(event_time) AS first_failed_login,
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
        f.ip_address AS failed_ip,
        f.failed_attempts,
        f.first_failed_login,
        f.last_failed_login,
        MIN(s.event_time) AS successful_login_time
    FROM failed_logins f
    JOIN raw_security_logs s
      ON s.user_id = f.user_id
     AND s.event_type = 'LOGIN'
     AND s.status = 'SUCCESS'
     AND s.event_time > f.last_failed_login
    GROUP BY
        f.user_id,
        f.ip_address,
        f.failed_attempts,
        f.first_failed_login,
        f.last_failed_login
),

large_data_access AS (
    SELECT
        s.user_id,
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
    GROUP BY s.user_id, s.successful_login_time
)

SELECT
    s.user_id,
    s.failed_attempts,
    s.first_failed_login,
    s.last_failed_login,
    s.successful_login_time,
    COALESCE(d.large_access_events, 0) AS large_access_events,
    COALESCE(d.total_data_mb, 0) AS total_data_mb,
    CASE
        WHEN d.total_data_mb >= 1000
            THEN 'HIGH PRIORITY'
        WHEN d.total_data_mb >= 500
            THEN 'MEDIUM PRIORITY'
        ELSE 'REVIEW'
    END AS investigation_priority
FROM successful_logins s
LEFT JOIN large_data_access d
  ON d.user_id = s.user_id
 AND d.successful_login_time = s.successful_login_time
ORDER BY total_data_mb DESC;
