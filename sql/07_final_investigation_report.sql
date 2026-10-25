
SELECT
    user_id,
    COUNT(*) FILTER (
        WHERE event_type = 'LOGIN'
          AND status = 'FAILED'
    ) AS failed_logins,
    COUNT(*) FILTER (
        WHERE event_type = 'LOGIN'
          AND status = 'SUCCESS'
    ) AS successful_logins,
    COUNT(*) FILTER (
        WHERE event_type = 'FILE_ACCESS'
          AND data_volume_mb >= 500
    ) AS large_file_access_events,
    COALESCE(
        SUM(data_volume_mb) FILTER (
            WHERE event_type = 'FILE_ACCESS'
        ), 0
    ) AS total_data_accessed_mb,
    CASE
        WHEN COUNT(*) FILTER (
            WHERE event_type = 'LOGIN'
              AND status = 'FAILED'
        ) >= 3
        AND COUNT(*) FILTER (
            WHERE event_type = 'FILE_ACCESS'
              AND data_volume_mb >= 500
        ) >= 2
        THEN 'HIGH PRIORITY'
        ELSE 'REVIEW'
    END AS investigation_priority
FROM raw_security_logs
GROUP BY user_id
ORDER BY
    CASE
        WHEN COUNT(*) FILTER (
            WHERE event_type = 'LOGIN'
              AND status = 'FAILED'
        ) >= 3
        AND COUNT(*) FILTER (
            WHERE event_type = 'FILE_ACCESS'
              AND data_volume_mb >= 500
        ) >= 2
        THEN 1
        ELSE 2
    END,
    user_id;
