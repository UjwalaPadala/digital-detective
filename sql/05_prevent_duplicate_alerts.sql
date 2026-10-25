
CREATE UNIQUE INDEX IF NOT EXISTS
    uq_incident_alert_user_login
ON incident_alerts (user_id, successful_login_time);
