
CREATE TABLE IF NOT EXISTS incident_alerts (
    alert_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    failed_attempts INTEGER NOT NULL,
    successful_login_time TIMESTAMP,
    large_access_events INTEGER NOT NULL,
    total_data_mb NUMERIC(12,2) NOT NULL,
    investigation_priority VARCHAR(20) NOT NULL,
    alert_created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
