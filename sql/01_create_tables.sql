
CREATE TABLE IF NOT EXISTS raw_security_logs (
    event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_time TIMESTAMP NOT NULL,
    user_id VARCHAR(50) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    country VARCHAR(50),
    resource_accessed VARCHAR(255),
    data_volume_mb NUMERIC(12,2),
    status VARCHAR(20)
);
