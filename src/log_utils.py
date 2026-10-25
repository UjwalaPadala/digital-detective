
REQUIRED_COLUMNS = {
    "event_time",
    "user_id",
    "event_type",
    "ip_address",
    "country",
    "resource_accessed",
    "data_volume_mb",
    "status",
}


def validate_columns(fieldnames):
    """Check that all required CSV columns exist."""
    if not fieldnames:
        raise ValueError("CSV is missing its header row.")

    missing = REQUIRED_COLUMNS - set(fieldnames)

    if missing:
        raise ValueError(
            f"CSV is missing required columns: {sorted(missing)}"
        )


def normalize_log_row(row):
    """Validate and normalize one CSV record for PostgreSQL."""
    missing = REQUIRED_COLUMNS - set(row.keys())

    if missing:
        raise ValueError(
            f"Log row is missing required columns: {sorted(missing)}"
        )

    if (
        not row["event_time"]
        or not row["user_id"]
        or not row["event_type"]
    ):
        raise ValueError(
            "event_time, user_id, and event_type cannot be empty."
        )

    return (
        row["event_time"],
        row["user_id"],
        row["event_type"],
        row["ip_address"] or None,
        row["country"] or None,
        row["resource_accessed"] or None,
        row["data_volume_mb"] or None,
        row["status"] or None,
    )
