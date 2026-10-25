
def is_duplicate(existing_record, new_record):
    """Check whether two normalized log records are identical."""
    return existing_record == new_record


def test_identical_security_logs_are_duplicates():
    existing = {
        "event_time": "2026-10-25 09:10:00",
        "user_id": "U104",
        "event_type": "LOGIN",
        "status": "FAILED",
    }

    new_record = existing.copy()

    assert is_duplicate(existing, new_record)


def test_different_login_statuses_are_not_duplicates():
    existing = {
        "event_time": "2026-10-25 09:10:00",
        "user_id": "U104",
        "event_type": "LOGIN",
        "status": "FAILED",
    }

    new_record = existing.copy()
    new_record["status"] = "SUCCESS"

    assert not is_duplicate(existing, new_record)


def test_different_event_times_are_not_duplicates():
    existing = {
        "event_time": "2026-10-25 09:10:00",
        "user_id": "U104",
        "event_type": "LOGIN",
        "status": "FAILED",
    }

    new_record = existing.copy()
    new_record["event_time"] = "2026-10-25 09:11:00"

    assert not is_duplicate(existing, new_record)
