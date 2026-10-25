
import pytest

from src.log_utils import normalize_log_row, validate_columns


VALID_COLUMNS = [
    "event_time",
    "user_id",
    "event_type",
    "ip_address",
    "country",
    "resource_accessed",
    "data_volume_mb",
    "status",
]

VALID_ROW = {
    "event_time": "2026-10-25 09:10:00",
    "user_id": "U104",
    "event_type": "LOGIN",
    "ip_address": "198.51.100.25",
    "country": "India",
    "resource_accessed": "",
    "data_volume_mb": "",
    "status": "FAILED",
}


def test_valid_csv_columns_are_accepted():
    validate_columns(VALID_COLUMNS)


def test_missing_csv_columns_are_rejected():
    with pytest.raises(ValueError, match="missing required columns"):
        validate_columns(["event_time", "user_id"])


def test_valid_row_is_normalized():
    values = normalize_log_row(VALID_ROW)

    assert values[0] == "2026-10-25 09:10:00"
    assert values[1] == "U104"
    assert values[2] == "LOGIN"
    assert values[5] is None
    assert values[6] is None


def test_missing_required_row_fields_are_rejected():
    row = VALID_ROW.copy()
    del row["user_id"]

    with pytest.raises(ValueError, match="missing required columns"):
        normalize_log_row(row)


def test_empty_user_id_is_rejected():
    row = VALID_ROW.copy()
    row["user_id"] = ""

    with pytest.raises(ValueError, match="cannot be empty"):
        normalize_log_row(row)
