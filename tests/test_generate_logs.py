
import csv
import subprocess
import sys
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
GENERATOR = PROJECT_DIR / "src" / "generate_logs.py"
CSV_FILE = PROJECT_DIR / "data" / "security_logs.csv"


def test_generator_script_exists():
    assert GENERATOR.exists()


def test_generator_creates_valid_csv():
    result = subprocess.run(
        [sys.executable, str(GENERATOR)],
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert CSV_FILE.exists()

    with CSV_FILE.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        rows = list(reader)

    expected_columns = {
        "event_time",
        "user_id",
        "event_type",
        "ip_address",
        "country",
        "resource_accessed",
        "data_volume_mb",
        "status",
    }

    assert expected_columns.issubset(reader.fieldnames or [])
    assert len(rows) > 0
    assert all(row["user_id"] for row in rows)
