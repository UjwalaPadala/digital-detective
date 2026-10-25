
import csv
from pathlib import Path

# Find the main project directory
PROJECT_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

output_file = DATA_DIR / "security_logs.csv"

# Synthetic security events for our investigation
events = [
    # Normal activity by another user
    {
        "event_time": "2026-10-25 09:00:00",
        "user_id": "U101",
        "event_type": "LOGIN",
        "ip_address": "192.0.2.10",
        "country": "India",
        "resource_accessed": "",
        "data_volume_mb": "",
        "status": "SUCCESS",
    },
    {
        "event_time": "2026-10-25 09:05:00",
        "user_id": "U101",
        "event_type": "FILE_ACCESS",
        "ip_address": "192.0.2.10",
        "country": "India",
        "resource_accessed": "team_report.csv",
        "data_volume_mb": 5,
        "status": "SUCCESS",
    },

    # Suspicious sequence: repeated failures, then success
    {
        "event_time": "2026-10-25 09:10:00",
        "user_id": "U104",
        "event_type": "LOGIN",
        "ip_address": "198.51.100.25",
        "country": "India",
        "resource_accessed": "",
        "data_volume_mb": "",
        "status": "FAILED",
    },
    {
        "event_time": "2026-10-25 09:11:00",
        "user_id": "U104",
        "event_type": "LOGIN",
        "ip_address": "198.51.100.25",
        "country": "India",
        "resource_accessed": "",
        "data_volume_mb": "",
        "status": "FAILED",
    },
    {
        "event_time": "2026-10-25 09:12:00",
        "user_id": "U104",
        "event_type": "LOGIN",
        "ip_address": "198.51.100.25",
        "country": "India",
        "resource_accessed": "",
        "data_volume_mb": "",
        "status": "FAILED",
    },
    {
        "event_time": "2026-10-25 09:14:00",
        "user_id": "U104",
        "event_type": "LOGIN",
        "ip_address": "198.51.100.25",
        "country": "India",
        "resource_accessed": "",
        "data_volume_mb": "",
        "status": "SUCCESS",
    },
    {
        "event_time": "2026-10-25 09:16:00",
        "user_id": "U104",
        "event_type": "FILE_ACCESS",
        "ip_address": "198.51.100.25",
        "country": "India",
        "resource_accessed": "customer_records.csv",
        "data_volume_mb": 850,
        "status": "SUCCESS",
    },
    {
        "event_time": "2026-10-25 09:18:00",
        "user_id": "U104",
        "event_type": "FILE_ACCESS",
        "ip_address": "198.51.100.25",
        "country": "India",
        "resource_accessed": "financial_records.csv",
        "data_volume_mb": 1200,
        "status": "SUCCESS",
    },

    # Another account with an ordinary login
    {
        "event_time": "2026-10-25 10:00:00",
        "user_id": "U102",
        "event_type": "LOGIN",
        "ip_address": "192.0.2.20",
        "country": "India",
        "resource_accessed": "",
        "data_volume_mb": "",
        "status": "SUCCESS",
    },
]

fields = [
    "event_time",
    "user_id",
    "event_type",
    "ip_address",
    "country",
    "resource_accessed",
    "data_volume_mb",
    "status",
]

with output_file.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=fields)
    writer.writeheader()
    writer.writerows(events)

print(f"Generated {len(events)} synthetic events.")
print(f"CSV location: {output_file}")
