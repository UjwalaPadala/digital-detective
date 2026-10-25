
from pathlib import Path

import pandas as pd

PROJECT_DIR = Path(__file__).resolve().parent.parent
CSV_FILE = PROJECT_DIR / "data" / "security_logs.csv"
REPORT_FILE = PROJECT_DIR / "reports" / "security_log_analytics.md"


def main():
    if not CSV_FILE.exists():
        print("Security log CSV not found.")
        print("Generate it first using: python src/generate_logs.py")
        return

    df = pd.read_csv(CSV_FILE)

    required_columns = {
        "event_time",
        "user_id",
        "event_type",
        "data_volume_mb",
        "status",
    }

    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    df["event_time"] = pd.to_datetime(df["event_time"], errors="coerce")
    df["data_volume_mb"] = pd.to_numeric(
        df["data_volume_mb"], errors="coerce"
    ).fillna(0)

    event_counts = df["event_type"].value_counts()
    login_events = df[df["event_type"] == "LOGIN"]
    login_outcomes = login_events["status"].value_counts()
    file_access = df[df["event_type"] == "FILE_ACCESS"]

    user_summary = (
        df.groupby("user_id")
        .agg(
            total_events=("event_type", "size"),
            failed_logins=(
                "status",
                lambda values: (
                    (values == "FAILED")
                    & (df.loc[values.index, "event_type"] == "LOGIN")
                ).sum(),
            ),
            file_access_events=(
                "event_type",
                lambda values: (values == "FILE_ACCESS").sum(),
            ),
            total_data_accessed_mb=("data_volume_mb", "sum"),
        )
        .sort_values("total_data_accessed_mb", ascending=False)
    )

    report_lines = [
        "# Security Log Analytics Report",
        "",
        "Generated from the synthetic security log dataset.",
        "",
        "## Overview",
        "",
        f"- Total events: {len(df)}",
        f"- Unique users: {df['user_id'].nunique()}",
        f"- Login events: {len(login_events)}",
        f"- File-access events: {len(file_access)}",
        f"- Total file-access volume: {file_access['data_volume_mb'].sum():,.2f} MB",
        "",
        "## Events by Type",
        "",
        "| Event Type | Count |",
        "|---|---:|",
    ]

    for event_type, count in event_counts.items():
        report_lines.append(f"| {event_type} | {count} |")

    report_lines.extend([
        "",
        "## Login Outcomes",
        "",
        "| Status | Count |",
        "|---|---:|",
    ])

    for status, count in login_outcomes.items():
        report_lines.append(f"| {status} | {count} |")

    report_lines.extend([
        "",
        "## Activity by User",
        "",
        "| User | Total Events | Failed Logins | File Access Events | Data Accessed (MB) |",
        "|---|---:|---:|---:|---:|",
    ])

    for user_id, row in user_summary.iterrows():
        report_lines.append(
            f"| {user_id} | {row['total_events']} | "
            f"{row['failed_logins']} | {row['file_access_events']} | "
            f"{row['total_data_accessed_mb']:.2f} |"
        )

    report_lines.extend([
        "",
        "## Interpretation",
        "",
        "These summaries describe patterns in synthetic data. "
        "High event counts or large file-access volumes warrant context "
        "and review; they do not independently prove malicious activity.",
        "",
    ])

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    REPORT_FILE.write_text("\n".join(report_lines), encoding="utf-8")

    print("Analytics completed successfully!")
    print(f"Total events: {len(df)}")
    print(f"Unique users: {df['user_id'].nunique()}")
    print(f"File-access volume: {file_access['data_volume_mb'].sum():.2f} MB")
    print(f"Report saved to: {REPORT_FILE}")


if __name__ == "__main__":
    main()
