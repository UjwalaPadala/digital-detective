
import csv
import getpass
from pathlib import Path

import psycopg2


PROJECT_DIR = Path(__file__).resolve().parent.parent
CSV_FILE = PROJECT_DIR / "data" / "security_logs.csv"


def main():
    if not CSV_FILE.exists():
        print(f"CSV file not found: {CSV_FILE}")
        return

    password = getpass.getpass("Enter PostgreSQL password: ")
    connection = None
    run_id = None
    inserted = 0
    skipped = 0

    try:
        connection = psycopg2.connect(
            host="127.0.0.1",
            port=5432,
            database="digital_detective",
            user="postgres",
            password=password,
        )

        with connection:
            with connection.cursor() as cursor:
                # Record the start of this pipeline run.
                cursor.execute(
                    """
                    INSERT INTO etl_audit_log (
                        pipeline_name,
                        run_status
                    )
                    VALUES (%s, %s)
                    RETURNING run_id;
                    """,
                    ("security_log_csv_loader", "RUNNING"),
                )
                run_id = cursor.fetchone()[0]

                # Read and load CSV records.
                with CSV_FILE.open(
                    "r", newline="", encoding="utf-8"
                ) as file:
                    reader = csv.DictReader(file)

                    required_columns = {
                        "event_time",
                        "user_id",
                        "event_type",
                        "ip_address",
                        "country",
                        "resource_accessed",
                        "data_volume_mb",
                        "status",
                    }

                    if not required_columns.issubset(
                        reader.fieldnames or []
                    ):
                        raise ValueError(
                            "CSV is missing one or more required columns."
                        )

                    for row in reader:
                        values = (
                            row["event_time"],
                            row["user_id"],
                            row["event_type"],
                            row["ip_address"] or None,
                            row["country"] or None,
                            row["resource_accessed"] or None,
                            row["data_volume_mb"] or None,
                            row["status"] or None,
                        )

                        cursor.execute(
                            """
                            SELECT 1
                            FROM raw_security_logs
                            WHERE event_time = %s
                              AND user_id = %s
                              AND event_type = %s
                              AND ip_address
                                  IS NOT DISTINCT FROM %s
                              AND country
                                  IS NOT DISTINCT FROM %s
                              AND resource_accessed
                                  IS NOT DISTINCT FROM %s
                              AND data_volume_mb
                                  IS NOT DISTINCT FROM %s
                              AND status
                                  IS NOT DISTINCT FROM %s
                            LIMIT 1;
                            """,
                            values,
                        )

                        if cursor.fetchone():
                            skipped += 1
                            continue

                        cursor.execute(
                            """
                            INSERT INTO raw_security_logs (
                                event_time,
                                user_id,
                                event_type,
                                ip_address,
                                country,
                                resource_accessed,
                                data_volume_mb,
                                status
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                            """,
                            values,
                        )
                        inserted += 1

                cursor.execute(
                    "SELECT COUNT(*) FROM raw_security_logs;"
                )
                total_logs = cursor.fetchone()[0]

                # Mark this run as successful.
                cursor.execute(
                    """
                    UPDATE etl_audit_log
                    SET finished_at = CURRENT_TIMESTAMP,
                        records_inserted = %s,
                        records_skipped = %s,
                        run_status = %s
                    WHERE run_id = %s;
                    """,
                    (inserted, skipped, "SUCCESS", run_id),
                )

        print("\nETL load completed successfully!")
        print(f"New records inserted: {inserted}")
        print(f"Duplicate records skipped: {skipped}")
        print(f"Total database records: {total_logs}")
        print(f"Audit run ID: {run_id}")

    except (
        psycopg2.Error,
        OSError,
        csv.Error,
        KeyError,
        ValueError,
    ) as error:
        print(f"Pipeline failed: {error}")

        # Save a failure record when possible.
        # Roll back first in case the main transaction failed.
        if connection is not None and run_id is not None:
            try:
                connection.rollback()
                with connection:
                    with connection.cursor() as cursor:
                        cursor.execute(
                            """
                            UPDATE etl_audit_log
                            SET finished_at = CURRENT_TIMESTAMP,
                                records_inserted = %s,
                                records_skipped = %s,
                                run_status = %s,
                                error_message = %s
                            WHERE run_id = %s;
                            """,
                            (
                                inserted,
                                skipped,
                                "FAILED",
                                str(error)[:2000],
                                run_id,
                            ),
                        )
            except psycopg2.Error as audit_error:
                print(f"Could not save failure audit: {audit_error}")

    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    main()
