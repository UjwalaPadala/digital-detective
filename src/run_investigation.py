
import getpass
from pathlib import Path

import psycopg2

PROJECT_DIR = Path(__file__).resolve().parent.parent
SQL_FILE = PROJECT_DIR / "sql" / "04_generate_incident_alerts.sql"


def main():
    if not SQL_FILE.exists():
        print(f"SQL file not found: {SQL_FILE}")
        return

    password = getpass.getpass("Enter PostgreSQL password: ")
    connection = None

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
                sql_query = SQL_FILE.read_text(encoding="utf-8")
                cursor.execute(sql_query)

                cursor.execute("""
                    SELECT user_id,
                           failed_attempts,
                           large_access_events,
                           total_data_mb,
                           investigation_priority
                    FROM incident_alerts
                    ORDER BY alert_id DESC;
                """)

                alerts = cursor.fetchall()

        print("\nInvestigation completed successfully!")
        print(f"Total incident alerts: {len(alerts)}")

        if alerts:
            print("\nIncident Alerts")
            print("-" * 75)

            for alert in alerts:
                print(
                    f"User: {alert[0]} | "
                    f"Failed logins: {alert[1]} | "
                    f"Large accesses: {alert[2]} | "
                    f"Data accessed: {alert[3]} MB | "
                    f"Priority: {alert[4]}"
                )
        else:
            print("No incident alerts found.")

    except (psycopg2.Error, OSError) as error:
        print(f"Investigation failed: {error}")

    finally:
        if connection is not None:
            connection.close()


if __name__ == "__main__":
    main()
