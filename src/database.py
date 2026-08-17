import sqlite3
from datetime import datetime


DATABASE = "data/security_events.db"


def create_database():
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            destination_ip TEXT,
            port INTEGER,
            severity TEXT NOT NULL,
            message TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_alert(alert):
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        INSERT INTO security_events (
            timestamp,
            threat_type,
            source_ip,
            destination_ip,
            port,
            severity,
            message
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        alert["threat_type"],
        alert["source_ip"],
        alert["destination_ip"],
        alert["port"],
        alert["severity"],
        alert["message"]
    ))

    connection.commit()
    connection.close()


def get_alerts():
    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        SELECT *
        FROM security_events
        ORDER BY id DESC
    """)

    alerts = cursor.fetchall()

    connection.close()

    return alerts


if __name__ == "__main__":
    create_database()
    print("Security database initialized successfully.")