import sqlite3
from datetime import datetime

# Database file
DATABASE = "history.db"


def initialize_database():
    """
    Creates the scan_history table if it doesn't exist.
    """

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history (

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        url TEXT NOT NULL,

        risk_score INTEGER NOT NULL,

        risk_level TEXT NOT NULL,

        scan_time TEXT NOT NULL

    )
    """)

    conn.commit()
    conn.close()


def save_scan(url, score, risk_level):
    """
    Saves a URL scan to the database.
    """

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scan_history
    (url, risk_score, risk_level, scan_time)

    VALUES (?, ?, ?, ?)
    """, (

        url,
        score,
        risk_level,
        datetime.now().strftime("%d-%m-%Y %H:%M:%S")

    ))

    conn.commit()
    conn.close()


def get_history():
    """
    Returns complete scan history.
    """

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT *
    FROM scan_history
    ORDER BY id DESC
    """)

    history = cursor.fetchall()

    conn.close()

    return history


def get_dashboard_stats():
    """
    Returns statistics for dashboard.
    """

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Total scans
    cursor.execute("SELECT COUNT(*) FROM scan_history")
    total = cursor.fetchone()[0]

    # High Risk
    cursor.execute("""
    SELECT COUNT(*)
    FROM scan_history
    WHERE risk_level='High Risk'
    """)
    high = cursor.fetchone()[0]

    # Medium Risk
    cursor.execute("""
    SELECT COUNT(*)
    FROM scan_history
    WHERE risk_level='Medium Risk'
    """)
    medium = cursor.fetchone()[0]

    # Low Risk
    cursor.execute("""
    SELECT COUNT(*)
    FROM scan_history
    WHERE risk_level='Low Risk'
    """)
    low = cursor.fetchone()[0]

    conn.close()

    return {
        "total": total,
        "high": high,
        "medium": medium,
        "low": low
    }


def get_recent_scans(limit=5):
    """
    Returns the most recent scans.
    """

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    SELECT
        url,
        risk_level,
        scan_time

    FROM scan_history

    ORDER BY id DESC

    LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()

    conn.close()

    return rows


def clear_history():
    """
    Deletes all scan history.
    """

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("DELETE FROM scan_history")

    conn.commit()
    conn.close()