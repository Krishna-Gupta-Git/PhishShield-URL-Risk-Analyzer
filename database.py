import sqlite3
from datetime import datetime

DATABASE = "history.db"


def initialize_database():
    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scan_history(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        url TEXT,

        risk_score INTEGER,

        risk_level TEXT,

        scan_time TEXT

    )
    """)

    conn.commit()
    conn.close()


def save_scan(url, score, risk_level):

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