import sqlite3
from datetime import datetime

# UPDATED DB NAME to fix your error automatically
DB_NAME = "security_logs_v2.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        message TEXT
    )
    """)
    conn.commit()
    conn.close()

def add_log(message):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO logs (timestamp, message) VALUES (?, ?)", (time_str, message))
    conn.commit()
    conn.close()