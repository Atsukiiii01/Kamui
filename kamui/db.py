import sqlite3
import os

DB_PATH = "kamui_state.db"

def init_db():
    """Initializes the SQLite database and creates the targets table."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                ip TEXT PRIMARY KEY,
                status TEXT DEFAULT 'PENDING'
            )
        ''')

def add_targets(ips):
    """Inserts targets into the database. Ignores if they already exist."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany(
            "INSERT OR IGNORE INTO targets (ip, status) VALUES (?, 'PENDING')",
            [(ip,) for ip in ips]
        )

def get_pending_targets():
    """Retrieves all targets that have not been completed."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("SELECT ip FROM targets WHERE status = 'PENDING'")
        return [row[0] for row in cursor.fetchall()]

def mark_completed(ip):
    """Marks a specific target as completed."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("UPDATE targets SET status = 'COMPLETED' WHERE ip = ?", (ip,))

def reset_db():
    """Wipes the state. Used for fresh scans."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)