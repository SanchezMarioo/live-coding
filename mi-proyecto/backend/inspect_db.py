import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "data" / "app.db"

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

tables = [row[0] for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
print("DB:", DB_PATH)
print("TABLES:", tables)

if "users" in tables:
    users = cur.execute(
        "SELECT id, username, email, auth_provider, created_at FROM users ORDER BY id DESC LIMIT 10"
    ).fetchall()
    print("USERS (latest 10):", users)

if "messages" in tables:
    messages = cur.execute(
        "SELECT id, user_id, category, text, created_at FROM messages ORDER BY id DESC LIMIT 10"
    ).fetchall()
    print("MESSAGES (latest 10):", messages)

conn.close()
