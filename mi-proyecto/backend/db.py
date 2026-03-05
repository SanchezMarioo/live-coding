import os
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    avatar_url TEXT NOT NULL DEFAULT '',
    cover_url TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    auth_provider TEXT NOT NULL DEFAULT 'local',
    google_sub TEXT,
    created_at TEXT NOT NULL,
    last_login_at TEXT,
    UNIQUE(google_sub)
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    parent_id INTEGER,
    category TEXT NOT NULL,
    text TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (parent_id) REFERENCES messages (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_friendships (
    user_id INTEGER NOT NULL,
    friend_user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, friend_user_id),
    CHECK (user_id <> friend_user_id),
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (friend_user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS user_follows (
    follower_user_id INTEGER NOT NULL,
    followee_user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (follower_user_id, followee_user_id),
    CHECK (follower_user_id <> followee_user_id),
    FOREIGN KEY (follower_user_id) REFERENCES users (id) ON DELETE CASCADE,
    FOREIGN KEY (followee_user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_category_created ON messages (category, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_parent ON messages (parent_id);
CREATE INDEX IF NOT EXISTS idx_messages_user ON messages (user_id);
CREATE INDEX IF NOT EXISTS idx_friendships_friend ON user_friendships (friend_user_id);
CREATE INDEX IF NOT EXISTS idx_follows_followee ON user_follows (followee_user_id);
CREATE INDEX IF NOT EXISTS idx_follows_follower ON user_follows (follower_user_id);
"""


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_db_path() -> str:
    db_path = current_app.config["DATABASE_PATH"]
    if os.path.isabs(db_path):
        return db_path

    return os.path.join(current_app.root_path, db_path)


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        db_path = _resolve_db_path()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn

    return g.db


def close_db(_error=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db() -> None:
    db = get_db()
    db.executescript(SCHEMA_SQL)

    # Backward-compatible migration for existing local databases.
    existing_columns = {
        row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()
    }
    if "auth_provider" not in existing_columns:
        db.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local'")
    if "google_sub" not in existing_columns:
        db.execute("ALTER TABLE users ADD COLUMN google_sub TEXT")
    if "first_name" not in existing_columns:
        db.execute("ALTER TABLE users ADD COLUMN first_name TEXT NOT NULL DEFAULT ''")
    if "last_name" not in existing_columns:
        db.execute("ALTER TABLE users ADD COLUMN last_name TEXT NOT NULL DEFAULT ''")
    if "avatar_url" not in existing_columns:
        db.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT NOT NULL DEFAULT ''")
    if "cover_url" not in existing_columns:
        db.execute("ALTER TABLE users ADD COLUMN cover_url TEXT NOT NULL DEFAULT ''")

    db.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users (google_sub) WHERE google_sub IS NOT NULL"
    )
    db.commit()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)

    @app.cli.command("init-db")
    def init_db_command():
        init_db()
        print("Database initialized.")
