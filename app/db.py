import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "vulnlab.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create schema and seed data. Safe to re-run: drops and recreates."""
    conn = get_db()
    cur = conn.cursor()

    cur.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        DROP TABLE IF EXISTS sessions;

        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            bio TEXT DEFAULT ''
        );

        CREATE TABLE notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        );

        -- Deliberately trivial session store: a token that is just the
        -- username, base64'd, with no signature. Used by the "broken auth"
        -- vulnerability. Do not model real sessions on this.
        CREATE TABLE sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL
        );
        """
    )

    # Seed users. Passwords are stored in plaintext ON PURPOSE for lab #2
    # (and because this app never sees real credentials). Never do this
    # in anything that touches real users.
    cur.execute(
        "INSERT INTO users (username, password, is_admin, bio) VALUES (?, ?, ?, ?)",
        ("alice", "alice123", 0, "I like cats and CTFs."),
    )
    cur.execute(
        "INSERT INTO users (username, password, is_admin, bio) VALUES (?, ?, ?, ?)",
        ("bob", "hunter2", 0, "Still learning Flask."),
    )
    cur.execute(
        "INSERT INTO users (username, password, is_admin, bio) VALUES (?, ?, ?, ?)",
        ("admin", "SuperSecretAdminPW!2026", 1, "Site administrator."),
    )

    cur.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (1, "Shopping list", "Milk, eggs, bread."),
    )
    cur.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (2, "TODO", "Finish the internship homework."),
    )
    cur.execute(
        "INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)",
        (3, "Admin reminder", "Rotate the backup keys this month."),
    )

    conn.commit()
    conn.close()
