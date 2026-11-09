import sqlite3
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS administrator (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    login TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    ,must_change INTEGER NOT NULL DEFAULT 1 CHECK (must_change IN (0, 1))
);
CREATE TABLE IF NOT EXISTS login_attempt (
    id INTEGER PRIMARY KEY,
    source_ip TEXT NOT NULL,
    attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    successful INTEGER NOT NULL CHECK (successful IN (0, 1))
);
CREATE INDEX IF NOT EXISTS login_attempt_ip_time
    ON login_attempt(source_ip, attempted_at);
CREATE TABLE IF NOT EXISTS vpn_user (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    ,public_key TEXT
    ,address TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS vpn_user_public_key
    ON vpn_user(public_key) WHERE public_key IS NOT NULL;
CREATE TABLE IF NOT EXISTS hysteria_user (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')),
    expires_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS hysteria_user_password
    ON hysteria_user(password);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    # Права задаёт тот, кто файл создаёт: chmod установщика приходится на момент, когда на
    # девственном узле базы ещё нет, и она оставалась 0644, а в ней пароли Hysteria2 открытым
    # текстом (22.04, 09.11). Уже созданную базу правит chmod в install.sh.
    if not Path(path).exists():
        Path(path).touch(0o600)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def initialize(path: Path, login: str, password_hash: str | None) -> None:
    with connect(path) as conn:
        conn.executescript(SCHEMA)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(vpn_user)")}
        for column in ("public_key", "address"):
            if column not in columns:
                conn.execute(f"ALTER TABLE vpn_user ADD COLUMN {column} TEXT")
        if "must_change" not in {row[1] for row in conn.execute("PRAGMA table_info(administrator)")}:
            # Апгрейд живого узла: пароль у существующего администратора выбирали до нас,
            # обязательная замена касается только учётки, созданной этим запуском.
            conn.execute("ALTER TABLE administrator ADD COLUMN must_change INTEGER NOT NULL DEFAULT 0")
        existing = conn.execute("SELECT 1 FROM administrator WHERE id = 1").fetchone()
        if existing:
            return
        if password_hash is None:
            raise RuntimeError("administrator account is missing")
        conn.execute(
            "INSERT INTO administrator (id, login, password_hash, must_change) VALUES (1, ?, ?, 1)",
            (login, password_hash),
        )
