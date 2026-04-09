from __future__ import annotations

import sqlite3
from pathlib import Path

from sentinelioc.models import IOCRecord


DEFAULT_DB_PATH = Path("sentinelioc.db")


class IOCDatabase:
    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)

    def connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def init_db(self) -> None:
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS iocs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    confidence INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    threat_name TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    expires_at TEXT,
                    notes TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(type, value)"
            )
            conn.commit()

    def insert_iocs(self, iocs: list[IOCRecord]) -> int:
        rows = [
            (
                ioc.type,
                ioc.value,
                ioc.confidence,
                ioc.source,
                ioc.threat_name,
                ioc.first_seen,
                ioc.last_seen,
                ioc.expires_at,
                ioc.notes,
            )
            for ioc in iocs
        ]
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO iocs (
                    type, value, confidence, source,
                    threat_name, first_seen, last_seen, expires_at, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            conn.commit()
        return len(rows)

    def lookup(self, ioc_type: str, value: str) -> list[dict]:
        with self.connect() as conn:
            cursor = conn.execute(
                "SELECT type, value, confidence, source, threat_name, notes FROM iocs WHERE type = ? AND value = ?",
                (ioc_type, value),
            )
            columns = [column[0] for column in cursor.description]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]
