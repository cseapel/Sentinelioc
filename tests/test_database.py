from pathlib import Path

from sentinelioc.database import IOCDatabase
from sentinelioc.models import IOCRecord


def test_insert_and_lookup(tmp_path: Path) -> None:
    db = IOCDatabase(tmp_path / "test.db")
    db.init_db()
    db.insert_iocs([
        IOCRecord(type="filename", value="bad.exe", confidence=50, source="test")
    ])
    rows = db.lookup("filename", "bad.exe")
    assert len(rows) == 1
    assert rows[0]["value"] == "bad.exe"
