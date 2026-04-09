from pathlib import Path

from sentinelioc.database import IOCDatabase
from sentinelioc.matcher import IOCMatcher
from sentinelioc.models import IOCRecord, ScanArtifact


def test_match_filename(tmp_path: Path) -> None:
    db = IOCDatabase(tmp_path / "test.db")
    db.init_db()
    db.insert_iocs([
        IOCRecord(type="filename", value="bad.exe", confidence=40, source="test")
    ])

    matcher = IOCMatcher(db)
    findings = matcher.match_artifacts([
        ScanArtifact(artifact_type="file", artifact_value="bad.exe", path="/tmp/bad.exe")
    ])

    assert len(findings) == 1
    assert findings[0].matched_ioc_value == "bad.exe"
