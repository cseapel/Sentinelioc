from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field


IOCType = Literal["hash_sha256", "filename", "filepath"]
Severity = Literal["critical", "high", "medium", "low"]
ArtifactType = Literal["file", "process", "startup"]


class IOCRecord(BaseModel):
    type: IOCType
    value: str
    confidence: int = Field(default=50, ge=0, le=100)
    source: str = "manual"
    threat_name: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    expires_at: Optional[str] = None
    notes: Optional[str] = None


class ScanArtifact(BaseModel):
    artifact_type: ArtifactType
    artifact_value: str
    path: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None
    sha256: Optional[str] = None


class Finding(BaseModel):
    artifact_type: ArtifactType
    artifact_value: str
    matched_ioc_type: IOCType
    matched_ioc_value: str
    confidence: int
    severity: Severity
    reason: str
    path: Optional[str] = None
    pid: Optional[int] = None
    process_name: Optional[str] = None


class ScanReport(BaseModel):
    generated_at: str
    findings: list[Finding]
    scanned_paths: list[str] = []
    scanned_files: int = 0
    scanned_processes: int = 0
    scanned_startup_items: int = 0

    @classmethod
    def empty(cls) -> "ScanReport":
        return cls(
            generated_at=datetime.utcnow().isoformat() + "Z",
            findings=[],
            scanned_paths=[],
            scanned_files=0,
            scanned_processes=0,
            scanned_startup_items=0,
        )
