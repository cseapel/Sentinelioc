from __future__ import annotations

from sentinelioc.database import IOCDatabase
from sentinelioc.models import Finding, ScanArtifact


def severity_from_confidence(confidence: int) -> str:
    if confidence >= 90:
        return "critical"
    if confidence >= 70:
        return "high"
    if confidence >= 50:
        return "medium"
    return "low"


class IOCMatcher:
    def __init__(self, database: IOCDatabase):
        self.database = database

    def match_artifacts(self, artifacts: list[ScanArtifact]) -> list[Finding]:
        findings: list[Finding] = []

        for artifact in artifacts:
            if artifact.sha256:
                findings.extend(
                    self._build_findings(
                        artifact=artifact,
                        ioc_type="hash_sha256",
                        value=artifact.sha256,
                        reason="Exact SHA256 match",
                    )
                )

            if artifact.artifact_value:
                findings.extend(
                    self._build_findings(
                        artifact=artifact,
                        ioc_type="filename",
                        value=artifact.artifact_value,
                        reason="Filename matched IOC",
                    )
                )

            if artifact.path:
                findings.extend(
                    self._build_findings(
                        artifact=artifact,
                        ioc_type="filepath",
                        value=artifact.path,
                        reason="File path matched IOC",
                    )
                )

        return findings

    def _build_findings(
        self,
        artifact: ScanArtifact,
        ioc_type: str,
        value: str,
        reason: str,
    ) -> list[Finding]:
        matches = self.database.lookup(ioc_type, value)
        findings: list[Finding] = []

        for match in matches:
            confidence = int(match["confidence"])
            findings.append(
                Finding(
                    artifact_type=artifact.artifact_type,
                    artifact_value=artifact.artifact_value,
                    matched_ioc_type=match["type"],
                    matched_ioc_value=match["value"],
                    confidence=confidence,
                    severity=severity_from_confidence(confidence),
                    reason=reason,
                    path=artifact.path,
                    pid=artifact.pid,
                    process_name=artifact.process_name,
                )
            )

        return findings
