from __future__ import annotations

from pathlib import Path

from sentinelioc.hashing import sha256_file
from sentinelioc.models import ScanArtifact
from sentinelioc.paths import get_startup_paths


class StartupScanner:
    def scan(self) -> tuple[list[ScanArtifact], int]:
        artifacts: list[ScanArtifact] = []
        scanned_items = 0

        for startup_path in get_startup_paths():
            if not startup_path.exists():
                continue

            if startup_path.is_file():
                scanned_items += 1
                artifact = self._build_artifact(startup_path)
                if artifact:
                    artifacts.append(artifact)
                continue

            for item in startup_path.rglob("*"):
                if not item.is_file():
                    continue
                scanned_items += 1
                artifact = self._build_artifact(item)
                if artifact:
                    artifacts.append(artifact)

        return artifacts, scanned_items

    def _build_artifact(self, path: Path) -> ScanArtifact | None:
        try:
            file_hash = sha256_file(path)
        except (PermissionError, OSError, IsADirectoryError):
            file_hash = None

        try:
            resolved = str(path.resolve())
        except OSError:
            resolved = str(path)

        return ScanArtifact(
            artifact_type="startup",
            artifact_value=path.name,
            path=resolved,
            sha256=file_hash,
        )
