from __future__ import annotations

from pathlib import Path

import psutil

from sentinelioc.hashing import sha256_file
from sentinelioc.models import ScanArtifact


class HostScanner:
    def scan_paths(self, paths: list[Path]) -> tuple[list[ScanArtifact], int]:
        artifacts: list[ScanArtifact] = []
        scanned_files = 0

        for base_path in paths:
            if not base_path.exists():
                continue

            if base_path.is_file():
                artifact = self._scan_single_file(base_path)
                scanned_files += 1
                if artifact:
                    artifacts.append(artifact)
                continue

            for file_path in base_path.rglob("*"):
                if not file_path.is_file():
                    continue
                scanned_files += 1
                artifact = self._scan_single_file(file_path)
                if artifact:
                    artifacts.append(artifact)

        return artifacts, scanned_files

    def _scan_single_file(self, file_path: Path) -> ScanArtifact | None:
        try:
            file_hash = sha256_file(file_path)
            return ScanArtifact(
                artifact_type="file",
                artifact_value=file_path.name,
                path=str(file_path.resolve()),
                sha256=file_hash,
            )
        except (PermissionError, OSError):
            return None

    def scan_processes(self) -> tuple[list[ScanArtifact], int]:
        artifacts: list[ScanArtifact] = []
        scanned_processes = 0

        for process in psutil.process_iter(["pid", "name", "exe"]):
            scanned_processes += 1
            try:
                info = process.info
                exe_path = info.get("exe")
                process_name = info.get("name") or "unknown"
                pid = info.get("pid")

                sha256 = None
                if exe_path:
                    try:
                        sha256 = sha256_file(Path(exe_path))
                    except (PermissionError, OSError):
                        sha256 = None

                artifacts.append(
                    ScanArtifact(
                        artifact_type="process",
                        artifact_value=process_name,
                        path=exe_path,
                        pid=pid,
                        process_name=process_name,
                        sha256=sha256,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return artifacts, scanned_processes
