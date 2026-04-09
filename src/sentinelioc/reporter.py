from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

from sentinelioc.models import ScanReport


console = Console()


def print_report(report: ScanReport) -> None:
    table = Table(title="SentinelIOC Findings")
    table.add_column("Severity")
    table.add_column("Artifact Type")
    table.add_column("Artifact")
    table.add_column("IOC Match")
    table.add_column("Reason")

    for finding in report.findings:
        table.add_row(
            finding.severity,
            finding.artifact_type,
            finding.path or finding.artifact_value,
            f"{finding.matched_ioc_type}: {finding.matched_ioc_value}",
            finding.reason,
        )

    if report.findings:
        console.print(table)
    else:
        console.print("[green]No IOC matches found.[/green]")

    console.print(
        " | ".join(
            [
                f"Scanned files: {report.scanned_files}",
                f"Scanned processes: {report.scanned_processes}",
                f"Scanned startup items: {report.scanned_startup_items}",
                f"Findings: {len(report.findings)}",
            ]
        )
    )


def save_report(report: ScanReport, output_path: Path) -> None:
    output_path.write_text(
        json.dumps(report.model_dump(), indent=2),
        encoding="utf-8",
    )
