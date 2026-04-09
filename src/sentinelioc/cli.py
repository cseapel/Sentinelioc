from __future__ import annotations

from datetime import datetime
from pathlib import Path

import typer
from rich import print

from sentinelioc.database import DEFAULT_DB_PATH, IOCDatabase
from sentinelioc.importer import load_iocs
from sentinelioc.matcher import IOCMatcher
from sentinelioc.models import ScanReport
from sentinelioc.persistence import StartupScanner
from sentinelioc.reporter import print_report, save_report
from sentinelioc.scanner import HostScanner


app = typer.Typer(help="SentinelIOC defensive host scanner")


def build_report(
    findings,
    scanned_paths: list[Path],
    scanned_files: int,
    scanned_processes: int,
    scanned_startup_items: int,
) -> ScanReport:
    return ScanReport(
        generated_at=datetime.utcnow().isoformat() + "Z",
        findings=findings,
        scanned_paths=[str(path) for path in scanned_paths],
        scanned_files=scanned_files,
        scanned_processes=scanned_processes,
        scanned_startup_items=scanned_startup_items,
    )


@app.command("init-db")
def init_db(db_path: Path = DEFAULT_DB_PATH) -> None:
    database = IOCDatabase(db_path)
    database.init_db()
    print(f"[green]Initialized database:[/green] {db_path}")


@app.command("import-iocs")
def import_iocs(
    file: Path = typer.Option(..., exists=True, readable=True, help="Path to IOC JSON or CSV file"),
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    database = IOCDatabase(db_path)
    database.init_db()
    iocs = load_iocs(file)
    count = database.insert_iocs(iocs)
    print(f"[green]Imported {count} IOC records[/green] from {file}")


@app.command("scan")
def scan(
    path: list[Path] = typer.Option(..., exists=True, readable=True, help="Path(s) to scan"),
    output: Path | None = typer.Option(None, help="Optional JSON report output path"),
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    database = IOCDatabase(db_path)
    scanner = HostScanner()
    matcher = IOCMatcher(database)

    artifacts, scanned_files = scanner.scan_paths(path)
    findings = matcher.match_artifacts(artifacts)
    report = build_report(findings, path, scanned_files, 0, 0)

    print_report(report)
    if output:
        save_report(report, output)
        print(f"[cyan]Saved report:[/cyan] {output}")


@app.command("scan-processes")
def scan_processes(
    output: Path | None = typer.Option(None, help="Optional JSON report output path"),
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    database = IOCDatabase(db_path)
    scanner = HostScanner()
    matcher = IOCMatcher(database)

    artifacts, scanned_processes = scanner.scan_processes()
    findings = matcher.match_artifacts(artifacts)
    report = build_report(findings, [], 0, scanned_processes, 0)

    print_report(report)
    if output:
        save_report(report, output)
        print(f"[cyan]Saved report:[/cyan] {output}")


@app.command("scan-startup")
def scan_startup(
    output: Path | None = typer.Option(None, help="Optional JSON report output path"),
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    database = IOCDatabase(db_path)
    startup_scanner = StartupScanner()
    matcher = IOCMatcher(database)

    artifacts, scanned_startup_items = startup_scanner.scan()
    findings = matcher.match_artifacts(artifacts)
    report = build_report(findings, [], 0, 0, scanned_startup_items)

    print_report(report)
    if output:
        save_report(report, output)
        print(f"[cyan]Saved report:[/cyan] {output}")


@app.command("full-scan")
def full_scan(
    path: list[Path] = typer.Option(..., exists=True, readable=True, help="Path(s) to scan"),
    output: Path | None = typer.Option(None, help="Optional JSON report output path"),
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    database = IOCDatabase(db_path)
    scanner = HostScanner()
    startup_scanner = StartupScanner()
    matcher = IOCMatcher(database)

    file_artifacts, scanned_files = scanner.scan_paths(path)
    process_artifacts, scanned_processes = scanner.scan_processes()
    startup_artifacts, scanned_startup_items = startup_scanner.scan()

    findings = matcher.match_artifacts(file_artifacts + process_artifacts + startup_artifacts)
    report = build_report(findings, path, scanned_files, scanned_processes, scanned_startup_items)

    print_report(report)
    if output:
        save_report(report, output)
        print(f"[cyan]Saved report:[/cyan] {output}")


if __name__ == "__main__":
    app()
