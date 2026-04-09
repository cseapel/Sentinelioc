# SentinelIOC

SentinelIOC is a defensive IOC scanner that correlates local host artifacts against curated indicators of compromise.

## Features
- Import IOCs from JSON or CSV
- Store IOCs in SQLite
- Scan files by SHA256 hash
- Check running processes
- Scan basic startup / persistence locations
- Generate JSON reports
- Clean terminal output with Rich
- Safe by default: report-only behavior

## Supported IOC Types
- `hash_sha256`
- `filename`
- `filepath`

## Installation

### Development install
```bash
pip install -e .
```

### Install dev tools
```bash
pip install -r requirements-dev.txt
```

## Quick Start
```bash
sentinelioc init-db
sentinelioc import-iocs --file examples/sample_iocs.json
sentinelioc scan --path ./examples/test_data --output report.json
sentinelioc scan-processes --output process_report.json
sentinelioc scan-startup --output startup_report.json
sentinelioc full-scan --path ./examples/test_data --output full_report.json
```

## IOC File Example
```json
[
  {
    "type": "filename",
    "value": "suspicious.exe",
    "confidence": 45,
    "source": "sample_feed",
    "threat_name": "TestFamily"
  }
]
```

## Design Goals
- defensive-only host analysis
- clear and explainable results
- minimal false positives
- modular CLI architecture

## Safety Note
SentinelIOC is a defensive security tool for analysis and reporting. It does not delete files automatically.

## Roadmap
- V1: IOC import, file scan, process scan, JSON reporting
- V2: startup/persistence scanning, IOC deduplication, better confidence handling
- V3: YARA support, HTML reports, AI-assisted IOC enrichment

## Packaging
Build the package with:
```bash
python -m build
```
