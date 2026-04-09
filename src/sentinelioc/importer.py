from __future__ import annotations

import csv
import json
from pathlib import Path

from sentinelioc.models import IOCRecord


REQUIRED_FIELDS = {"type", "value"}


def load_iocs(file_path: Path) -> list[IOCRecord]:
    suffix = file_path.suffix.lower()
    if suffix == ".json":
        return _load_json(file_path)
    if suffix == ".csv":
        return _load_csv(file_path)
    raise ValueError("Unsupported IOC format. Use JSON or CSV.")


def _load_json(file_path: Path) -> list[IOCRecord]:
    data = json.loads(file_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("JSON IOC file must contain a list of objects.")
    return [IOCRecord(**item) for item in data]


def _load_csv(file_path: Path) -> list[IOCRecord]:
    with file_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames or not REQUIRED_FIELDS.issubset(set(reader.fieldnames)):
            raise ValueError("CSV IOC file must include at least 'type' and 'value' columns.")
        return [IOCRecord(**_clean_row(row)) for row in reader]


def _clean_row(row: dict) -> dict:
    cleaned = dict(row)
    if "confidence" in cleaned and cleaned["confidence"] not in (None, ""):
        cleaned["confidence"] = int(cleaned["confidence"])
    return {key: value for key, value in cleaned.items() if value not in (None, "")}
