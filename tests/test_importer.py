from pathlib import Path

from sentinelioc.importer import load_iocs


def test_load_json_iocs(tmp_path: Path) -> None:
    file_path = tmp_path / "iocs.json"
    file_path.write_text('[{"type": "filename", "value": "bad.exe", "confidence": 50}]', encoding="utf-8")
    iocs = load_iocs(file_path)
    assert len(iocs) == 1
    assert iocs[0].value == "bad.exe"
