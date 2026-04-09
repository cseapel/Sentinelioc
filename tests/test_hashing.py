from pathlib import Path

from sentinelioc.hashing import sha256_file


def test_sha256_file(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.txt"
    test_file.write_text("hello", encoding="utf-8")
    digest = sha256_file(test_file)
    assert len(digest) == 64
