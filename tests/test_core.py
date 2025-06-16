import os
from pathlib import Path
import pytest
from endectools.core import encrypt_path, decrypt_path

@pytest.fixture
def tmp_data(tmp_path):
    # create a sample file and directory
    file = tmp_path / "foo.txt"
    file.write_text("hello world")
    d = tmp_path / "subdir"
    d.mkdir()
    (d / "bar.txt").write_text("👋")
    return tmp_path, file, d

@pytest.mark.parametrize("src_attr", ["file", "dir"] )
def test_roundtrip(tmp_data, src_attr):
    base, file, d = tmp_data
    src = {"file": file, "dir": d}[src_attr]
    enc = base / f"{src.name}.enc"

    # Encrypt
    encrypt_path(src, enc, b"password")
    assert enc.exists(), "Encrypted file should be created"

    # Remove original source to ensure decrypt restores it
    if src.is_dir():
        # remove inner file, then directory
        (src / "bar.txt").unlink()
        src.rmdir()
    else:
        src.unlink()

    # Decrypt
    decrypt_path(enc, base / src.name, b"password")

    # Verify contents
    if src.is_dir():
        out_file = base / src.name / "bar.txt"
        assert out_file.exists(), "Decrypted directory should contain bar.txt"
        assert out_file.read_text() == "👋"
    else:
        out_file = base / src.name
        assert out_file.exists(), "Decrypted file should exist"
        assert out_file.read_text() == "hello world"
