import os
from pathlib import Path
import tempfile

import pytest
from endectools.core import encrypt_path, decrypt_path

@pytest.fixture
def tmp_data(tmp_path):
    # create a sample file and dir
    file = tmp_path / "foo.txt"
    file.write_text("hello world")
    d = tmp_path / "subdir"
    d.mkdir()
    (d / "bar.txt").write_text("👋")
    return tmp_path, file, d

@pytest.mark.parametrize("src_attr", ["file", "dir"])
def test_roundtrip(tmp_data, src_attr):
    base, file, d = tmp_data
    src = {"file": file, "dir": d}[src_attr]
    enc = base / f"{src.name}.enc"
    # encrypt
    encrypt_path(src, enc, b"password")
    assert enc.exists()
    # cleanup original to ensure decrypt restores it
    if src.is_dir():
        os.rmdir(src / "bar.txt")  # remove inner before rmdir
        src.rmdir()
    else:
        src.unlink()
    # decrypt
    decrypt_path(enc, base / src.name, b"password")
    # verify contents
    if src.is_dir():
        assert (base / src.name / "bar.txt").read_text() == "👋"
    else:
        assert (base / f"{src.name}").read_text() == "hello world"