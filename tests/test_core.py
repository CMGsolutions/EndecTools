import os
from pathlib import Path
import pytest
from endectools.core import encrypt_path, decrypt_path, shred_path

@ pytest.fixture
def tmp_data(tmp_path):
    # create a sample file and directory
    file = tmp_path / "foo.txt"
    file.write_text("hello world")
    d = tmp_path / "subdir"
    d.mkdir()
    (d / "bar.txt").write_text("👋")
    return tmp_path, file, d

def test_roundtrip_file(tmp_data):
    base, file, _ = tmp_data
    src = file
    enc = base / f"{src.name}.enc"
    encrypt_path(src, enc, b"password")
    assert enc.exists()

    # remove original and decrypt
    src.unlink()
    decrypt_path(enc, base / src.name, b"password")
    out = base / src.name
    assert out.read_text() == "hello world"

def test_roundtrip_dir(tmp_data):
    base, file, d = tmp_data
    src = d
    enc = base / f"{src.name}.enc"
    encrypt_path(src, enc, b"password")
    assert enc.exists()

    # cleanup original directory
    (src / "bar.txt").unlink()
    src.rmdir()
    decrypt_path(enc, base / src.name, b"password")

    out_file = base / src.name / "bar.txt"
    assert out_file.exists()
    assert out_file.read_text() == "👋"

def test_wrong_password(tmp_data):
    base, file, d = tmp_data
    src = file
    enc = base / f"{src.name}.enc"
    encrypt_path(src, enc, b"correct")
    src.unlink()
    import zstandard
    with pytest.raises((ValueError, zstandard.ZstdError)):
        decrypt_path(enc, base / src.name, b"wrong")
        decrypt_path(enc, base / src.name, b"wrong")

def test_not_endectools_file(tmp_path):
    random_file = tmp_path / "random.bin"
    random_file.write_bytes(b"not a real file")
    with pytest.raises(ValueError):
        decrypt_path(random_file, tmp_path / "out", b"password")

def test_empty_directory(tmp_path):
    empty = tmp_path / "emptydir"
    empty.mkdir()
    enc = tmp_path / "emptydir.enc"
    encrypt_path(empty, enc, b"password")
    assert enc.exists()

    # remove and decrypt
    empty.rmdir()
    decrypt_path(enc, tmp_path / "emptydir", b"password")
    out = tmp_path / "emptydir"
    assert out.exists() and out.is_dir()
    assert list(out.iterdir()) == []

def test_small_file(tmp_path):
    small = tmp_path / "small.txt"
    small.write_bytes(b"a")
    enc = tmp_path / "small.txt.enc"
    encrypt_path(small, enc, b"p")
    small.unlink()
    decrypt_path(enc, tmp_path / "small.txt", b"p")
    assert (tmp_path / "small.txt").read_bytes() == b"a"

def test_shred_file(tmp_path):
    f = tmp_path / "temp.bin"
    f.write_bytes(b"0123456789")
    shred_path(f, passes=2, pattern="zero")
    assert not f.exists()

def test_shred_directory(tmp_path):
    d = tmp_path / "d"
    d.mkdir()
    (d / "a.txt").write_text("a")
    (d / "b.txt").write_text("b")
    shred_path(d, passes=1, pattern="rand")
    assert not d.exists()
