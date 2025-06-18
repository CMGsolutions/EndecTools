import pytest
# from pathlib import Path
from endectools.utils.crypto_stream import encrypt_path, decrypt_path, shred_path
from endectools.utils.hashutils import hash_string, hash_string_interactive
from endectools.utils.vault import (
    init_vault,
    add_secret,
    edit_secret,
    delete_secret,
    delete_vault,
    get_secret_by_label,
)
# import builtins
# import os
import hashlib


@pytest.fixture
def tmp_data(tmp_path):
    file = tmp_path / "foo.txt"
    file.write_text("hello world")
    d = tmp_path / "subdir"
    d.mkdir()
    (d / "bar.txt").write_text("👋")
    return tmp_path, file, d

class TestEncryptDecrypt:
    def test_roundtrip_file(self, tmp_data):
        base, file, _ = tmp_data
        src = file
        enc = base / f".{src.name}.enc"
        encrypt_path(src, enc, b"password")
        assert enc.exists()

        src.unlink()
        decrypt_path(enc, base / src.name, b"password")
        out = base / src.name
        assert out.read_text() == "hello world"

    def test_roundtrip_dir(self, tmp_data):
        base, _, d = tmp_data
        enc = base / f".{d.name}.enc"
        encrypt_path(d, enc, b"password")
        assert enc.exists()

        (d / "bar.txt").unlink()
        d.rmdir()
        decrypt_path(enc, base / d.name, b"password")

        out_file = base / d.name / "bar.txt"
        assert out_file.exists()
        assert out_file.read_text() == "👋"

    def test_wrong_password(self, tmp_data):
        base, file, _ = tmp_data
        enc = base / f".{file.name}.enc"
        encrypt_path(file, enc, b"correct")
        file.unlink()
        import zstandard
        with pytest.raises((ValueError, zstandard.ZstdError)):
            decrypt_path(enc, base / file.name, b"wrong")

    def test_empty_directory(self, tmp_path):
        empty = tmp_path / "emptydir"
        empty.mkdir()
        enc = tmp_path / ".emptydir.enc"
        encrypt_path(empty, enc, b"password")
        assert enc.exists()

        empty.rmdir()
        decrypt_path(enc, tmp_path / "emptydir", b"password")
        assert (tmp_path / "emptydir").exists()

    def test_small_file(self, tmp_path):
        small = tmp_path / "small.txt"
        small.write_bytes(b"a")
        enc = tmp_path / ".small.txt.enc"
        encrypt_path(small, enc, b"p")
        small.unlink()
        decrypt_path(enc, tmp_path / "small.txt", b"p")
        assert (tmp_path / "small.txt").read_bytes() == b"a"

    def test_shred_file(self, tmp_path):
        f = tmp_path / "temp.bin"
        f.write_bytes(b"0123456789")
        shred_path(f, passes=2, pattern="zero")
        assert not f.exists()

    def test_shred_directory(self, tmp_path):
        d = tmp_path / "d"
        d.mkdir()
        (d / "a.txt").write_text("a")
        (d / "b.txt").write_text("b")
        shred_path(d, passes=1, pattern="rand")
        assert not d.exists()

class TestHash:
    def test_sha256_hash(self):
        result = hash_string("hello", "sha256")
        expected = hashlib.sha256(b"hello").hexdigest()
        assert result == expected

    def test_md5_hash(self):
        result = hash_string("test", "md5")
        expected = hashlib.md5(b"test").hexdigest()
        assert result == expected

    def test_hash_string_interactive(self, monkeypatch, capsys):
        def mock_prompt(text, **kwargs):
            if "Enter string to hash" in text:
                return "hello"
            elif "Selection" in text:
                return 1  # SHA-256
            raise ValueError(f"Unexpected prompt: {text}")

        monkeypatch.setattr("click.prompt", mock_prompt)

        result = hash_string_interactive()
        expected = hashlib.sha256(b"hello").hexdigest()

        assert result == expected

# class TestVault:
#     def test_vault_lifecycle(self, tmp_path, monkeypatch):
#         vault_file = tmp_path / ".vault.json.enc"
#         monkeypatch.setenv("ENDECTOOLS_VAULT_PATH", str(vault_file))

#         # Input simulation
#         input_values = iter([
#             "label1",     # add_secret → label
#             "secret1",    # add_secret → value
#             "label1",     # edit_secret → label
#             "secret2",    # edit_secret → new secret
#             "label1",     # delete_secret → label
#         ])

#         monkeypatch.setattr("builtins.input", lambda _: next(input_values))

#         # Reusable password map
#         password_map = {
#             "Create a master password:": "masterpw",
#             "Enter master password:": "masterpw",
#             "Password for this entry:": "entrypw",
#         }

#         # Patched getpass to always return expected value
#         def fake_getpass(prompt):
#             print(f"[TEST getpass] Prompted with: {prompt!r}")
#             for key in password_map:
#                 if prompt.startswith(key):
#                     return password_map[key]
#             raise ValueError(f"Unexpected getpass prompt: {prompt}")

#         monkeypatch.setattr("getpass.getpass", fake_getpass)

#         # Log patch
#         original_print = print
#         monkeypatch.setattr("builtins.print", lambda *args, **kwargs: original_print("[LOG]", *args, **kwargs))

#         print("[LOG] Step 1: Init Vault")
#         init_vault()
#         print("[LOG] Vault initialized successfully.")

#         print("[LOG] Step 2: Add Secret")
#         add_secret()
#         print("[LOG] Secret added.")

#         print("[LOG] Step 3: Retrieve and Assert Secret is 'secret1'")
#         secret = get_secret_by_label("label1", "masterpw", "entrypw")
#         print("[LOG] Retrieved Secret:", secret)
#         assert secret == "secret1"

#         print("[LOG] Step 4: Edit Secret to 'secret2'")
#         edit_secret()

#         print("[LOG] Step 5: Retrieve and Assert Updated Secret is 'secret2'")
#         secret_updated = get_secret_by_label("label1", "masterpw", "entrypw")
#         print("[LOG] Retrieved Updated Secret:", secret_updated)
#         assert secret_updated == "secret2"

#         print("[LOG] Step 6: Delete Secret")
#         delete_secret()

#         print("[LOG] Step 7: Confirm Secret is Deleted")
#         deleted = get_secret_by_label("label1", "masterpw", "entrypw")
#         print("[LOG] Retrieved After Deletion:", deleted)
#         assert deleted is None

#         print("[LOG] Step 8: Delete Vault")
#         delete_vault(force=True)
#         assert not vault_file.exists(), "[FAIL] Vault file still exists after deletion"